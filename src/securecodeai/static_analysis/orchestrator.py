"""Static analysis orchestrator that combines multiple tools."""

import logging
from typing import List, Dict, Set, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib

from ..core.models import Finding, AnalysisResult, SourceTool, SeverityLevel
from ..core.config import StaticAnalysisConfig
from .base import BaseStaticAnalyzer, StaticAnalysisError
from .bandit_analyzer import BanditAnalyzer
from .safety_analyzer import SafetyAnalyzer  
from .semgrep_analyzer import SemgrepAnalyzer


logger = logging.getLogger(__name__)


class StaticAnalysisOrchestrator:
    """Orchestrates multiple static analysis tools."""
    
    def __init__(self, config: StaticAnalysisConfig):
        self.config = config
        self.analyzers: Dict[str, BaseStaticAnalyzer] = {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize analyzers based on configuration
        self._initialize_analyzers()
    
    def _initialize_analyzers(self) -> None:
        """Initialize available static analysis tools."""
        analyzer_configs = {
            'bandit': {
                'skip_tests': self.config.bandit_skip_tests,
                'exclude_paths': self.config.bandit_exclude_paths,
                'config_file': self.config.bandit_config_file,
            },
            'safety': {
                'ignore_ids': self.config.safety_ignore_ids,
                'db_update': self.config.safety_db_update,
            },
            'semgrep': {
                'rules': self.config.semgrep_rules,
                'config_file': self.config.semgrep_config_file,
                'exclude_patterns': self.config.semgrep_exclude_patterns,
            }
        }
        
        # Initialize each analyzer if enabled
        if self.config.enable_bandit:
            try:
                self.analyzers['bandit'] = BanditAnalyzer(analyzer_configs['bandit'])
                self.logger.info("Initialized Bandit analyzer")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Bandit: {e}")
        
        if self.config.enable_safety:
            try:
                self.analyzers['safety'] = SafetyAnalyzer(analyzer_configs['safety'])
                self.logger.info("Initialized Safety analyzer")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Safety: {e}")
        
        if self.config.enable_semgrep:
            try:
                self.analyzers['semgrep'] = SemgrepAnalyzer(analyzer_configs['semgrep'])
                self.logger.info("Initialized Semgrep analyzer")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Semgrep: {e}")
        
        if not self.analyzers:
            raise StaticAnalysisError("No static analysis tools available")
        
        self.logger.info(f"Initialized {len(self.analyzers)} static analysis tools")
    
    def analyze_paths(self, paths: List[Path], parallel: bool = True) -> List[Finding]:
        """Analyze multiple paths with all available tools."""
        all_findings = []
        
        if parallel and len(self.analyzers) > 1:
            # Run analyzers in parallel
            with ThreadPoolExecutor(max_workers=len(self.analyzers)) as executor:
                future_to_analyzer = {
                    executor.submit(analyzer.analyze_paths, paths): name
                    for name, analyzer in self.analyzers.items()
                }
                
                for future in as_completed(future_to_analyzer):
                    analyzer_name = future_to_analyzer[future]
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                        self.logger.info(f"{analyzer_name} found {len(findings)} findings")
                    except Exception as e:
                        self.logger.error(f"Error running {analyzer_name}: {e}")
        else:
            # Run analyzers sequentially
            for name, analyzer in self.analyzers.items():
                try:
                    findings = analyzer.analyze_paths(paths)
                    all_findings.extend(findings)
                    self.logger.info(f"{name} found {len(findings)} findings")
                except Exception as e:
                    self.logger.error(f"Error running {name}: {e}")
        
        # Deduplicate findings
        deduplicated_findings = self._deduplicate_findings(all_findings)
        
        self.logger.info(
            f"Static analysis complete: {len(all_findings)} raw findings, "
            f"{len(deduplicated_findings)} after deduplication"
        )
        
        return deduplicated_findings
    
    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings across different tools."""
        seen_signatures: Set[str] = set()
        deduplicated = []
        
        # Group findings by signature
        finding_groups: Dict[str, List[Finding]] = {}
        
        for finding in findings:
            signature = self._get_finding_signature(finding)
            if signature not in finding_groups:
                finding_groups[signature] = []
            finding_groups[signature].append(finding)
        
        # For each group, keep the best finding
        for signature, group in finding_groups.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                # Multiple findings with same signature - pick the best one
                best_finding = self._select_best_finding(group)
                deduplicated.append(best_finding)
        
        return deduplicated
    
    def _get_finding_signature(self, finding: Finding) -> str:
        """Generate a signature for a finding to detect duplicates."""
        # Create signature based on location and vulnerability type
        signature_parts = [
            str(finding.location.file_path),
            str(finding.location.start_line),
            str(finding.vulnerability_type.value),
        ]
        
        # Add normalized description for better matching
        normalized_desc = self._normalize_description(finding.description)
        signature_parts.append(normalized_desc[:100])  # First 100 chars
        
        signature = "|".join(signature_parts)
        return hashlib.md5(signature.encode()).hexdigest()
    
    def _normalize_description(self, description: str) -> str:
        """Normalize description for better duplicate detection."""
        # Remove tool-specific prefixes and formatting
        normalized = description.lower()
        
        # Remove common tool prefixes
        for prefix in ['bandit:', 'safety:', 'semgrep:', '[bandit]', '[safety]', '[semgrep]']:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):].strip()
        
        # Remove extra whitespace and punctuation
        normalized = ' '.join(normalized.split())
        
        return normalized
    
    def _select_best_finding(self, findings: List[Finding]) -> Finding:
        """Select the best finding from a group of duplicates."""
        # Prioritize by tool reliability and confidence
        tool_priority = {
            SourceTool.SAFETY: 3,    # Highest priority for known vulnerabilities
            SourceTool.SEMGREP: 2,   # Good for custom rules
            SourceTool.BANDIT: 1,    # Good for Python-specific issues
        }
        
        # Sort by tool priority (desc) then confidence (desc)
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                tool_priority.get(f.source_tool, 0),
                f.confidence,
                f.severity.value  # Use string value for comparison
            ),
            reverse=True
        )
        
        best_finding = sorted_findings[0]
        
        # Merge information from other findings
        merged_finding = self._merge_finding_information(best_finding, sorted_findings[1:])
        
        return merged_finding
    
    def _merge_finding_information(self, primary: Finding, others: List[Finding]) -> Finding:
        """Merge information from multiple findings into one."""
        # Start with primary finding
        merged_metadata = primary.metadata.copy()
        
        # Add metadata from other findings
        for other in others:
            merged_metadata[f"{other.source_tool.value}_metadata"] = other.metadata
        
        # Update confidence to reflect multiple tool agreement
        confidence_boost = min(0.1 * len(others), 0.3)  # Max 30% boost
        new_confidence = min(1.0, primary.confidence + confidence_boost)
        
        # Create new finding with merged information
        merged = primary.copy(deep=True)
        merged.confidence = new_confidence
        merged.metadata = merged_metadata
        
        # Add note about tool agreement
        if len(others) > 0:
            tool_names = [other.source_tool.value for other in others]
            agreement_note = f"\n\nAlso detected by: {', '.join(tool_names)}"
            merged.description += agreement_note
        
        return merged
    
    def get_analyzer_info(self) -> Dict[str, Dict[str, str]]:
        """Get information about available analyzers."""
        info = {}
        
        for name, analyzer in self.analyzers.items():
            info[name] = {
                'name': analyzer.get_tool_name(),
                'version': analyzer.get_version() or 'Unknown',
                'available': analyzer.is_available(),
                'supported_extensions': ', '.join(analyzer.get_supported_extensions()),
            }
        
        return info
    
    def validate_configuration(self) -> List[str]:
        """Validate static analysis configuration."""
        issues = []
        
        # Check if at least one tool is enabled
        if not any([
            self.config.enable_bandit,
            self.config.enable_safety,
            self.config.enable_semgrep
        ]):
            issues.append("No static analysis tools are enabled")
        
        # Check tool availability
        for name, analyzer in self.analyzers.items():
            if not analyzer.is_available():
                issues.append(f"{name} is enabled but not available")
        
        # Check configuration files exist
        if self.config.bandit_config_file and not self.config.bandit_config_file.exists():
            issues.append(f"Bandit config file not found: {self.config.bandit_config_file}")
        
        if self.config.semgrep_config_file and not self.config.semgrep_config_file.exists():
            issues.append(f"Semgrep config file not found: {self.config.semgrep_config_file}")
        
        return issues
