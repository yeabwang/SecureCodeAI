"""Main security analyzer that orchestrates static analysis and LLM integration."""

import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

from .models import AnalysisResult, Finding, SourceTool, ScanMode
from .config import Config
from ..static_analysis import StaticAnalysisOrchestrator
from ..llm import GroqClient, GroqError


logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """Main security analyzer that combines static analysis with LLM intelligence."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config.get_default_config()
        self.logger = logging.getLogger(__name__)
        
        # Validate configuration
        config_issues = self.config.validate_config()
        if config_issues:
            self.logger.warning(f"Configuration issues: {config_issues}")
        
        # Initialize components
        self.static_orchestrator = StaticAnalysisOrchestrator(self.config.static_analysis)
        
        # Initialize LLM client if configured
        self.llm_client: Optional[GroqClient] = None
        if self.config.llm.api_key:
            try:
                self.llm_client = GroqClient(
                    api_key=self.config.llm.api_key,
                    model=self.config.llm.model,
                    max_tokens=self.config.llm.max_tokens,
                    temperature=self.config.llm.temperature,
                    timeout=self.config.llm.timeout_seconds,
                    max_retries=self.config.llm.max_retries,
                    requests_per_minute=self.config.llm.requests_per_minute,
                    tokens_per_minute=self.config.llm.tokens_per_minute,
                )
                self.logger.info("LLM client initialized successfully")
            except GroqError as e:
                self.logger.error(f"Failed to initialize LLM client: {e}")
                self.llm_client = None
        else:
            self.logger.info("LLM analysis disabled (no API key configured)")
    
    def analyze(self, 
                target_paths: List[Path],
                mode: Optional[ScanMode] = None) -> AnalysisResult:
        """Analyze the given paths for security vulnerabilities."""
        
        mode = mode or self.config.scan.mode
        start_time = datetime.utcnow()
        
        self.logger.info(f"Starting security analysis in {mode} mode")
        self.logger.info(f"Target paths: {[str(p) for p in target_paths]}")
        
        # Create analysis result
        result = AnalysisResult(
            start_time=start_time,
            target_paths=target_paths,
            tools_used=[],
        )
        
        try:
            # Step 1: Static Analysis
            static_findings = self._run_static_analysis(target_paths, mode)
            result.tools_used.extend([tool.get_source_tool() for tool in self.static_orchestrator.analyzers.values()])
            
            # Add static findings to result
            for finding in static_findings:
                result.add_finding(finding)
            
            self.logger.info(f"Static analysis found {len(static_findings)} issues")
            
            # Step 2: LLM Analysis (if enabled and in appropriate mode)
            if self.llm_client and mode in [ScanMode.FULL, ScanMode.TARGETED]:
                llm_findings = self._run_llm_analysis(static_findings, target_paths)
                
                # Add LLM findings
                for finding in llm_findings:
                    result.add_finding(finding)
                
                if SourceTool.LLM_GROQ not in result.tools_used:
                    result.tools_used.append(SourceTool.LLM_GROQ)
                
                self.logger.info(f"LLM analysis found {len(llm_findings)} additional issues")
            
            # Step 3: Apply filters
            filtered_findings = self._apply_filters(result.findings)
            result.findings = filtered_findings
            
            # Finalize result
            result.end_time = datetime.utcnow()
            result.total_files_analyzed = self._count_files_analyzed(target_paths)
            result.total_lines_analyzed = self._estimate_lines_analyzed(target_paths)
            
            # Add LLM usage statistics
            if self.llm_client:
                llm_stats = self.llm_client.get_usage_stats()
                result.llm_tokens_used = llm_stats.get('total_tokens', 0)
                result.llm_requests_made = llm_stats.get('total_requests', 0)
            
            # Update statistics
            result._update_statistics()
            
            self.logger.info(
                f"Analysis complete: {len(result.findings)} findings in "
                f"{result.duration_seconds:.2f} seconds" if result.duration_seconds is not None
                else f"Analysis complete: {len(result.findings)} findings"
            )
            
            return result
            
        except Exception as e:
            result.end_time = datetime.utcnow()
            result.static_analysis_errors.append(str(e))
            self.logger.error(f"Analysis failed: {e}")
            raise
    
    def _run_static_analysis(self, paths: List[Path], mode: ScanMode) -> List[Finding]:
        """Run static analysis on the given paths."""
        try:
            # Determine if we should run in parallel
            parallel = mode != ScanMode.FAST and len(self.static_orchestrator.analyzers) > 1
            
            findings = self.static_orchestrator.analyze_paths(paths, parallel=parallel)
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Static analysis failed: {e}")
            raise
    
    def _run_llm_analysis(self, 
                         static_findings: List[Finding],
                         target_paths: List[Path]) -> List[Finding]:
        """Run LLM-based analysis."""
        llm_findings = []
        
        if not self.llm_client:
            return llm_findings
        
        try:
            # For now, just validate static findings with LLM
            # In future PRs, this will include classification and detailed analysis
            
            if self.config.llm.enable_classification:
                validated_findings = self._validate_findings_with_llm(static_findings)
                llm_findings.extend(validated_findings)
            
            if self.config.llm.enable_detailed_analysis:
                # TODO: Implement detailed LLM analysis in future PRs
                pass
                
        except Exception as e:
            self.logger.error(f"LLM analysis failed: {e}")
        
        return llm_findings
    
    def _validate_findings_with_llm(self, findings: List[Finding]) -> List[Finding]:
        """Validate static analysis findings with LLM."""
        validated = []
        
        # Check if LLM client is available
        if not self.llm_client:
            return validated
        
        # For PR0, we'll do enhanced validation with intelligent selection
        # Priority order: High severity -> High confidence -> Specific vulnerability types
        
        # Sort findings by priority for LLM analysis
        sorted_findings = sorted(findings, key=lambda f: (
            # Priority 1: Severity (high=2, medium=1, low=0)
            2 if f.severity.value == 'high' else 1 if f.severity.value == 'medium' else 0,
            # Priority 2: Confidence score
            f.confidence,
            # Priority 3: Prefer certain vulnerability types
            1 if f.vulnerability_type in ['command_injection', 'sql_injection', 'unsafe_deserialization'] else 0
        ), reverse=True)
        
        # Process findings with dynamic limits based on severity and confidence
        max_llm_findings = min(
            8,  # Reasonable limit for PR0 (increased from 5)
            len([f for f in findings if f.confidence >= 0.6])  # At least medium confidence
        )
        
        for finding in sorted_findings[:max_llm_findings]:
            try:
                # Enhanced validation and remediation prompt
                code_context = finding.code_snippet or "No code snippet available"
                
                prompt = f"""You are a security expert. Analyze this vulnerability and provide actionable remediation advice.

VULNERABILITY DETAILS:
- Title: {finding.title}
- Type: {finding.vulnerability_type}
- Severity: {finding.severity.value}
- Description: {finding.description}

CODE:
{code_context}

INSTRUCTIONS:
1. Validate if this is a real security issue
2. Provide clear remediation advice (1-2 sentences)
3. Give a specific code fix example

RESPOND ONLY WITH VALID JSON (no extra text):
{{
  "valid": true,
  "remediation_advice": "Clear, actionable advice here",
  "fix_suggestion": "Specific code example or guidance"
}}"""

                response = self.llm_client.simple_completion(
                    prompt,
                    max_tokens=400
                )
                
                # Clean response - remove any markdown or extra formatting
                cleaned_response = response.strip()
                if cleaned_response.startswith('```json'):
                    cleaned_response = cleaned_response.replace('```json', '').replace('```', '').strip()
                if cleaned_response.startswith('```'):
                    cleaned_response = cleaned_response.replace('```', '').strip()
                
                # Parse JSON response
                try:
                    llm_analysis = json.loads(cleaned_response)
                    
                    if llm_analysis.get('valid', False):
                        # Create a new finding with enhanced content
                        enhanced_finding = finding.copy(deep=True)
                        enhanced_finding.confidence = min(1.0, finding.confidence + 0.1)
                        
                        # Clean and set remediation advice
                        remediation = llm_analysis.get('remediation_advice', '').strip()
                        fix_suggestion = llm_analysis.get('fix_suggestion', '').strip()
                        
                        enhanced_finding.remediation_advice = remediation if remediation else None
                        enhanced_finding.fix_suggestion = fix_suggestion if fix_suggestion else None
                        enhanced_finding.metadata['llm_validated'] = True
                        enhanced_finding.metadata['llm_confidence_boost'] = 0.1
                        validated.append(enhanced_finding)
                        
                except json.JSONDecodeError as e:
                    # Better fallback: try to extract meaningful content
                    self.logger.warning(f"Failed to parse LLM JSON response for finding {finding.id}: {e}")
                    self.logger.debug(f"Raw response: {response[:200]}...")
                    
                    # Skip this finding rather than creating messy fallback
                    continue
                    
            except Exception as e:
                self.logger.warning(f"Failed to validate finding {finding.id}: {e}")
                continue
        
        return validated
    
    def _apply_filters(self, findings: List[Finding]) -> List[Finding]:
        """Apply configured filters to findings."""
        filtered = []
        
        for finding in findings:
            # Apply confidence threshold
            if finding.confidence < self.config.scan.confidence_threshold:
                continue
            
            # Apply severity threshold
            severity_levels = ['info', 'low', 'medium', 'high', 'critical']
            min_severity_index = severity_levels.index(self.config.scan.severity_threshold.value)
            finding_severity_index = severity_levels.index(finding.severity.value)
            
            if finding_severity_index < min_severity_index:
                continue
            
            # Apply vulnerability type filter
            if (self.config.scan.vulnerability_types and 
                finding.vulnerability_type not in self.config.scan.vulnerability_types):
                continue
            
            filtered.append(finding)
        
        return filtered
    
    def _count_files_analyzed(self, paths: List[Path]) -> int:
        """Count the number of files analyzed."""
        count = 0
        supported_extensions = set()
        
        # Get all supported extensions from analyzers
        for analyzer in self.static_orchestrator.analyzers.values():
            supported_extensions.update(analyzer.get_supported_extensions())
        
        for path in paths:
            if path.is_file():
                if not supported_extensions or path.suffix in supported_extensions:
                    count += 1
            elif path.is_dir():
                for file_path in path.rglob('*'):
                    if file_path.is_file():
                        if not supported_extensions or file_path.suffix in supported_extensions:
                            count += 1
        
        return count
    
    def _estimate_lines_analyzed(self, paths: List[Path]) -> int:
        """Estimate the number of lines of code analyzed."""
        lines = 0
        
        for path in paths:
            try:
                if path.is_file():
                    lines += self._count_file_lines(path)
                elif path.is_dir():
                    for file_path in path.rglob('*'):
                        if file_path.is_file() and self._is_code_file(file_path):
                            lines += self._count_file_lines(file_path)
            except Exception:
                continue  # Skip files we can't read
        
        return lines
    
    def _count_file_lines(self, file_path: Path) -> int:
        """Count lines in a file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except Exception:
            return 0
    
    def _is_code_file(self, file_path: Path) -> bool:
        """Check if file is a code file."""
        code_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.php', '.rb', '.c', '.cpp', '.cs'}
        return file_path.suffix.lower() in code_extensions
    
    def get_analyzer_info(self) -> Dict[str, Any]:
        """Get information about the analyzer and its components."""
        info = {
            'static_analysis': self.static_orchestrator.get_analyzer_info(),
            'llm_enabled': self.llm_client is not None,
            'config': {
                'scan_mode': self.config.scan.mode.value,
                'severity_threshold': self.config.scan.severity_threshold.value,
                'confidence_threshold': self.config.scan.confidence_threshold,
            }
        }
        
        if self.llm_client:
            info['llm_stats'] = self.llm_client.get_usage_stats()
        
        return info
