"""Base class for static analysis tools integration."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

from ..core.models import Finding, AnalysisResult, SourceTool, SeverityLevel, VulnerabilityType


logger = logging.getLogger(__name__)


class StaticAnalysisError(Exception):
    """Base exception for static analysis errors."""
    pass


class ToolNotFoundError(StaticAnalysisError):
    """Raised when a required tool is not found."""
    pass


class ToolExecutionError(StaticAnalysisError):
    """Raised when tool execution fails."""
    pass


class BaseStaticAnalyzer(ABC):
    """Base class for static analysis tool integrations."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.tool_name = self.get_tool_name()
        self.logger = logging.getLogger(f"{__name__}.{self.tool_name}")
        
        # Validate tool availability
        if not self.is_available():
            raise ToolNotFoundError(f"{self.tool_name} is not available")
    
    @abstractmethod
    def get_tool_name(self) -> str:
        """Get the name of the tool."""
        pass
    
    @abstractmethod
    def get_source_tool(self) -> SourceTool:
        """Get the SourceTool enum value for this analyzer."""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the tool is available on the system."""
        pass
    
    @abstractmethod
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a single file and return findings."""
        pass
    
    @abstractmethod
    def analyze_directory(self, directory_path: Path) -> List[Finding]:
        """Analyze a directory and return findings."""
        pass
    
    def analyze_paths(self, paths: List[Path]) -> List[Finding]:
        """Analyze multiple paths (files and directories)."""
        all_findings = []
        
        for path in paths:
            try:
                if path.is_file():
                    findings = self.analyze_file(path)
                elif path.is_dir():
                    findings = self.analyze_directory(path)
                else:
                    self.logger.warning(f"Skipping non-existent path: {path}")
                    continue
                
                all_findings.extend(findings)
                
            except Exception as e:
                self.logger.error(f"Error analyzing {path}: {e}")
                # Continue with other paths even if one fails
                continue
        
        return all_findings
    
    def _normalize_severity(self, tool_severity: str) -> SeverityLevel:
        """Normalize tool-specific severity to our standard levels."""
        severity_map = self._get_severity_mapping()
        normalized = severity_map.get(tool_severity.lower(), SeverityLevel.MEDIUM)
        
        self.logger.debug(f"Normalized severity '{tool_severity}' to '{normalized}'")
        return normalized
    
    def _get_severity_mapping(self) -> Dict[str, SeverityLevel]:
        """Get tool-specific severity mapping. Override in subclasses."""
        return {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH, 
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO,
            'informational': SeverityLevel.INFO,
        }
    
    def _normalize_vulnerability_type(self, tool_type: str) -> VulnerabilityType:
        """Normalize tool-specific vulnerability type. Override in subclasses."""
        # Default mapping - subclasses should override this
        type_map = {
            'sql_injection': VulnerabilityType.SQL_INJECTION,
            'command_injection': VulnerabilityType.COMMAND_INJECTION,
            'xss': VulnerabilityType.XSS,
            'hardcoded_password': VulnerabilityType.HARDCODED_SECRETS,
            'weak_crypto': VulnerabilityType.WEAK_CRYPTOGRAPHY,
        }
        
        return type_map.get(tool_type.lower(), VulnerabilityType.OTHER)
    
    def _calculate_confidence(self, tool_confidence: Optional[float] = None) -> float:
        """Calculate confidence score. Override in subclasses for tool-specific logic."""
        if tool_confidence is not None:
            return max(0.0, min(1.0, tool_confidence))
        
        # Default confidence based on tool reliability
        default_confidences = {
            SourceTool.BANDIT: 0.8,
            SourceTool.SAFETY: 0.9,  # High confidence for known vulnerabilities
            SourceTool.SEMGREP: 0.85,
        }
        
        return default_confidences.get(self.get_source_tool(), 0.7)
    
    def _should_include_finding(self, finding: Finding) -> bool:
        """Determine if a finding should be included based on configuration."""
        # Check confidence threshold
        min_confidence = self.config.get('minimum_confidence', 0.3)
        if finding.confidence < min_confidence:
            return False
        
        # Check severity threshold  
        severity_threshold = self.config.get('severity_threshold', SeverityLevel.LOW)
        severity_levels = [SeverityLevel.INFO, SeverityLevel.LOW, SeverityLevel.MEDIUM, 
                          SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        
        if severity_levels.index(finding.severity) < severity_levels.index(severity_threshold):
            return False
        
        # Check vulnerability type filters
        allowed_types = self.config.get('allowed_vulnerability_types', [])
        if allowed_types and finding.vulnerability_type not in allowed_types:
            return False
        
        return True
    
    def get_version(self) -> Optional[str]:
        """Get tool version. Override in subclasses."""
        return None
    
    def get_supported_extensions(self) -> List[str]:
        """Get list of file extensions this tool can analyze."""
        return []
    
    def can_analyze_file(self, file_path: Path) -> bool:
        """Check if this tool can analyze the given file."""
        if not file_path.exists() or not file_path.is_file():
            return False
        
        supported_extensions = self.get_supported_extensions()
        if not supported_extensions:
            return True  # Tool supports all files
        
        return file_path.suffix.lower() in supported_extensions
