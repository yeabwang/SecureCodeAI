"""Core data models for SecureCodeAI."""

from enum import Enum
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from pathlib import Path
from pydantic import BaseModel, Field, validator
import uuid


class SeverityLevel(str, Enum):
    """Severity levels for security findings."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities that can be detected."""
    
    # Injection vulnerabilities
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    XPATH_INJECTION = "xpath_injection"
    LDAP_INJECTION = "ldap_injection"
    
    # Authentication and authorization
    BROKEN_AUTHENTICATION = "broken_authentication"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    
    # Cryptographic issues
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    INSECURE_RANDOMNESS = "insecure_randomness"
    HARDCODED_SECRETS = "hardcoded_secrets"
    
    # Input validation
    XSS = "xss"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    PATH_TRAVERSAL = "path_traversal"
    
    # Security misconfiguration
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    INSECURE_DEFAULTS = "insecure_defaults"
    DEBUG_MODE_ENABLED = "debug_mode_enabled"
    
    # Dependencies
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    OUTDATED_DEPENDENCY = "outdated_dependency"
    
    # Other
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    RACE_CONDITION = "race_condition"
    BUFFER_OVERFLOW = "buffer_overflow"
    OTHER = "other"


class ConfidenceLevel(str, Enum):
    """Confidence levels for findings."""
    
    VERY_HIGH = "very_high"  # 0.9-1.0
    HIGH = "high"           # 0.7-0.89
    MEDIUM = "medium"       # 0.5-0.69
    LOW = "low"            # 0.3-0.49
    VERY_LOW = "very_low"  # 0.0-0.29


class SourceTool(str, Enum):
    """Tools that can generate findings."""
    
    BANDIT = "bandit"
    SAFETY = "safety"
    SEMGREP = "semgrep"
    LLM_GROQ = "llm_groq"
    COMBINED = "combined"


class Location(BaseModel):
    """Location information for a finding."""
    
    file_path: Path
    start_line: int
    end_line: Optional[int] = None
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    
    @validator('end_line')
    def validate_end_line(cls, v, values):
        if v is not None and 'start_line' in values and v < values['start_line']:
            raise ValueError('end_line must be >= start_line')
        return v


class Finding(BaseModel):
    """Represents a security finding."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel
    location: Location
    source_tool: SourceTool
    rule_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    
    # Code context
    code_snippet: Optional[str] = None
    surrounding_code: Optional[str] = None
    
    # Additional metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Remediation
    remediation_advice: Optional[str] = None
    fix_suggestion: Optional[str] = None
    
    @validator('confidence_level', always=True)
    def set_confidence_level(cls, v, values):
        """Automatically set confidence level based on confidence score."""
        if 'confidence' not in values:
            return v
            
        confidence = values['confidence']
        if confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif confidence >= 0.7:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif confidence >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW


class AnalysisResult(BaseModel):
    """Results from a security analysis."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    
    # Analysis metadata
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    
    # Scan configuration
    target_paths: List[Path]
    tools_used: List[SourceTool]
    config_hash: Optional[str] = None
    
    # Results
    findings: List[Finding] = Field(default_factory=list)
    total_files_analyzed: int = 0
    total_lines_analyzed: int = 0
    
    # Statistics
    findings_by_severity: Dict[SeverityLevel, int] = Field(default_factory=dict)
    findings_by_type: Dict[VulnerabilityType, int] = Field(default_factory=dict)
    findings_by_tool: Dict[SourceTool, int] = Field(default_factory=dict)
    
    # Analysis quality metrics
    llm_tokens_used: int = 0
    llm_requests_made: int = 0
    static_analysis_errors: List[str] = Field(default_factory=list)
    
    @validator('duration_seconds', always=True)
    def calculate_duration(cls, v, values):
        """Calculate duration if end_time is set."""
        if v is not None:
            return v
        if 'end_time' in values and values['end_time'] and 'start_time' in values:
            delta = values['end_time'] - values['start_time']
            return delta.total_seconds()
        return v
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding and update statistics."""
        self.findings.append(finding)
        self._update_statistics()
    
    def _update_statistics(self) -> None:
        """Update finding statistics."""
        self.findings_by_severity = {}
        self.findings_by_type = {}
        self.findings_by_tool = {}
        
        for finding in self.findings:
            # Count by severity
            severity_count = self.findings_by_severity.get(finding.severity, 0)
            self.findings_by_severity[finding.severity] = severity_count + 1
            
            # Count by type
            type_count = self.findings_by_type.get(finding.vulnerability_type, 0)
            self.findings_by_type[finding.vulnerability_type] = type_count + 1
            
            # Count by tool
            tool_count = self.findings_by_tool.get(finding.source_tool, 0)
            self.findings_by_tool[finding.source_tool] = tool_count + 1
    
    def get_high_severity_findings(self) -> List[Finding]:
        """Get all high and critical severity findings."""
        return [
            f for f in self.findings 
            if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        ]
    
    def get_findings_by_file(self, file_path: Path) -> List[Finding]:
        """Get all findings for a specific file."""
        return [f for f in self.findings if f.location.file_path == file_path]
    
    def get_unique_vulnerability_types(self) -> List[VulnerabilityType]:
        """Get list of unique vulnerability types found."""
        return list(set(f.vulnerability_type for f in self.findings))


class ScanMode(str, Enum):
    """Different modes for scanning."""
    
    FULL = "full"                    # Complete analysis with all tools
    FAST = "fast"                    # Quick analysis, static tools only
    TARGETED = "targeted"            # Focus on specific vulnerability types
    DIFFERENTIAL = "differential"     # Only analyze changed files
    CONTINUOUS = "continuous"        # Continuous monitoring mode


class OutputFormat(str, Enum):
    """Supported output formats."""
    
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"
    MARKDOWN = "markdown"
    TABLE = "table"
    CSV = "csv"
