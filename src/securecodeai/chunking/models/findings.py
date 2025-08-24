"""Models for correlating security findings with code chunks."""

from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum
from pydantic import BaseModel, Field, computed_field
from datetime import datetime

from ...core.models import Finding, SeverityLevel, VulnerabilityType


class CorrelationType(str, Enum):
    """Types of finding correlations."""
    
    DIRECT = "direct"              # Finding directly in chunk
    CONTEXTUAL = "contextual"      # Finding in related context
    DEPENDENCY = "dependency"      # Finding in dependency
    PATTERN = "pattern"           # Similar pattern to finding
    FLOW = "flow"                 # Data flow connection
    TEMPORAL = "temporal"         # Time-based correlation


class CorrelationStrength(str, Enum):
    """Strength of correlation between finding and chunk."""
    
    VERY_HIGH = "very_high"  # 0.9-1.0
    HIGH = "high"           # 0.7-0.89  
    MEDIUM = "medium"       # 0.5-0.69
    LOW = "low"            # 0.3-0.49
    VERY_LOW = "very_low"  # 0.0-0.29


class FindingCorrelation(BaseModel):
    """Correlation between a finding and a code chunk."""
    
    # Identity
    correlation_id: str
    finding_id: str
    chunk_id: str
    
    # Correlation details
    correlation_type: CorrelationType
    strength: CorrelationStrength
    confidence: float = Field(ge=0.0, le=1.0)
    
    # Location information
    finding_line: Optional[int] = None
    chunk_start_line: int
    chunk_end_line: int
    line_distance: Optional[int] = None
    
    # Contextual information
    shared_functions: List[str] = Field(default_factory=list)
    shared_variables: List[str] = Field(default_factory=list)
    data_flow_path: List[str] = Field(default_factory=list)
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    analysis_method: str = "automated"
    
    @computed_field
    @property
    def strength_score(self) -> float:
        """Get numerical strength score."""
        strength_map = {
            CorrelationStrength.VERY_HIGH: 0.95,
            CorrelationStrength.HIGH: 0.8,
            CorrelationStrength.MEDIUM: 0.6,
            CorrelationStrength.LOW: 0.45,
            CorrelationStrength.VERY_LOW: 0.2
        }
        return strength_map[self.strength]
    
    @computed_field
    @property
    def is_direct_correlation(self) -> bool:
        """Check if this is a direct correlation."""
        return self.correlation_type == CorrelationType.DIRECT


class FindingCluster(BaseModel):
    """A cluster of related security findings."""
    
    # Identity
    cluster_id: str
    cluster_name: str
    
    # Findings
    findings: List[Finding] = Field(default_factory=list)
    primary_finding: Optional[Finding] = None
    
    # Cluster characteristics
    vulnerability_types: Set[VulnerabilityType] = Field(default_factory=set)
    severity_levels: Set[SeverityLevel] = Field(default_factory=set)
    affected_files: Set[str] = Field(default_factory=set)
    
    # Relationships
    related_clusters: List[str] = Field(default_factory=list)
    
    # Statistics
    total_findings: int = 0
    highest_severity: Optional[SeverityLevel] = None
    average_confidence: float = 0.0
    
    @computed_field
    @property
    def cluster_severity(self) -> SeverityLevel:
        """Calculate overall cluster severity."""
        if not self.findings:
            return SeverityLevel.INFO
        
        severity_order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO
        ]
        
        for severity in severity_order:
            if any(f.severity == severity for f in self.findings):
                return severity
        
        return SeverityLevel.INFO
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the cluster."""
        if finding not in self.findings:
            self.findings.append(finding)
            self.vulnerability_types.add(finding.vulnerability_type)
            self.severity_levels.add(finding.severity)
            if finding.location:
                self.affected_files.add(str(finding.location.file_path))
            
            self._update_statistics()
    
    def _update_statistics(self) -> None:
        """Update cluster statistics."""
        self.total_findings = len(self.findings)
        
        if self.findings:
            self.highest_severity = self.cluster_severity
            self.average_confidence = sum(f.confidence for f in self.findings) / len(self.findings)
            
            # Set primary finding (highest severity, highest confidence)
            self.primary_finding = max(
                self.findings,
                key=lambda f: (f.severity.value, f.confidence)
            )


class ChunkFindingAssociation(BaseModel):
    """Association between a chunk and its findings."""
    
    # Identity
    chunk_id: str
    
    # Direct findings
    direct_findings: List[Finding] = Field(default_factory=list)
    
    # Correlated findings
    correlations: List[FindingCorrelation] = Field(default_factory=list)
    
    # Clusters
    finding_clusters: List[FindingCluster] = Field(default_factory=list)
    
    # Priority information
    priority_score: float = 0.0
    focus_weight: float = 1.0
    
    # Context
    context_radius: int = 10  # lines of context
    related_chunks: List[str] = Field(default_factory=list)
    
    @computed_field
    @property
    def total_findings(self) -> int:
        """Total number of findings (direct + correlated)."""
        return len(self.direct_findings) + len(self.correlations)
    
    @computed_field
    @property
    def max_severity(self) -> Optional[SeverityLevel]:
        """Maximum severity level among all findings."""
        all_findings = self.direct_findings + [
            f for f in self.get_all_correlated_findings()
        ]
        
        if not all_findings:
            return None
        
        severity_order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH, 
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO
        ]
        
        for severity in severity_order:
            if any(f.severity == severity for f in all_findings):
                return severity
        
        return SeverityLevel.INFO
    
    @computed_field
    @property
    def has_critical_findings(self) -> bool:
        """Check if chunk has critical findings."""
        return (
            any(f.severity == SeverityLevel.CRITICAL for f in self.direct_findings) or
            any(f.severity == SeverityLevel.CRITICAL for f in self.get_all_correlated_findings())
        )
    
    def get_all_correlated_findings(self) -> List[Finding]:
        """Get all findings from correlations."""
        # This would need to be populated with actual Finding objects
        # For now, return empty list
        return []
    
    def add_direct_finding(self, finding: Finding) -> None:
        """Add a direct finding to the chunk."""
        if finding not in self.direct_findings:
            self.direct_findings.append(finding)
            self._update_priority()
    
    def add_correlation(self, correlation: FindingCorrelation) -> None:
        """Add a finding correlation."""
        if correlation not in self.correlations:
            self.correlations.append(correlation)
            self._update_priority()
    
    def _update_priority(self) -> None:
        """Update priority score based on findings."""
        # Base score from direct findings
        direct_score = 0.0
        for finding in self.direct_findings:
            severity_weight = {
                SeverityLevel.CRITICAL: 1.0,
                SeverityLevel.HIGH: 0.8,
                SeverityLevel.MEDIUM: 0.6,
                SeverityLevel.LOW: 0.4,
                SeverityLevel.INFO: 0.2
            }.get(finding.severity, 0.0)
            
            direct_score += severity_weight * finding.confidence
        
        # Add correlated findings with reduced weight
        correlated_score = 0.0
        for correlation in self.correlations:
            correlated_score += correlation.strength_score * correlation.confidence * 0.5
        
        self.priority_score = min(direct_score + correlated_score, 1.0)


class FindingDistribution(BaseModel):
    """Distribution of findings across chunks."""
    
    # Overall statistics
    total_chunks: int = 0
    chunks_with_findings: int = 0
    total_findings: int = 0
    
    # Severity distribution
    severity_distribution: Dict[SeverityLevel, int] = Field(default_factory=dict)
    
    # Type distribution
    vulnerability_type_distribution: Dict[VulnerabilityType, int] = Field(default_factory=dict)
    
    # Spatial distribution
    file_distribution: Dict[str, int] = Field(default_factory=dict)
    line_distribution: Dict[int, int] = Field(default_factory=dict)  # line -> count
    
    # Priority distribution
    high_priority_chunks: List[str] = Field(default_factory=list)
    medium_priority_chunks: List[str] = Field(default_factory=list)
    low_priority_chunks: List[str] = Field(default_factory=list)
    
    @computed_field
    @property
    def coverage_percentage(self) -> float:
        """Percentage of chunks with findings."""
        if self.total_chunks == 0:
            return 0.0
        return (self.chunks_with_findings / self.total_chunks) * 100
    
    @computed_field
    @property
    def density(self) -> float:
        """Average findings per chunk."""
        if self.total_chunks == 0:
            return 0.0
        return self.total_findings / self.total_chunks
    
    def update_from_associations(self, associations: List[ChunkFindingAssociation]) -> None:
        """Update distribution from chunk-finding associations."""
        self.total_chunks = len(associations)
        self.chunks_with_findings = sum(1 for assoc in associations if assoc.total_findings > 0)
        self.total_findings = sum(assoc.total_findings for assoc in associations)
        
        # Reset distributions
        self.severity_distribution.clear()
        self.vulnerability_type_distribution.clear()
        self.file_distribution.clear()
        
        # Calculate distributions
        for assoc in associations:
            for finding in assoc.direct_findings:
                # Severity
                self.severity_distribution[finding.severity] = (
                    self.severity_distribution.get(finding.severity, 0) + 1
                )
                
                # Vulnerability type
                self.vulnerability_type_distribution[finding.vulnerability_type] = (
                    self.vulnerability_type_distribution.get(finding.vulnerability_type, 0) + 1
                )
                
                # File distribution
                if finding.location:
                    file_path = str(finding.location.file_path)
                    self.file_distribution[file_path] = (
                        self.file_distribution.get(file_path, 0) + 1
                    )
        
        # Priority classification
        self.high_priority_chunks.clear()
        self.medium_priority_chunks.clear()
        self.low_priority_chunks.clear()
        
        for assoc in associations:
            if assoc.priority_score >= 0.8:
                self.high_priority_chunks.append(assoc.chunk_id)
            elif assoc.priority_score >= 0.5:
                self.medium_priority_chunks.append(assoc.chunk_id)
            else:
                self.low_priority_chunks.append(assoc.chunk_id)
