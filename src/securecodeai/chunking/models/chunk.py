"""Core data models for intelligent code chunking."""

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Union, Tuple
from pathlib import Path
from enum import Enum
from pydantic import BaseModel, Field, computed_field

from ...core.models import Finding, SeverityLevel, Location


class ChunkType(str, Enum):
    """Types of code chunks."""
    
    FUNCTION = "function"
    CLASS = "class"
    MODULE = "module"
    BLOCK = "block"
    FOCUSED = "focused"
    CONTEXT = "context"
    OVERLAP = "overlap"


class NodeType(str, Enum):
    """AST node types for semantic boundaries."""
    
    FUNCTION_DEF = "function_definition"
    CLASS_DEF = "class_definition"
    METHOD_DEF = "method_definition"
    IMPORT_STMT = "import_statement"
    IF_STMT = "if_statement"
    FOR_STMT = "for_statement" 
    WHILE_STMT = "while_statement"
    TRY_STMT = "try_statement"
    BLOCK = "block"
    EXPRESSION = "expression"


class ChunkMetadata(BaseModel):
    """Metadata for a code chunk."""
    
    # Identification
    chunk_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    parent_file: Path
    language: str
    
    # Position information
    start_line: int
    end_line: int
    start_byte: Optional[int] = None
    end_byte: Optional[int] = None
    
    # Content information
    token_count: int
    character_count: int
    line_count: int
    
    # AST information
    primary_node_type: Optional[NodeType] = None
    node_types: List[NodeType] = Field(default_factory=list)
    function_names: List[str] = Field(default_factory=list)
    class_names: List[str] = Field(default_factory=list)
    
    # Dependencies
    imports: List[str] = Field(default_factory=list)
    function_calls: List[str] = Field(default_factory=list)
    variable_references: List[str] = Field(default_factory=list)
    
    # Quality metrics
    complexity_score: Optional[float] = None
    maintainability_index: Optional[float] = None
    
    # Timestamp
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    @computed_field
    @property
    def density(self) -> float:
        """Calculate token density (tokens per line)."""
        if self.line_count == 0:
            return 0.0
        return self.token_count / self.line_count


class CodeChunk(BaseModel):
    """A chunk of code with associated metadata."""
    
    # Core content
    content: str
    metadata: ChunkMetadata
    chunk_type: ChunkType = ChunkType.BLOCK
    
    # Relationships
    parent_chunk_id: Optional[str] = None
    child_chunk_ids: List[str] = Field(default_factory=list)
    related_chunk_ids: List[str] = Field(default_factory=list)
    
    # Focus information
    security_findings: List[Finding] = Field(default_factory=list)
    focus_score: float = 0.0
    priority_weight: float = 1.0
    
    # Processing state
    is_processed: bool = False
    processing_errors: List[str] = Field(default_factory=list)
    
    # Cache information
    content_hash: Optional[str] = None
    cache_key: Optional[str] = None
    
    @computed_field
    @property
    def severity_score(self) -> float:
        """Calculate maximum severity score from findings."""
        if not self.security_findings:
            return 0.0
        
        severity_weights = {
            SeverityLevel.CRITICAL: 1.0,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.MEDIUM: 0.6,
            SeverityLevel.LOW: 0.4,
            SeverityLevel.INFO: 0.2
        }
        
        return max(
            severity_weights.get(finding.severity, 0.0) 
            for finding in self.security_findings
        )
    
    @computed_field
    @property
    def finding_count(self) -> int:
        """Count of security findings in this chunk."""
        return len(self.security_findings)
    
    @computed_field
    @property
    def has_critical_findings(self) -> bool:
        """Check if chunk contains critical security findings."""
        return any(
            finding.severity == SeverityLevel.CRITICAL
            for finding in self.security_findings
        )
    
    def add_finding(self, finding: Finding) -> None:
        """Add a security finding to this chunk."""
        if finding not in self.security_findings:
            self.security_findings.append(finding)
            self._update_focus_score()
    
    def _update_focus_score(self) -> None:
        """Update focus score based on findings."""
        if not self.security_findings:
            self.focus_score = 0.0
            return
        
        # Calculate weighted score based on severity and confidence
        score = 0.0
        for finding in self.security_findings:
            severity_weight = {
                SeverityLevel.CRITICAL: 1.0,
                SeverityLevel.HIGH: 0.8,
                SeverityLevel.MEDIUM: 0.6,
                SeverityLevel.LOW: 0.4,
                SeverityLevel.INFO: 0.2
            }.get(finding.severity, 0.0)
            
            confidence_weight = finding.confidence
            score += severity_weight * confidence_weight
        
        self.focus_score = min(score, 1.0)  # Cap at 1.0


class ChunkContext(BaseModel):
    """Context information for a chunk within its file and project."""
    
    # File context
    file_path: Path
    file_language: str
    file_size_lines: int
    file_functions: List[str] = Field(default_factory=list)
    file_classes: List[str] = Field(default_factory=list)
    
    # Project context
    project_root: Optional[Path] = None
    module_path: Optional[str] = None
    package_imports: List[str] = Field(default_factory=list)
    
    # Surrounding context
    preceding_chunks: List[str] = Field(default_factory=list)  # chunk IDs
    following_chunks: List[str] = Field(default_factory=list)  # chunk IDs
    related_files: List[Path] = Field(default_factory=list)
    
    # Dependency context
    import_dependencies: List[str] = Field(default_factory=list)
    function_dependencies: List[str] = Field(default_factory=list)
    class_dependencies: List[str] = Field(default_factory=list)


class OverlapRegion(BaseModel):
    """Information about overlapping regions between chunks."""
    
    chunk_id_1: str
    chunk_id_2: str
    overlap_start_line: int
    overlap_end_line: int
    overlap_content: str
    overlap_tokens: int
    
    # Semantic information
    overlap_node_types: List[NodeType] = Field(default_factory=list)
    is_semantic_boundary: bool = False
    boundary_type: Optional[str] = None  # function, class, block, etc.


class ChunkRelationship(BaseModel):
    """Relationship between two chunks."""
    
    source_chunk_id: str
    target_chunk_id: str
    relationship_type: str  # parent, child, overlap, dependency, related
    relationship_strength: float = Field(ge=0.0, le=1.0)
    
    # Relationship details
    shared_functions: List[str] = Field(default_factory=list)
    shared_variables: List[str] = Field(default_factory=list)
    shared_imports: List[str] = Field(default_factory=list)
    
    # Metrics
    content_similarity: Optional[float] = None
    structural_similarity: Optional[float] = None


class ChunkValidationResult(BaseModel):
    """Result of chunk validation."""
    
    chunk_id: str
    is_valid: bool = True
    validation_errors: List[str] = Field(default_factory=list)
    validation_warnings: List[str] = Field(default_factory=list)
    
    # Validation metrics
    syntax_valid: bool = True
    boundary_preserved: bool = True
    token_count_valid: bool = True
    content_complete: bool = True
    
    # Performance metrics
    validation_time_ms: Optional[float] = None


class ChunkingResult(BaseModel):
    """Result of chunking operation for a file or project."""
    
    # Input information
    source_file: Optional[Path] = None
    source_files: List[Path] = Field(default_factory=list)
    strategy_used: str
    
    # Output chunks
    chunks: List[CodeChunk] = Field(default_factory=list)
    chunk_relationships: List[ChunkRelationship] = Field(default_factory=list)
    overlap_regions: List[OverlapRegion] = Field(default_factory=list)
    
    # Statistics
    total_chunks: int = 0
    total_tokens: int = 0
    total_lines: int = 0
    average_chunk_size: float = 0.0
    
    # Quality metrics
    syntax_preservation_rate: float = 1.0
    boundary_preservation_rate: float = 1.0
    validation_results: List[ChunkValidationResult] = Field(default_factory=list)
    
    # Performance metrics
    processing_time_ms: float = 0.0
    memory_usage_mb: Optional[float] = None
    cache_hit_rate: Optional[float] = None
    
    # Error information
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    
    @computed_field
    @property
    def success_rate(self) -> float:
        """Calculate success rate based on validation results."""
        if not self.validation_results:
            return 1.0
        
        valid_chunks = sum(1 for result in self.validation_results if result.is_valid)
        return valid_chunks / len(self.validation_results)
    
    @computed_field
    @property
    def chunks_with_findings(self) -> List[CodeChunk]:
        """Get chunks that contain security findings."""
        return [chunk for chunk in self.chunks if chunk.security_findings]
    
    @computed_field
    @property
    def high_priority_chunks(self) -> List[CodeChunk]:
        """Get chunks with high priority (critical or high severity findings)."""
        return [
            chunk for chunk in self.chunks
            if chunk.has_critical_findings or chunk.severity_score >= 0.8
        ]
    
    def add_chunk(self, chunk: CodeChunk) -> None:
        """Add a chunk and update statistics."""
        self.chunks.append(chunk)
        self.total_chunks = len(self.chunks)
        self.total_tokens += chunk.metadata.token_count
        self.total_lines += chunk.metadata.line_count
        
        if self.total_chunks > 0:
            self.average_chunk_size = self.total_tokens / self.total_chunks
    
    def get_chunk_by_id(self, chunk_id: str) -> Optional[CodeChunk]:
        """Get chunk by ID."""
        for chunk in self.chunks:
            if chunk.metadata.chunk_id == chunk_id:
                return chunk
        return None
    
    def get_chunks_by_file(self, file_path: Path) -> List[CodeChunk]:
        """Get all chunks for a specific file."""
        return [
            chunk for chunk in self.chunks
            if chunk.metadata.parent_file == file_path
        ]
