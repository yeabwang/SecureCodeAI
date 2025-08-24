"""Context models for intelligent code chunking."""

from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path
from enum import Enum
from pydantic import BaseModel, Field, computed_field

from ...core.models import Finding


class ContextType(str, Enum):
    """Types of context windows."""
    
    LOCAL = "local"          # Within function/class
    FILE = "file"           # Within same file
    MODULE = "module"       # Within same module/package
    PROJECT = "project"     # Within entire project
    EXTERNAL = "external"   # External dependencies


class ContextScope(str, Enum):
    """Scope of context analysis."""
    
    SYNTAX = "syntax"           # Syntax-level context
    SEMANTIC = "semantic"       # Semantic meaning context
    DEPENDENCY = "dependency"   # Dependency-based context
    SECURITY = "security"       # Security-focused context
    FUNCTIONAL = "functional"   # Functional relationship context


class ContextWindow(BaseModel):
    """A context window around a code element."""
    
    # Identity
    window_id: str
    center_element: str  # function name, class name, etc.
    center_line: int
    
    # Scope
    context_type: ContextType
    context_scope: ContextScope
    
    # Boundaries
    start_line: int
    end_line: int
    line_count: int
    
    # Content
    content_lines: List[str] = Field(default_factory=list)
    token_count: int = 0
    
    # Relationships
    includes_elements: List[str] = Field(default_factory=list)  # Functions, classes included
    depends_on: List[str] = Field(default_factory=list)       # External dependencies
    depended_by: List[str] = Field(default_factory=list)      # Elements that depend on this
    
    # Security context
    security_findings: List[Finding] = Field(default_factory=list)
    risk_indicators: List[str] = Field(default_factory=list)
    
    @computed_field
    @property
    def density(self) -> float:
        """Calculate token density."""
        if self.line_count == 0:
            return 0.0
        return self.token_count / self.line_count


class DependencyNode(BaseModel):
    """A node in the dependency graph."""
    
    # Identity
    node_id: str
    node_type: str  # function, class, module, file
    name: str
    file_path: Path
    
    # Location
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    
    # Dependencies
    imports: Set[str] = Field(default_factory=set)
    calls: Set[str] = Field(default_factory=set)
    references: Set[str] = Field(default_factory=set)
    
    # Reverse dependencies
    imported_by: Set[str] = Field(default_factory=set)
    called_by: Set[str] = Field(default_factory=set)
    referenced_by: Set[str] = Field(default_factory=set)
    
    # Metrics
    complexity: Optional[float] = None
    coupling: Optional[float] = None
    importance_score: float = 0.0


class DependencyGraph(BaseModel):
    """Graph representing dependencies between code elements."""
    
    # Nodes and edges
    nodes: Dict[str, DependencyNode] = Field(default_factory=dict)
    edges: List[Tuple[str, str, str]] = Field(default_factory=list)  # (from, to, type)
    
    # Graph properties
    is_cyclic: bool = False
    strongly_connected_components: List[List[str]] = Field(default_factory=list)
    
    # Statistics
    node_count: int = 0
    edge_count: int = 0
    max_depth: int = 0
    
    def add_node(self, node: DependencyNode) -> None:
        """Add a node to the graph."""
        self.nodes[node.node_id] = node
        self.node_count = len(self.nodes)
    
    def add_edge(self, from_node: str, to_node: str, edge_type: str) -> None:
        """Add an edge to the graph."""
        edge = (from_node, to_node, edge_type)
        if edge not in self.edges:
            self.edges.append(edge)
            self.edge_count = len(self.edges)
    
    def get_dependencies(self, node_id: str, depth: int = 1) -> List[str]:
        """Get dependencies of a node up to specified depth."""
        if node_id not in self.nodes:
            return []
        
        dependencies = set()
        to_visit = [(node_id, 0)]
        visited = set()
        
        while to_visit:
            current, current_depth = to_visit.pop(0)
            if current in visited or current_depth >= depth:
                continue
            
            visited.add(current)
            
            # Find outgoing edges
            for from_id, to_id, _ in self.edges:
                if from_id == current and to_id not in visited:
                    dependencies.add(to_id)
                    if current_depth + 1 < depth:
                        to_visit.append((to_id, current_depth + 1))
        
        return list(dependencies)
    
    def get_dependents(self, node_id: str, depth: int = 1) -> List[str]:
        """Get dependents of a node up to specified depth."""
        if node_id not in self.nodes:
            return []
        
        dependents = set()
        to_visit = [(node_id, 0)]
        visited = set()
        
        while to_visit:
            current, current_depth = to_visit.pop(0)
            if current in visited or current_depth >= depth:
                continue
            
            visited.add(current)
            
            # Find incoming edges
            for from_id, to_id, _ in self.edges:
                if to_id == current and from_id not in visited:
                    dependents.add(from_id)
                    if current_depth + 1 < depth:
                        to_visit.append((from_id, current_depth + 1))
        
        return list(dependents)


class SecurityContext(BaseModel):
    """Security-specific context information."""
    
    # Threat indicators
    sensitive_functions: List[str] = Field(default_factory=list)
    dangerous_patterns: List[str] = Field(default_factory=list)
    input_sources: List[str] = Field(default_factory=list)
    output_sinks: List[str] = Field(default_factory=list)
    
    # Data flow
    tainted_variables: Set[str] = Field(default_factory=set)
    sanitization_points: List[str] = Field(default_factory=list)
    validation_points: List[str] = Field(default_factory=list)
    
    # Risk assessment
    attack_surface_score: float = 0.0
    privilege_level: str = "user"  # user, admin, system
    network_exposure: bool = False
    data_sensitivity: str = "low"  # low, medium, high, critical
    
    # Vulnerability context
    similar_patterns: List[str] = Field(default_factory=list)
    historical_vulnerabilities: List[str] = Field(default_factory=list)
    security_annotations: Dict[str, Any] = Field(default_factory=dict)


class AnalysisContext(BaseModel):
    """Complete context for chunk analysis."""
    
    # Basic context
    file_context: Dict[str, Any] = Field(default_factory=dict)
    project_context: Dict[str, Any] = Field(default_factory=dict)
    
    # Dependency context
    dependency_graph: Optional[DependencyGraph] = None
    local_dependencies: List[str] = Field(default_factory=list)
    external_dependencies: List[str] = Field(default_factory=list)
    
    # Security context
    security_context: SecurityContext = Field(default_factory=SecurityContext)
    existing_findings: List[Finding] = Field(default_factory=list)
    
    # Template context
    relevant_templates: List[str] = Field(default_factory=list)
    template_parameters: Dict[str, Any] = Field(default_factory=dict)
    
    # Token budget context
    available_tokens: int = 0
    reserved_tokens: int = 0
    template_tokens: int = 0
    
    @computed_field
    @property
    def usable_tokens(self) -> int:
        """Calculate tokens available for chunk content."""
        return max(0, self.available_tokens - self.reserved_tokens - self.template_tokens)
    
    def can_fit_tokens(self, token_count: int) -> bool:
        """Check if given token count fits in available budget."""
        return token_count <= self.usable_tokens


class ChunkingContext(BaseModel):
    """Context for the entire chunking operation."""
    
    # Input context
    source_files: List[Path] = Field(default_factory=list)
    target_languages: List[str] = Field(default_factory=list)
    project_root: Optional[Path] = None
    
    # Analysis context
    analysis_context: AnalysisContext = Field(default_factory=AnalysisContext)
    existing_findings: List[Finding] = Field(default_factory=list)
    
    # Strategy context
    preferred_strategy: Optional[str] = None
    strategy_parameters: Dict[str, Any] = Field(default_factory=dict)
    
    # Performance context
    time_budget_seconds: Optional[int] = None
    memory_budget_mb: Optional[int] = None
    quality_requirements: Dict[str, float] = Field(default_factory=dict)
    
    # Output context
    required_overlap: bool = True
    preserve_boundaries: bool = True
    include_metadata: bool = True
    
    def get_file_context(self, file_path: Path) -> Dict[str, Any]:
        """Get context specific to a file."""
        return self.analysis_context.file_context.get(str(file_path), {})
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the context."""
        if finding not in self.existing_findings:
            self.existing_findings.append(finding)
            self.analysis_context.existing_findings.append(finding)
    
    def get_findings_for_file(self, file_path: Path) -> List[Finding]:
        """Get findings specific to a file."""
        return [
            finding for finding in self.existing_findings
            if finding.location and finding.location.file_path == file_path
        ]
