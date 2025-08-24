"""Data models for intelligent code chunking."""

from .chunk import (
    ChunkType,
    NodeType,
    ChunkMetadata,
    CodeChunk,
    ChunkContext,
    OverlapRegion,
    ChunkRelationship,
    ChunkValidationResult,
    ChunkingResult
)

from .context import (
    ContextType,
    ContextScope,
    ContextWindow,
    DependencyNode,
    DependencyGraph,
    SecurityContext,
    AnalysisContext,
    ChunkingContext
)

from .findings import (
    CorrelationType,
    CorrelationStrength,
    FindingCorrelation,
    FindingCluster,
    ChunkFindingAssociation,
    FindingDistribution
)

__all__ = [
    # Chunk models
    "ChunkType",
    "NodeType", 
    "ChunkMetadata",
    "CodeChunk",
    "ChunkContext",
    "OverlapRegion",
    "ChunkRelationship",
    "ChunkValidationResult",
    "ChunkingResult",
    
    # Context models
    "ContextType",
    "ContextScope",
    "ContextWindow",
    "DependencyNode", 
    "DependencyGraph",
    "SecurityContext",
    "AnalysisContext",
    "ChunkingContext",
    
    # Finding models
    "CorrelationType",
    "CorrelationStrength",
    "FindingCorrelation",
    "FindingCluster",
    "ChunkFindingAssociation",
    "FindingDistribution"
]
