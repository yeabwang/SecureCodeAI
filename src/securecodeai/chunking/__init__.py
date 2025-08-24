"""Production-grade intelligent code chunking module for SecureCodeAI."""

from .orchestrator import ChunkingOrchestrator, create_chunking_orchestrator
from .config import ChunkingConfig, CacheConfig, TokenConfig, ParserConfig, StrategyConfig
from .models import CodeChunk, ChunkingResult, ChunkingContext, ChunkMetadata, ChunkType
from .strategies import (
    ChunkingStrategy, StrategySelector, ASTAwareStrategy, FocusBasedStrategy,
    HybridStrategy, FunctionBasedStrategy, SemanticStrategy
)
from .parsers import BaseParser, TreeSitterParser, parser_factory, language_registry
from .utils import TokenCounter, MetricsCollector
from .cache import ProductionCache, cache_manager
from .exceptions import ChunkingError, ParsingError, TokenLimitExceededError

__version__ = "1.0.0"

__all__ = [
    # Main orchestrator
    "ChunkingOrchestrator",
    "create_chunking_orchestrator",
    
    # Configuration
    "ChunkingConfig",
    "CacheConfig", 
    "TokenConfig",
    "ParserConfig",
    "StrategyConfig",
    
    # Data models
    "CodeChunk",
    "ChunkingResult",
    "ChunkingContext", 
    "ChunkMetadata",
    "ChunkType",
    
    # Strategies
    "ChunkingStrategy",
    "StrategySelector",
    "ASTAwareStrategy",
    "FocusBasedStrategy",
    "HybridStrategy",
    "FunctionBasedStrategy",
    "SemanticStrategy",
    
    # Parsers
    "BaseParser",
    "TreeSitterParser",
    "parser_factory",
    "language_registry",
    
    # Utilities
    "TokenCounter",
    "MetricsCollector",
    
    # Caching
    "ProductionCache",
    "cache_manager",
    
    # Exceptions
    "ChunkingError",
    "ParsingError", 
    "TokenLimitExceededError"
]


def get_default_config() -> ChunkingConfig:
    """Get default production configuration."""
    return ChunkingConfig.get_production_config()


def get_development_config() -> ChunkingConfig:
    """Get development configuration."""
    return ChunkingConfig.get_development_config()


# Quick start function for convenience
def chunk_code(content: str, file_path: str, findings=None, config=None) -> ChunkingResult:
    """
    Quick chunking function for simple use cases.
    
    Args:
        content: Code content to chunk
        file_path: Path to the source file
        findings: Optional security findings to focus on
        config: Optional chunking configuration
    
    Returns:
        ChunkingResult with generated chunks
    """
    from pathlib import Path
    
    if config is None:
        config = get_default_config()
    
    orchestrator = create_chunking_orchestrator(config)
    
    # Create context
    context = ChunkingContext(
        project_root=Path(file_path).parent,
        source_files=[Path(file_path)],
        existing_findings=findings or []
    )
    
    # Process the file
    import asyncio
    return asyncio.run(orchestrator.process_single_file(Path(file_path), context))
