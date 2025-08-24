"""Production-grade configuration for intelligent code chunking."""

from typing import Dict, List, Optional, Union, Tuple
from pathlib import Path
from enum import Enum
from pydantic import BaseModel, Field, field_validator, model_validator


class ChunkingStrategy(str, Enum):
    """Available chunking strategies."""
    
    AST_AWARE = "ast_aware"
    FOCUS_BASED = "focus_based"
    HYBRID = "hybrid"
    SEMANTIC = "semantic"
    FUNCTION_BASED = "function_based"


class SupportedLanguage(str, Enum):
    """Supported programming languages."""
    
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    JAVA = "java"
    PHP = "php"
    C = "c"
    CPP = "cpp"
    RUST = "rust"
    RUBY = "ruby"


class TokenModel(str, Enum):
    """Supported token models for counting."""
    
    GPT_4 = "gpt-4"
    GPT_35_TURBO = "gpt-3.5-turbo"
    CLAUDE_3 = "claude-3"
    LLAMA_3_70B = "llama3-70b-8192"


class CacheConfig(BaseModel):
    """Configuration for caching system."""
    
    # LRU Cache sizes
    chunk_cache_size: int = Field(default=1000, ge=100, le=10000)
    ast_cache_size: int = Field(default=500, ge=50, le=5000) 
    token_cache_size: int = Field(default=200, ge=20, le=2000)
    file_hash_cache_size: int = Field(default=64, ge=16, le=512)
    
    # TTL settings (seconds)
    chunk_ttl: int = Field(default=3600, ge=300, le=86400)  # 1 hour
    ast_ttl: int = Field(default=1800, ge=300, le=7200)     # 30 minutes
    token_ttl: int = Field(default=300, ge=60, le=1800)     # 5 minutes
    
    # Memory limits
    max_memory_mb: int = Field(default=512, ge=128, le=2048)
    enable_memory_monitoring: bool = True
    memory_cleanup_threshold: float = Field(default=0.8, ge=0.5, le=0.95)


class TokenConfig(BaseModel):
    """Configuration for token management."""
    
    # Model settings
    model: TokenModel = TokenModel.LLAMA_3_70B
    max_tokens_per_chunk: int = Field(default=4000, ge=1000, le=8000)
    overlap_tokens: int = Field(default=200, ge=50, le=500)
    
    # Budget allocation
    template_reserve_ratio: float = Field(default=0.3, ge=0.1, le=0.5)
    context_reserve_ratio: float = Field(default=0.2, ge=0.05, le=0.3)
    response_reserve_ratio: float = Field(default=0.1, ge=0.05, le=0.2)
    
    # Optimization
    enable_token_optimization: bool = True
    min_chunk_tokens: int = Field(default=500, ge=100, le=1000)
    
    @field_validator('overlap_tokens')
    @classmethod
    def validate_overlap(cls, v: int, info) -> int:
        if 'max_tokens_per_chunk' in info.data:
            max_tokens = info.data['max_tokens_per_chunk']
            if v >= max_tokens * 0.5:
                raise ValueError(f"Overlap tokens ({v}) must be less than 50% of max tokens ({max_tokens})")
        return v


class ParserConfig(BaseModel):
    """Configuration for AST parsers."""
    
    # Language support
    supported_languages: List[SupportedLanguage] = Field(
        default_factory=lambda: list(SupportedLanguage)
    )
    fallback_language: SupportedLanguage = SupportedLanguage.PYTHON
    
    # Parser behavior
    enable_error_recovery: bool = True
    max_parse_retries: int = Field(default=3, ge=1, le=10)
    syntax_validation: bool = True
    preserve_comments: bool = True
    preserve_whitespace: bool = False
    
    # File filtering
    exclude_patterns: List[str] = Field(default_factory=lambda: [
        "__pycache__", ".git", ".venv", "node_modules", ".pytest_cache",
        "dist", "build", ".tox", ".coverage", "*.pyc", "*.pyo"
    ])
    
    # Node filtering
    significant_node_types: Dict[str, List[str]] = Field(default_factory=lambda: {
        "python": ["function_definition", "class_definition", "import_statement", 
                  "from_import_statement", "if_statement", "try_statement"],
        "javascript": ["function_declaration", "arrow_function", "class_declaration",
                      "import_statement", "if_statement", "try_statement"],
        "typescript": ["function_declaration", "arrow_function", "class_declaration",
                      "interface_declaration", "import_statement", "if_statement"],
        "go": ["function_declaration", "type_declaration", "import_declaration",
               "if_statement", "for_statement"],
        "java": ["class_declaration", "method_declaration", "import_declaration",
                "if_statement", "try_statement"]
    })


class StrategyConfig(BaseModel):
    """Configuration for chunking strategies."""
    
    # Strategy selection
    default_strategy: ChunkingStrategy = ChunkingStrategy.HYBRID
    enable_strategy_fallback: bool = True
    strategy_selection_rules: Dict[str, ChunkingStrategy] = Field(default_factory=lambda: {
        "focus_available": ChunkingStrategy.FOCUS_BASED,
        "large_file": ChunkingStrategy.AST_AWARE,
        "small_file": ChunkingStrategy.FUNCTION_BASED
    })
    
    # AST strategy settings
    ast_preserve_boundaries: bool = True
    ast_min_node_size: int = Field(default=50, ge=10, le=200)
    ast_max_depth: int = Field(default=10, ge=3, le=20)
    
    # Focus strategy settings
    focus_context_lines: int = Field(default=10, ge=5, le=50)
    focus_priority_weights: Dict[str, float] = Field(default_factory=lambda: {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.6,
        "low": 0.4,
        "info": 0.2
    })
    
    # Overlap strategy
    smart_overlap: bool = True
    overlap_prefer_boundaries: bool = True


class PerformanceConfig(BaseModel):
    """Configuration for performance optimization."""
    
    # Parallel processing
    max_workers: Optional[int] = None  # Auto-detect
    enable_async_processing: bool = True
    chunk_processing_timeout: int = Field(default=60, ge=10, le=300)
    
    # Memory management
    enable_memory_profiling: bool = False
    gc_frequency: int = Field(default=100, ge=10, le=1000)  # chunks
    max_file_size_mb: int = Field(default=10, ge=1, le=100)
    
    # Rate limiting
    max_chunks_per_second: Optional[int] = Field(default=100, ge=10, le=1000)
    enable_backpressure: bool = True


class MonitoringConfig(BaseModel):
    """Configuration for monitoring and metrics."""
    
    # Prometheus metrics
    enable_prometheus: bool = True
    metrics_port: int = Field(default=8080, ge=1024, le=65535)
    metrics_path: str = "/metrics"
    
    # Custom metrics
    track_chunk_distribution: bool = True
    track_parsing_performance: bool = True
    track_cache_performance: bool = True
    track_token_usage: bool = True
    
    # Logging
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    enable_structured_logging: bool = True
    log_chunk_summaries: bool = False  # Avoid logging sensitive code


class ChunkingConfig(BaseModel):
    """Master configuration for intelligent code chunking."""
    
    # Sub-configurations
    cache: CacheConfig = Field(default_factory=CacheConfig)
    tokens: TokenConfig = Field(default_factory=TokenConfig)
    parser: ParserConfig = Field(default_factory=ParserConfig)
    strategy: StrategyConfig = Field(default_factory=StrategyConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    
    # Global settings
    enable_chunking: bool = True
    validate_chunks: bool = True
    enable_chunk_correlation: bool = True
    
    @model_validator(mode='after')
    def validate_config_consistency(self) -> 'ChunkingConfig':
        """Validate configuration consistency across components."""
        # Validate token budget allocation
        total_ratio = (
            self.tokens.template_reserve_ratio +
            self.tokens.context_reserve_ratio + 
            self.tokens.response_reserve_ratio
        )
        if total_ratio >= 1.0:
            raise ValueError("Token reserve ratios sum to >= 1.0, no tokens left for chunks")
        
        # Validate cache sizes relative to performance
        if self.performance.max_workers and self.cache.chunk_cache_size < self.performance.max_workers * 10:
            raise ValueError("Chunk cache size too small for number of workers")
            
        return self
    
    @classmethod
    def from_dict(cls, config_dict: Dict) -> 'ChunkingConfig':
        """Create configuration from dictionary."""
        return cls(**config_dict)
    
    @classmethod
    def get_production_config(cls) -> 'ChunkingConfig':
        """Get production-optimized configuration."""
        return cls(
            cache=CacheConfig(
                chunk_cache_size=2000,
                ast_cache_size=1000,
                max_memory_mb=1024,
                chunk_ttl=7200  # 2 hours
            ),
            tokens=TokenConfig(
                max_tokens_per_chunk=6000,
                overlap_tokens=300,
                enable_token_optimization=True
            ),
            performance=PerformanceConfig(
                enable_async_processing=True,
                max_file_size_mb=50,
                enable_memory_profiling=True
            ),
            monitoring=MonitoringConfig(
                enable_prometheus=True,
                track_chunk_distribution=True,
                log_level="INFO"
            )
        )
    
    @classmethod
    def get_development_config(cls) -> 'ChunkingConfig':
        """Get development-optimized configuration."""
        return cls(
            cache=CacheConfig(
                chunk_cache_size=500,
                ast_cache_size=250,
                max_memory_mb=256
            ),
            tokens=TokenConfig(
                max_tokens_per_chunk=3000,
                overlap_tokens=150
            ),
            performance=PerformanceConfig(
                max_workers=2,
                enable_memory_profiling=True
            ),
            monitoring=MonitoringConfig(
                enable_prometheus=False,
                log_level="DEBUG",
                log_chunk_summaries=True
            )
        )
