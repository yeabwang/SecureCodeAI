"""Base strategy interface for intelligent code chunking."""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any, Set
from pathlib import Path

from ..models import CodeChunk, ChunkingResult, ChunkingContext, AnalysisContext
from ..parsers import BaseParser, ParseResult
from ..utils import TokenCounter
from ..config import ChunkingConfig
from ..exceptions import ChunkingError


class ChunkingStrategy(ABC):
    """Abstract base class for chunking strategies."""
    
    def __init__(self, 
                 config: ChunkingConfig,
                 token_counter: TokenCounter,
                 parser: Optional[BaseParser] = None):
        self.config = config
        self.token_counter = token_counter
        self.parser = parser
        self.strategy_name = self.__class__.__name__
        
        # Performance tracking
        self._chunks_created = 0
        self._total_processing_time = 0.0
        self._errors = []
    
    @abstractmethod
    def chunk_content(self, 
                     content: str,
                     file_path: Path,
                     context: ChunkingContext) -> ChunkingResult:
        """Chunk content using this strategy."""
        pass
    
    @abstractmethod
    def can_handle(self, file_path: Path, content: str, 
                  context: ChunkingContext) -> bool:
        """Check if this strategy can handle the given content."""
        pass
    
    @abstractmethod
    def get_priority(self, file_path: Path, content: str,
                    context: ChunkingContext) -> float:
        """Get priority score for this strategy (0.0-1.0)."""
        pass
    
    def validate_chunk(self, chunk: CodeChunk) -> bool:
        """Validate a chunk using strategy-specific rules."""
        # Basic validation
        if not chunk.content.strip():
            return False
        
        # Token count validation
        if chunk.metadata.token_count > self.config.tokens.max_tokens_per_chunk:
            return False
        
        # Minimum size validation
        if chunk.metadata.token_count < self.config.tokens.min_chunk_tokens:
            return False
        
        return True
    
    def optimize_chunks(self, chunks: List[CodeChunk]) -> List[CodeChunk]:
        """Optimize chunks after creation."""
        optimized = []
        
        for chunk in chunks:
            if self.validate_chunk(chunk):
                # Apply token optimization if enabled
                if self.config.tokens.enable_token_optimization:
                    chunk = self._optimize_chunk_tokens(chunk)
                
                optimized.append(chunk)
            else:
                # Try to fix invalid chunks
                fixed_chunk = self._fix_invalid_chunk(chunk)
                if fixed_chunk and self.validate_chunk(fixed_chunk):
                    optimized.append(fixed_chunk)
        
        return optimized
    
    def _optimize_chunk_tokens(self, chunk: CodeChunk) -> CodeChunk:
        """Optimize chunk token usage."""
        current_tokens = chunk.metadata.token_count
        max_tokens = self.config.tokens.max_tokens_per_chunk
        
        if current_tokens <= max_tokens:
            return chunk
        
        # Truncate content to fit token limit
        optimized_content = self.token_counter.truncate_to_tokens(
            chunk.content, max_tokens
        )
        
        # Update chunk
        chunk.content = optimized_content
        chunk.metadata.token_count = self.token_counter.count_tokens(optimized_content)
        chunk.metadata.character_count = len(optimized_content)
        chunk.metadata.line_count = len(optimized_content.splitlines())
        
        return chunk
    
    def _fix_invalid_chunk(self, chunk: CodeChunk) -> Optional[CodeChunk]:
        """Try to fix an invalid chunk."""
        # If chunk is too small, return None (will be filtered out)
        if chunk.metadata.token_count < self.config.tokens.min_chunk_tokens:
            return None
        
        # If chunk is too large, truncate it
        if chunk.metadata.token_count > self.config.tokens.max_tokens_per_chunk:
            return self._optimize_chunk_tokens(chunk)
        
        return chunk
    
    def create_overlap_regions(self, chunks: List[CodeChunk]) -> List[Any]:
        """Create overlap regions between chunks."""
        overlaps = []
        overlap_tokens = self.config.tokens.overlap_tokens
        
        if not self.config.strategy.smart_overlap or overlap_tokens <= 0:
            return overlaps
        
        for i in range(len(chunks) - 1):
            current = chunks[i]
            next_chunk = chunks[i + 1]
            
            # Check if chunks are from the same file and sequential
            if (current.metadata.parent_file == next_chunk.metadata.parent_file and
                current.metadata.end_line >= next_chunk.metadata.start_line - 5):
                
                overlap = self._create_overlap_region(current, next_chunk, overlap_tokens)
                if overlap:
                    overlaps.append(overlap)
        
        return overlaps
    
    def _create_overlap_region(self, chunk1: CodeChunk, chunk2: CodeChunk, 
                              overlap_tokens: int) -> Optional[Any]:
        """Create overlap region between two chunks."""
        # Get overlap content from end of first chunk and start of second
        chunk1_lines = chunk1.content.splitlines()
        chunk2_lines = chunk2.content.splitlines()
        
        # Take last N lines from chunk1 and first N lines from chunk2
        overlap_lines_count = min(5, len(chunk1_lines) // 2, len(chunk2_lines) // 2)
        
        if overlap_lines_count <= 0:
            return None
        
        overlap_content = '\n'.join(
            chunk1_lines[-overlap_lines_count:] + 
            chunk2_lines[:overlap_lines_count]
        )
        
        overlap_token_count = self.token_counter.count_tokens(overlap_content)
        
        if overlap_token_count > overlap_tokens:
            # Truncate to fit
            overlap_content = self.token_counter.truncate_to_tokens(
                overlap_content, overlap_tokens
            )
            overlap_token_count = overlap_tokens
        
        from ..models import OverlapRegion
        return OverlapRegion(
            chunk_id_1=chunk1.metadata.chunk_id,
            chunk_id_2=chunk2.metadata.chunk_id,
            overlap_start_line=chunk1.metadata.end_line - overlap_lines_count + 1,
            overlap_end_line=chunk2.metadata.start_line + overlap_lines_count - 1,
            overlap_content=overlap_content,
            overlap_tokens=overlap_token_count
        )
    
    def calculate_chunk_relationships(self, chunks: List[CodeChunk]) -> List[Any]:
        """Calculate relationships between chunks."""
        relationships = []
        
        for i, chunk1 in enumerate(chunks):
            for j, chunk2 in enumerate(chunks[i+1:], i+1):
                relationship = self._analyze_chunk_relationship(chunk1, chunk2)
                if relationship:
                    relationships.append(relationship)
        
        return relationships
    
    def _analyze_chunk_relationship(self, chunk1: CodeChunk, chunk2: CodeChunk) -> Optional[Any]:
        """Analyze relationship between two chunks."""
        # Check for shared functions
        shared_functions = set(chunk1.metadata.function_names) & set(chunk2.metadata.function_names)
        
        # Check for shared imports
        shared_imports = set(chunk1.metadata.imports) & set(chunk2.metadata.imports)
        
        # Calculate relationship strength
        strength = 0.0
        relationship_type = "related"
        
        if shared_functions:
            strength += 0.5
            relationship_type = "functional"
        
        if shared_imports:
            strength += 0.3
        
        # Check if chunks are sequential
        if (chunk1.metadata.parent_file == chunk2.metadata.parent_file and
            abs(chunk1.metadata.end_line - chunk2.metadata.start_line) <= 5):
            strength += 0.4
            relationship_type = "sequential"
        
        if strength < 0.1:
            return None
        
        from ..models import ChunkRelationship
        return ChunkRelationship(
            source_chunk_id=chunk1.metadata.chunk_id,
            target_chunk_id=chunk2.metadata.chunk_id,
            relationship_type=relationship_type,
            relationship_strength=min(strength, 1.0),
            shared_functions=list(shared_functions),
            shared_imports=list(shared_imports)
        )
    
    def get_strategy_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for this strategy."""
        return {
            'strategy_name': self.strategy_name,
            'chunks_created': self._chunks_created,
            'total_processing_time': self._total_processing_time,
            'average_processing_time': (
                self._total_processing_time / max(self._chunks_created, 1)
            ),
            'error_count': len(self._errors),
            'errors': self._errors[-10:]  # Last 10 errors
        }
    
    def reset_metrics(self) -> None:
        """Reset performance metrics."""
        self._chunks_created = 0
        self._total_processing_time = 0.0
        self._errors.clear()
    
    def _record_error(self, error: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Record an error for metrics."""
        error_info = {
            'error': error,
            'context': context or {},
            'timestamp': __import__('time').time()
        }
        self._errors.append(error_info)
        
        # Keep only last 100 errors
        if len(self._errors) > 100:
            self._errors = self._errors[-100:]


class StrategySelector:
    """Selects the best chunking strategy for given content."""
    
    def __init__(self, strategies: List[ChunkingStrategy]):
        self.strategies = strategies
        self.strategy_cache = {}
    
    def select_strategy(self, file_path: Path, content: str,
                       context: ChunkingContext) -> ChunkingStrategy:
        """Select the best strategy for the given content."""
        # Check cache first
        cache_key = self._get_cache_key(file_path, content, context)
        if cache_key in self.strategy_cache:
            return self.strategy_cache[cache_key]
        
        # Evaluate strategies
        candidate_strategies = []
        
        for strategy in self.strategies:
            if strategy.can_handle(file_path, content, context):
                priority = strategy.get_priority(file_path, content, context)
                candidate_strategies.append((strategy, priority))
        
        if not candidate_strategies:
            raise ChunkingError(f"No strategy can handle file: {file_path}")
        
        # Select strategy with highest priority
        selected_strategy = max(candidate_strategies, key=lambda x: x[1])[0]
        
        # Cache the result
        self.strategy_cache[cache_key] = selected_strategy
        
        return selected_strategy
    
    def _get_cache_key(self, file_path: Path, content: str, 
                      context: ChunkingContext) -> str:
        """Generate cache key for strategy selection."""
        content_hash = hash(content[:1000])  # Hash of first 1000 chars
        context_hash = hash(str(context.preferred_strategy))
        return f"{file_path.suffix}:{content_hash}:{context_hash}"
    
    def get_available_strategies(self) -> List[str]:
        """Get names of available strategies."""
        return [strategy.strategy_name for strategy in self.strategies]
    
    def clear_cache(self) -> None:
        """Clear strategy selection cache."""
        self.strategy_cache.clear()
