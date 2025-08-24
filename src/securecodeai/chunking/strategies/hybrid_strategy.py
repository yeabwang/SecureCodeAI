"""Production-grade hybrid chunking strategy combining multiple approaches."""

import time
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass

from .base_strategy import ChunkingStrategy
from .ast_strategy import ASTAwareStrategy
from .focus_strategy import FocusBasedStrategy
from ..models import CodeChunk, ChunkingContext, ChunkingResult, ChunkMetadata, ChunkType
from ..config import ChunkingConfig
from ..utils import TokenCounter
from ..parsers import BaseParser
from ..exceptions import ChunkingError


logger = logging.getLogger(__name__)


@dataclass
class StrategyWeight:
    """Weight configuration for hybrid strategy."""
    ast_weight: float = 0.6
    focus_weight: float = 0.4
    overlap_threshold: int = 50
    merge_threshold: float = 0.8


class HybridStrategy(ChunkingStrategy):
    """
    hybrid strategy that intelligently combines AST-aware and focus-based approaches.
    
    This strategy:
    1. Runs both AST-aware and focus-based strategies
    2. Intelligently merges overlapping chunks based on quality metrics
    3. Optimizes boundaries for semantic coherence
    4. Provides comprehensive metrics and monitoring
    """
    
    def __init__(self, config: ChunkingConfig, token_counter: TokenCounter, 
                 parser: Optional[BaseParser] = None):
        super().__init__(config, token_counter, parser)
        self.strategy_name = "hybrid"
        
        # Initialize sub-strategies
        self.ast_strategy = ASTAwareStrategy(config, token_counter, parser)
        self.focus_strategy = FocusBasedStrategy(config, token_counter, parser)
        
        # Strategy weights configuration
        self.weights = StrategyWeight()
        
        # Performance metrics
        self.ast_chunks_created = 0
        self.focus_chunks_created = 0
        self.merged_chunks = 0
        self.overlap_resolutions = 0
        self.boundary_optimizations = 0
        
        logger.debug(f"HybridStrategy initialized with weights: AST={self.weights.ast_weight}, Focus={self.weights.focus_weight}")
    
    def can_handle(self, file_path: Path, content: str, 
                  context: ChunkingContext) -> bool:
        """Check if this strategy can handle the given content."""
        # Hybrid strategy can handle content if either sub-strategy can
        ast_can_handle = self.ast_strategy.can_handle(file_path, content, context)
        focus_can_handle = self.focus_strategy.can_handle(file_path, content, context)
        
        return ast_can_handle or focus_can_handle
    
    def get_priority(self, file_path: Path, content: str,
                    context: ChunkingContext) -> float:
        """Get priority score for this strategy."""
        ast_priority = self.ast_strategy.get_priority(file_path, content, context)
        focus_priority = self.focus_strategy.get_priority(file_path, content, context)
        
        # High priority when both strategies are applicable and suitable
        if ast_priority > 0.7 and focus_priority > 0.7:
            return 0.95  # Highest priority for hybrid approach
        
        # Medium-high priority when one strategy is highly suitable
        if max(ast_priority, focus_priority) > 0.8:
            return 0.75
        
        # Medium priority when both are moderately suitable
        if ast_priority > 0.5 and focus_priority > 0.5:
            return 0.65
        
        # Lower priority if only one strategy is applicable
        return max(ast_priority, focus_priority) * 0.7
    
    def chunk_content(self, content: str, file_path: Path, 
                     context: ChunkingContext) -> ChunkingResult:
        """Chunk content using intelligent hybrid approach."""
        start_time = time.time()
        
        try:
            # Synchronize parsers
            self._sync_parsers()
            
            # Execute both strategies in parallel conceptually
            ast_result = self._execute_ast_strategy(content, file_path, context)
            focus_result = self._execute_focus_strategy(content, file_path, context)
            
            # Analyze and combine results
            combined_chunks = self._intelligent_merge(
                ast_result.chunks, 
                focus_result.chunks, 
                context
            )
            
            # Create comprehensive result
            result = self._create_hybrid_result(
                file_path, combined_chunks, ast_result, focus_result
            )
            
            # Performance tracking
            result.processing_time_ms = (time.time() - start_time) * 1000
            self._chunks_created += len(result.chunks)
            
            self._log_strategy_performance(result, ast_result, focus_result)
            
            return result
            
        except Exception as e:
            logger.error(f"Hybrid chunking failed for {file_path}: {e}")
            self._errors.append(str(e))
            raise ChunkingError(f"Hybrid chunking failed: {e}")
    
    def _sync_parsers(self) -> None:
        """Synchronize parsers across sub-strategies."""
        if self.parser:
            self.ast_strategy.parser = self.parser
            self.focus_strategy.parser = self.parser
    
    def _execute_ast_strategy(self, content: str, file_path: Path, 
                             context: ChunkingContext) -> ChunkingResult:
        """Execute AST strategy with error handling."""
        try:
            result = self.ast_strategy.chunk_content(content, file_path, context)
            self.ast_chunks_created += len(result.chunks)
            logger.debug(f"AST strategy created {len(result.chunks)} chunks")
            return result
        except Exception as e:
            logger.warning(f"AST strategy failed: {e}")
            # Return empty result on failure
            return ChunkingResult(source_file=file_path, strategy_used="ast_failed")
    
    def _execute_focus_strategy(self, content: str, file_path: Path, 
                               context: ChunkingContext) -> ChunkingResult:
        """Execute focus strategy with error handling."""
        try:
            result = self.focus_strategy.chunk_content(content, file_path, context)
            self.focus_chunks_created += len(result.chunks)
            logger.debug(f"Focus strategy created {len(result.chunks)} chunks")
            return result
        except Exception as e:
            logger.warning(f"Focus strategy failed: {e}")
            # Return empty result on failure
            return ChunkingResult(source_file=file_path, strategy_used="focus_failed")
    
    def _intelligent_merge(self, ast_chunks: List[CodeChunk], 
                          focus_chunks: List[CodeChunk],
                          context: ChunkingContext) -> List[CodeChunk]:
        """Intelligently merge chunks from both strategies."""
        if not ast_chunks and not focus_chunks:
            return []
        
        if not ast_chunks:
            return self._apply_weights(focus_chunks, self.weights.focus_weight)
        
        if not focus_chunks:
            return self._apply_weights(ast_chunks, self.weights.ast_weight)
        
        # Both strategies produced chunks - intelligent merge
        merged_chunks = self._merge_overlapping_chunks(ast_chunks, focus_chunks)
        
        # Resolve remaining overlaps
        resolved_chunks = self._resolve_overlaps(merged_chunks)
        
        # Optimize boundaries
        optimized_chunks = self._optimize_chunk_boundaries(resolved_chunks, context)
        
        # Sort by priority and focus score
        final_chunks = sorted(optimized_chunks, 
                            key=lambda c: (c.focus_score, c.priority_weight), 
                            reverse=True)
        
        return final_chunks
    
    def _apply_weights(self, chunks: List[CodeChunk], weight: float) -> List[CodeChunk]:
        """Apply strategy weight to chunks."""
        weighted_chunks = []
        for chunk in chunks:
            weighted_chunk = chunk.model_copy()
            weighted_chunk.priority_weight *= weight
            weighted_chunks.append(weighted_chunk)
        return weighted_chunks
    
    def _merge_overlapping_chunks(self, ast_chunks: List[CodeChunk], 
                                 focus_chunks: List[CodeChunk]) -> List[CodeChunk]:
        """Merge overlapping chunks intelligently."""
        merged = []
        
        # Create spatial index for efficient overlap detection
        ast_index = {(c.metadata.start_line, c.metadata.end_line): c for c in ast_chunks}
        focus_index = {(c.metadata.start_line, c.metadata.end_line): c for c in focus_chunks}
        
        # Find all unique ranges
        all_ranges = set(ast_index.keys()) | set(focus_index.keys())
        
        for range_key in sorted(all_ranges):
            ast_chunk = ast_index.get(range_key)
            focus_chunk = focus_index.get(range_key)
            
            if ast_chunk and focus_chunk:
                # Perfect overlap - merge intelligently
                merged_chunk = self._merge_chunk_pair(ast_chunk, focus_chunk)
                merged.append(merged_chunk)
                self.merged_chunks += 1
                
            elif ast_chunk:
                # Only AST chunk
                ast_chunk.priority_weight *= self.weights.ast_weight
                merged.append(ast_chunk)
                
            elif focus_chunk:
                # Only focus chunk
                focus_chunk.priority_weight *= self.weights.focus_weight
                merged.append(focus_chunk)
        
        # Handle partial overlaps
        merged = self._handle_partial_overlaps(merged)
        
        return merged
    
    def _merge_chunk_pair(self, ast_chunk: CodeChunk, focus_chunk: CodeChunk) -> CodeChunk:
        """Merge two chunks with identical boundaries."""
        # Choose base chunk based on quality metrics
        base_chunk = self._select_base_chunk(ast_chunk, focus_chunk)
        other_chunk = focus_chunk if base_chunk == ast_chunk else ast_chunk
        
        # Create enhanced metadata
        enhanced_metadata = self._merge_metadata(base_chunk.metadata, other_chunk.metadata)
        
        # Create merged chunk
        merged = CodeChunk(
            content=base_chunk.content,
            metadata=enhanced_metadata,
            chunk_type=self._select_best_chunk_type(base_chunk.chunk_type, other_chunk.chunk_type),
            parent_chunk_id=base_chunk.parent_chunk_id or other_chunk.parent_chunk_id,
            child_chunk_ids=list(set(base_chunk.child_chunk_ids + other_chunk.child_chunk_ids)),
            related_chunk_ids=list(set(base_chunk.related_chunk_ids + other_chunk.related_chunk_ids)),
            security_findings=list(set(base_chunk.security_findings + other_chunk.security_findings)),
            priority_weight=self._calculate_merged_priority(base_chunk, other_chunk),
            focus_score=max(base_chunk.focus_score, other_chunk.focus_score)
        )
        
        return merged
    
    def _select_base_chunk(self, ast_chunk: CodeChunk, focus_chunk: CodeChunk) -> CodeChunk:
        """Select the better chunk as base for merging."""
        # Prioritize focus chunk if it has security findings
        if focus_chunk.security_findings and not ast_chunk.security_findings:
            return focus_chunk
        
        # Prioritize AST chunk if focus chunk has no findings
        if ast_chunk.security_findings and not focus_chunk.security_findings:
            return ast_chunk
        
        # Compare by focus score
        if focus_chunk.focus_score > ast_chunk.focus_score:
            return focus_chunk
        
        # Default to AST chunk for structural integrity
        return ast_chunk
    
    def _merge_metadata(self, base_meta: ChunkMetadata, other_meta: ChunkMetadata) -> ChunkMetadata:
        """Merge metadata from two chunks."""
        return ChunkMetadata(
            parent_file=base_meta.parent_file,
            language=base_meta.language,
            start_line=base_meta.start_line,
            end_line=base_meta.end_line,
            start_byte=base_meta.start_byte,
            end_byte=base_meta.end_byte,
            token_count=base_meta.token_count,
            character_count=base_meta.character_count,
            line_count=base_meta.line_count,
            primary_node_type=base_meta.primary_node_type or other_meta.primary_node_type,
            node_types=list(set(base_meta.node_types + other_meta.node_types)),
            function_names=list(set(base_meta.function_names + other_meta.function_names)),
            class_names=list(set(base_meta.class_names + other_meta.class_names)),
            imports=list(set(base_meta.imports + other_meta.imports)),
            function_calls=list(set(base_meta.function_calls + other_meta.function_calls)),
            variable_references=list(set(base_meta.variable_references + other_meta.variable_references)),
            complexity_score=max(base_meta.complexity_score or 0, other_meta.complexity_score or 0),
            maintainability_index=max(base_meta.maintainability_index or 0, other_meta.maintainability_index or 0)
        )
    
    def _select_best_chunk_type(self, type1: ChunkType, type2: ChunkType) -> ChunkType:
        """Select the best chunk type from two options."""
        # Priority order for chunk types
        type_priority = {
            ChunkType.FOCUSED: 5,
            ChunkType.FUNCTION: 4,
            ChunkType.CLASS: 3,
            ChunkType.CONTEXT: 2,
            ChunkType.BLOCK: 1,
            ChunkType.OVERLAP: 0
        }
        
        return type1 if type_priority.get(type1, 0) >= type_priority.get(type2, 0) else type2
    
    def _calculate_merged_priority(self, chunk1: CodeChunk, chunk2: CodeChunk) -> float:
        """Calculate priority for merged chunk."""
        # Weighted average with boost for security findings
        base_priority = (chunk1.priority_weight * self.weights.ast_weight + 
                        chunk2.priority_weight * self.weights.focus_weight)
        
        # Boost for security findings
        finding_boost = 0.2 if (chunk1.security_findings or chunk2.security_findings) else 0
        
        return min(base_priority + finding_boost, 1.0)
    
    def _handle_partial_overlaps(self, chunks: List[CodeChunk]) -> List[CodeChunk]:
        """Handle chunks with partial overlaps."""
        if len(chunks) <= 1:
            return chunks
        
        # Sort by start line
        sorted_chunks = sorted(chunks, key=lambda c: c.metadata.start_line)
        resolved = []
        
        i = 0
        while i < len(sorted_chunks):
            current = sorted_chunks[i]
            
            # Look for overlaps with subsequent chunks
            j = i + 1
            while j < len(sorted_chunks) and self._has_partial_overlap(current, sorted_chunks[j]):
                next_chunk = sorted_chunks[j]
                
                if self._should_merge_partial_overlap(current, next_chunk):
                    current = self._merge_partial_overlap(current, next_chunk)
                    j += 1  # Skip the merged chunk
                else:
                    break  # Stop merging
            
            resolved.append(current)
            i = j if j > i + 1 else i + 1
            self.overlap_resolutions += 1
        
        return resolved
    
    def _has_partial_overlap(self, chunk1: CodeChunk, chunk2: CodeChunk) -> bool:
        """Check if two chunks have partial overlap."""
        return (chunk1.metadata.start_line < chunk2.metadata.end_line and 
                chunk2.metadata.start_line < chunk1.metadata.end_line and
                not (chunk1.metadata.start_line == chunk2.metadata.start_line and
                     chunk1.metadata.end_line == chunk2.metadata.end_line))
    
    def _should_merge_partial_overlap(self, chunk1: CodeChunk, chunk2: CodeChunk) -> bool:
        """Determine if partially overlapping chunks should be merged."""
        # Calculate overlap ratio
        overlap_lines = min(chunk1.metadata.end_line, chunk2.metadata.end_line) - \
                       max(chunk1.metadata.start_line, chunk2.metadata.start_line)
        
        total_lines = max(chunk1.metadata.end_line, chunk2.metadata.end_line) - \
                     min(chunk1.metadata.start_line, chunk2.metadata.start_line)
        
        overlap_ratio = overlap_lines / total_lines if total_lines > 0 else 0
        
        # Merge if significant overlap or both have high focus scores
        return (overlap_ratio > 0.3 or 
                (chunk1.focus_score > 0.7 and chunk2.focus_score > 0.7))
    
    def _merge_partial_overlap(self, chunk1: CodeChunk, chunk2: CodeChunk) -> CodeChunk:
        """Merge two partially overlapping chunks."""
        # Determine new boundaries
        start_line = min(chunk1.metadata.start_line, chunk2.metadata.start_line)
        end_line = max(chunk1.metadata.end_line, chunk2.metadata.end_line)
        
        # Use the content from the chunk with higher focus score
        if chunk2.focus_score > chunk1.focus_score:
            base_chunk = chunk2
            other_chunk = chunk1
        else:
            base_chunk = chunk1
            other_chunk = chunk2
        
        # Create merged metadata
        merged_metadata = ChunkMetadata(
            parent_file=base_chunk.metadata.parent_file,
            language=base_chunk.metadata.language,
            start_line=start_line,
            end_line=end_line,
            start_byte=min(base_chunk.metadata.start_byte or 0, other_chunk.metadata.start_byte or 0),
            end_byte=max(base_chunk.metadata.end_byte or 0, other_chunk.metadata.end_byte or 0),
            token_count=base_chunk.metadata.token_count + other_chunk.metadata.token_count,
            character_count=base_chunk.metadata.character_count + other_chunk.metadata.character_count,
            line_count=end_line - start_line,
            primary_node_type=base_chunk.metadata.primary_node_type,
            node_types=list(set(base_chunk.metadata.node_types + other_chunk.metadata.node_types)),
            function_names=list(set(base_chunk.metadata.function_names + other_chunk.metadata.function_names)),
            class_names=list(set(base_chunk.metadata.class_names + other_chunk.metadata.class_names)),
            imports=list(set(base_chunk.metadata.imports + other_chunk.metadata.imports)),
            function_calls=list(set(base_chunk.metadata.function_calls + other_chunk.metadata.function_calls)),
            variable_references=list(set(base_chunk.metadata.variable_references + other_chunk.metadata.variable_references)),
            complexity_score=max(base_chunk.metadata.complexity_score or 0, other_chunk.metadata.complexity_score or 0)
        )
        
        return CodeChunk(
            content=base_chunk.content,  # Could be enhanced to merge content properly
            metadata=merged_metadata,
            chunk_type=self._select_best_chunk_type(base_chunk.chunk_type, other_chunk.chunk_type),
            parent_chunk_id=base_chunk.parent_chunk_id or other_chunk.parent_chunk_id,
            child_chunk_ids=list(set(base_chunk.child_chunk_ids + other_chunk.child_chunk_ids)),
            related_chunk_ids=list(set(base_chunk.related_chunk_ids + other_chunk.related_chunk_ids)),
            security_findings=list(set(base_chunk.security_findings + other_chunk.security_findings)),
            priority_weight=self._calculate_merged_priority(base_chunk, other_chunk),
            focus_score=max(base_chunk.focus_score, other_chunk.focus_score)
        )
    
    def _resolve_overlaps(self, chunks: List[CodeChunk]) -> List[CodeChunk]:
        """Final overlap resolution pass."""
        if not chunks:
            return chunks
        
        return self._handle_partial_overlaps(chunks)
    
    def _optimize_chunk_boundaries(self, chunks: List[CodeChunk], 
                                 context: ChunkingContext) -> List[CodeChunk]:
        """Optimize chunk boundaries for semantic coherence."""
        optimized = []
        
        for chunk in chunks:
            if self._needs_boundary_optimization(chunk):
                optimized_chunk = self._optimize_single_boundary(chunk, context)
                optimized.append(optimized_chunk)
                self.boundary_optimizations += 1
            else:
                optimized.append(chunk)
        
        return optimized
    
    def _needs_boundary_optimization(self, chunk: CodeChunk) -> bool:
        """Check if chunk needs boundary optimization."""
        # Check token count limits
        if (chunk.metadata.token_count < self.config.tokens.min_chunk_tokens or
            chunk.metadata.token_count > self.config.tokens.max_tokens_per_chunk):
            return True
        
        # Check semantic boundaries
        return not self._has_semantic_boundaries(chunk)
    
    def _has_semantic_boundaries(self, chunk: CodeChunk) -> bool:
        """Check if chunk has good semantic boundaries."""
        content = chunk.content.strip()
        if not content:
            return False
        
        lines = content.split('\n')
        first_line = lines[0].strip()
        
        # Check for semantic start indicators
        semantic_starts = ['def ', 'class ', 'function ', 'if ', 'for ', 'while ', 'try ']
        has_semantic_start = any(start in first_line for start in semantic_starts)
        
        return has_semantic_start or chunk.chunk_type in [ChunkType.FUNCTION, ChunkType.CLASS]
    
    def _optimize_single_boundary(self, chunk: CodeChunk, 
                                 context: ChunkingContext) -> CodeChunk:
        """Optimize boundaries of a single chunk."""
        # This is a simplified optimization - production version would use AST analysis
        content_lines = chunk.content.split('\n')
        
        # Find better start boundary
        start_idx = 0
        for i, line in enumerate(content_lines):
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                # Look for semantic boundaries
                if any(keyword in stripped for keyword in ['def ', 'class ', 'if ', 'for ']):
                    start_idx = i
                    break
        
        # Find better end boundary
        end_idx = len(content_lines)
        for i in range(len(content_lines) - 1, -1, -1):
            stripped = content_lines[i].strip()
            if stripped and not stripped.startswith('#'):
                end_idx = i + 1
                break
        
        # Apply optimization if beneficial
        if start_idx > 0 or end_idx < len(content_lines):
            optimized_content = '\n'.join(content_lines[start_idx:end_idx])
            
            # Update chunk
            optimized_chunk = chunk.model_copy()
            optimized_chunk.content = optimized_content
            optimized_chunk.metadata.start_line += start_idx
            optimized_chunk.metadata.end_line = optimized_chunk.metadata.start_line + (end_idx - start_idx)
            optimized_chunk.metadata.token_count = self.token_counter.count_tokens(optimized_content)
            optimized_chunk.metadata.character_count = len(optimized_content)
            optimized_chunk.metadata.line_count = len(optimized_content.splitlines())
            
            return optimized_chunk
        
        return chunk
    
    def _create_hybrid_result(self, file_path: Path, chunks: List[CodeChunk],
                             ast_result: ChunkingResult, focus_result: ChunkingResult) -> ChunkingResult:
        """Create comprehensive hybrid result."""
        result = ChunkingResult(
            source_file=file_path,
            strategy_used=self.strategy_name
        )
        
        # Add all chunks
        for chunk in chunks:
            result.add_chunk(chunk)
        
        # Merge relationships from both strategies
        result.chunk_relationships.extend(ast_result.chunk_relationships)
        result.chunk_relationships.extend(focus_result.chunk_relationships)
        
        # Merge overlap regions
        result.overlap_regions.extend(ast_result.overlap_regions)
        result.overlap_regions.extend(focus_result.overlap_regions)
        
        # Merge validation results if available
        if hasattr(ast_result, 'validation_results'):
            result.validation_results.extend(ast_result.validation_results)
        if hasattr(focus_result, 'validation_results'):
            result.validation_results.extend(focus_result.validation_results)
        
        # Merge errors and warnings
        result.errors.extend(ast_result.errors)
        result.errors.extend(focus_result.errors)
        result.warnings.extend(ast_result.warnings)
        result.warnings.extend(focus_result.warnings)
        
        return result
    
    def _log_strategy_performance(self, result: ChunkingResult, 
                                 ast_result: ChunkingResult, focus_result: ChunkingResult) -> None:
        """Log performance metrics."""
        logger.info(f"Hybrid strategy performance - Final: {len(result.chunks)} chunks, "
                   f"AST: {len(ast_result.chunks)}, Focus: {len(focus_result.chunks)}, "
                   f"Merged: {self.merged_chunks}, Optimized: {self.boundary_optimizations}")
    
    def get_strategy_metrics(self) -> Dict[str, Any]:
        """Get comprehensive strategy metrics."""
        base_metrics = super().get_strategy_metrics()
        
        hybrid_metrics = {
            'ast_chunks_created': self.ast_chunks_created,
            'focus_chunks_created': self.focus_chunks_created,
            'merged_chunks': self.merged_chunks,
            'overlap_resolutions': self.overlap_resolutions,
            'boundary_optimizations': self.boundary_optimizations,
            'merge_efficiency': self.merged_chunks / max(self.ast_chunks_created + self.focus_chunks_created, 1),
            'strategy_weights': {
                'ast_weight': self.weights.ast_weight,
                'focus_weight': self.weights.focus_weight,
                'overlap_threshold': self.weights.overlap_threshold
            }
        }
        
        return {**base_metrics, **hybrid_metrics}
    
    def reset_metrics(self) -> None:
        """Reset all metrics."""
        super().reset_metrics()
        self.ast_chunks_created = 0
        self.focus_chunks_created = 0
        self.merged_chunks = 0
        self.overlap_resolutions = 0
        self.boundary_optimizations = 0
    
    def configure_weights(self, ast_weight: float, focus_weight: float, 
                         overlap_threshold: int = 50) -> None:
        """Configure strategy weights dynamically."""
        total_weight = ast_weight + focus_weight
        if total_weight > 0:
            self.weights.ast_weight = ast_weight / total_weight
            self.weights.focus_weight = focus_weight / total_weight
            self.weights.overlap_threshold = overlap_threshold
            
            logger.debug(f"Updated strategy weights: AST={self.weights.ast_weight:.2f}, "
                        f"Focus={self.weights.focus_weight:.2f}")
