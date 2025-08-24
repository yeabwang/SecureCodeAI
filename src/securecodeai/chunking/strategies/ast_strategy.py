"""AST-aware chunking strategy for intelligent code chunking."""

import time
import logging
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path

from .base_strategy import ChunkingStrategy
from ..models import (
    CodeChunk, ChunkingResult, ChunkingContext, ChunkMetadata, 
    ChunkType, NodeType
)
from ..parsers import BaseParser, ParseResult
from ..utils import TokenCounter, timed_operation
from ..config import ChunkingConfig
from ..exceptions import ChunkingError, SyntaxBoundaryViolationError


logger = logging.getLogger(__name__)


class ASTAwareStrategy(ChunkingStrategy):
    """AST-aware chunking strategy that preserves semantic boundaries."""
    
    def __init__(self, 
                 config: ChunkingConfig,
                 token_counter: TokenCounter,
                 parser: Optional[BaseParser] = None):
        super().__init__(config, token_counter, parser)
        self.strategy_name = "ast_aware"
        
        # Strategy-specific configuration
        self.preserve_boundaries = config.strategy.ast_preserve_boundaries
        self.min_node_size = config.strategy.ast_min_node_size
        self.max_depth = config.strategy.ast_max_depth
    
    def can_handle(self, file_path: Path, content: str, 
                  context: ChunkingContext) -> bool:
        """Check if AST strategy can handle the content."""
        if not self.parser:
            return False
        
        # Must be a supported language
        if not self.parser.is_valid_syntax(content):
            return False
        
        # Must be large enough to benefit from AST chunking
        line_count = len(content.splitlines())
        return line_count >= self.min_node_size
    
    def get_priority(self, file_path: Path, content: str,
                    context: ChunkingContext) -> float:
        """Get priority for AST strategy."""
        base_priority = 0.7  # High priority for structured code
        
        # Increase priority for larger files
        line_count = len(content.splitlines())
        if line_count > 200:
            base_priority += 0.1
        
        # Increase priority if no findings (no need for focus)
        if not context.existing_findings:
            base_priority += 0.1
        
        # Decrease if syntax errors detected
        if self.parser and not self.parser.is_valid_syntax(content):
            base_priority -= 0.3
        
        return min(base_priority, 1.0)
    
    @timed_operation("chunk_processing", {"strategy": "ast_aware"})
    def chunk_content(self, 
                     content: str,
                     file_path: Path,
                     context: ChunkingContext) -> ChunkingResult:
        """Chunk content using AST-aware strategy."""
        start_time = time.time()
        result = ChunkingResult(
            source_file=file_path,
            strategy_used=self.strategy_name
        )
        
        try:
            # Parse the content
            if not self.parser:
                raise ChunkingError("No parser available for AST strategy")
            
            parse_result = self.parser.parse(content, file_path)
            
            # Find semantic boundaries
            semantic_chunks = self._find_semantic_boundaries(parse_result, context)
            
            # Create chunks from boundaries
            chunks = self._create_chunks_from_boundaries(
                semantic_chunks, content, file_path, parse_result
            )
            
            # Optimize chunks
            optimized_chunks = self.optimize_chunks(chunks)
            
            # Add chunks to result
            for chunk in optimized_chunks:
                result.add_chunk(chunk)
            
            # Create relationships and overlaps
            result.chunk_relationships = self.calculate_chunk_relationships(optimized_chunks)
            result.overlap_regions = self.create_overlap_regions(optimized_chunks)
            
            # Calculate metrics
            result.processing_time_ms = (time.time() - start_time) * 1000
            result.syntax_preservation_rate = self._calculate_syntax_preservation(optimized_chunks)
            result.boundary_preservation_rate = self._calculate_boundary_preservation(optimized_chunks)
            
            self._chunks_created += len(optimized_chunks)
            self._total_processing_time += result.processing_time_ms / 1000
            
            logger.info(f"AST strategy created {len(optimized_chunks)} chunks for {file_path}")
            
        except Exception as e:
            error_msg = f"AST chunking failed for {file_path}: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
            self._record_error(error_msg, {"file_path": str(file_path)})
        
        return result
    
    def _find_semantic_boundaries(self, parse_result: ParseResult, 
                                 context: ChunkingContext) -> List[Tuple[int, int, NodeType]]:
        """Find semantic boundaries in the parsed code."""
        boundaries = []
        max_chunk_lines = self.config.tokens.max_tokens_per_chunk // 10  # Rough estimate
        
        # Get semantic chunks from parser
        if self.parser and hasattr(self.parser, 'find_semantic_chunks'):
            parser_chunks = self.parser.find_semantic_chunks(parse_result, max_chunk_lines)
            boundaries.extend(parser_chunks)
        else:
            # Fallback to manual boundary detection
            boundaries = self._extract_manual_boundaries(parse_result)
        
        # Filter and sort boundaries
        valid_boundaries = []
        for start, end, node_type in boundaries:
            if end - start >= self.min_node_size:
                valid_boundaries.append((start, end, node_type))
        
        return sorted(valid_boundaries)
    
    def _extract_manual_boundaries(self, parse_result: ParseResult) -> List[Tuple[int, int, NodeType]]:
        """Manually extract boundaries from parse result."""
        boundaries = []
        
        # Add function boundaries
        for func in parse_result.functions:
            if 'start_line' in func and 'end_line' in func:
                boundaries.append((
                    func['start_line'],
                    func['end_line'],
                    NodeType.FUNCTION_DEF
                ))
        
        # Add class boundaries
        for cls in parse_result.classes:
            if 'start_line' in cls and 'end_line' in cls:
                boundaries.append((
                    cls['start_line'],
                    cls['end_line'],
                    NodeType.CLASS_DEF
                ))
        
        # If no major boundaries found, create logical blocks
        if not boundaries:
            boundaries = self._create_logical_blocks(parse_result)
        
        return boundaries
    
    def _create_logical_blocks(self, parse_result: ParseResult) -> List[Tuple[int, int, NodeType]]:
        """Create logical blocks when no major boundaries are found."""
        lines = parse_result.source_code.splitlines()
        total_lines = len(lines)
        
        if total_lines <= self.min_node_size:
            return [(1, total_lines, NodeType.BLOCK)]
        
        # Create blocks of reasonable size
        blocks = []
        block_size = min(100, total_lines // 3)  # Aim for 3-4 blocks
        
        start = 1
        while start <= total_lines:
            end = min(start + block_size - 1, total_lines)
            
            # Try to end at a natural boundary (empty line, comment, etc.)
            if end < total_lines:
                for i in range(end, min(end + 10, total_lines)):
                    line = lines[i-1].strip() if i <= len(lines) else ""
                    if not line or line.startswith('#') or line.startswith('//'):
                        end = i
                        break
            
            blocks.append((start, end, NodeType.BLOCK))
            start = end + 1
        
        return blocks
    
    def _create_chunks_from_boundaries(self, boundaries: List[Tuple[int, int, NodeType]],
                                     content: str, file_path: Path,
                                     parse_result: ParseResult) -> List[CodeChunk]:
        """Create chunks from semantic boundaries."""
        chunks = []
        lines = content.splitlines()
        
        for start_line, end_line, node_type in boundaries:
            try:
                # Extract chunk content
                chunk_lines = lines[start_line-1:end_line]
                chunk_content = '\n'.join(chunk_lines)
                
                if not chunk_content.strip():
                    continue
                
                # Validate syntax if configured
                if self.preserve_boundaries:
                    if not self._validate_chunk_syntax(chunk_content):
                        logger.warning(f"Syntax boundary violation at lines {start_line}-{end_line}")
                        continue
                
                # Create chunk metadata
                metadata = self._create_chunk_metadata(
                    chunk_content, file_path, start_line, end_line, node_type, parse_result
                )
                
                # Determine chunk type
                chunk_type = self._determine_chunk_type(node_type)
                
                # Create chunk
                chunk = CodeChunk(
                    content=chunk_content,
                    metadata=metadata,
                    chunk_type=chunk_type
                )
                
                chunks.append(chunk)
                
            except Exception as e:
                logger.error(f"Failed to create chunk at lines {start_line}-{end_line}: {e}")
                continue
        
        return chunks
    
    def _create_chunk_metadata(self, content: str, file_path: Path, 
                              start_line: int, end_line: int, node_type: NodeType,
                              parse_result: ParseResult) -> ChunkMetadata:
        """Create metadata for a chunk."""
        # Count tokens
        token_count = self.token_counter.count_tokens(content)
        
        # Extract functions and classes in this chunk
        chunk_functions = []
        chunk_classes = []
        
        for func in parse_result.functions:
            if (func.get('start_line', 0) >= start_line and 
                func.get('end_line', 0) <= end_line):
                chunk_functions.append(func.get('name', 'unknown'))
        
        for cls in parse_result.classes:
            if (cls.get('start_line', 0) >= start_line and 
                cls.get('end_line', 0) <= end_line):
                chunk_classes.append(cls.get('name', 'unknown'))
        
        # Extract imports (if at the beginning)
        chunk_imports = []
        if start_line <= 20:  # Imports usually at top
            for imp in parse_result.imports:
                if imp.get('line', 0) >= start_line and imp.get('line', 0) <= end_line:
                    chunk_imports.append(imp.get('module', 'unknown'))
        
        return ChunkMetadata(
            parent_file=file_path,
            language=parse_result.language,
            start_line=start_line,
            end_line=end_line,
            token_count=token_count,
            character_count=len(content),
            line_count=end_line - start_line + 1,
            primary_node_type=node_type,
            function_names=chunk_functions,
            class_names=chunk_classes,
            imports=chunk_imports
        )
    
    def _determine_chunk_type(self, node_type: NodeType) -> ChunkType:
        """Determine chunk type from node type."""
        type_mapping = {
            NodeType.FUNCTION_DEF: ChunkType.FUNCTION,
            NodeType.METHOD_DEF: ChunkType.FUNCTION,
            NodeType.CLASS_DEF: ChunkType.CLASS,
            NodeType.IMPORT_STMT: ChunkType.MODULE,
            NodeType.BLOCK: ChunkType.BLOCK
        }
        
        return type_mapping.get(node_type, ChunkType.BLOCK)
    
    def _validate_chunk_syntax(self, chunk_content: str) -> bool:
        """Validate that chunk has valid syntax."""
        if not self.parser:
            return True  # Can't validate without parser
        
        try:
            return self.parser.is_valid_syntax(chunk_content)
        except Exception:
            return False
    
    def _calculate_syntax_preservation(self, chunks: List[CodeChunk]) -> float:
        """Calculate syntax preservation rate."""
        if not chunks:
            return 1.0
        
        valid_chunks = 0
        for chunk in chunks:
            if self._validate_chunk_syntax(chunk.content):
                valid_chunks += 1
        
        return valid_chunks / len(chunks)
    
    def _calculate_boundary_preservation(self, chunks: List[CodeChunk]) -> float:
        """Calculate boundary preservation rate."""
        if not chunks:
            return 1.0
        
        preserved_boundaries = 0
        for chunk in chunks:
            # Check if chunk starts and ends at semantic boundaries
            if self._is_semantic_boundary(chunk):
                preserved_boundaries += 1
        
        return preserved_boundaries / len(chunks)
    
    def _is_semantic_boundary(self, chunk: CodeChunk) -> bool:
        """Check if chunk respects semantic boundaries."""
        # This is a simplified check - could be enhanced with AST analysis
        content = chunk.content.strip()
        
        # Check if starts with function/class definition
        first_line = content.split('\n')[0].strip()
        if (first_line.startswith('def ') or 
            first_line.startswith('class ') or
            first_line.startswith('function ') or
            first_line.startswith('export ')):
            return True
        
        # Check if it's a complete block (basic heuristic)
        if content.count('{') == content.count('}'):
            return True
        
        # Default to true for now
        return True
    
    def optimize_chunks(self, chunks: List[CodeChunk]) -> List[CodeChunk]:
        """Optimize chunks with AST-specific logic."""
        optimized = super().optimize_chunks(chunks)
        
        # AST-specific optimizations
        optimized = self._merge_small_chunks(optimized)
        optimized = self._split_large_chunks(optimized)
        
        return optimized
    
    def _merge_small_chunks(self, chunks: List[CodeChunk]) -> List[CodeChunk]:
        """Merge adjacent small chunks."""
        if len(chunks) <= 1:
            return chunks
        
        merged = []
        current_chunk = chunks[0]
        
        for next_chunk in chunks[1:]:
            # Check if chunks can be merged
            if self._can_merge_chunks(current_chunk, next_chunk):
                current_chunk = self._merge_two_chunks(current_chunk, next_chunk)
            else:
                merged.append(current_chunk)
                current_chunk = next_chunk
        
        merged.append(current_chunk)
        return merged
    
    def _can_merge_chunks(self, chunk1: CodeChunk, chunk2: CodeChunk) -> bool:
        """Check if two chunks can be merged."""
        # Must be from same file
        if chunk1.metadata.parent_file != chunk2.metadata.parent_file:
            return False
        
        # Must be adjacent or close
        if chunk2.metadata.start_line - chunk1.metadata.end_line > 3:
            return False
        
        # Combined size must not exceed limit
        combined_tokens = chunk1.metadata.token_count + chunk2.metadata.token_count
        if combined_tokens > self.config.tokens.max_tokens_per_chunk:
            return False
        
        # At least one chunk must be small
        min_tokens = self.config.tokens.min_chunk_tokens
        return (chunk1.metadata.token_count < min_tokens * 2 or 
                chunk2.metadata.token_count < min_tokens * 2)
    
    def _merge_two_chunks(self, chunk1: CodeChunk, chunk2: CodeChunk) -> CodeChunk:
        """Merge two chunks into one."""
        # Combine content
        combined_content = chunk1.content + '\n' + chunk2.content
        
        # Update metadata
        new_metadata = ChunkMetadata(
            parent_file=chunk1.metadata.parent_file,
            language=chunk1.metadata.language,
            start_line=chunk1.metadata.start_line,
            end_line=chunk2.metadata.end_line,
            token_count=self.token_counter.count_tokens(combined_content),
            character_count=len(combined_content),
            line_count=chunk2.metadata.end_line - chunk1.metadata.start_line + 1,
            primary_node_type=chunk1.metadata.primary_node_type,
            function_names=list(set(chunk1.metadata.function_names + chunk2.metadata.function_names)),
            class_names=list(set(chunk1.metadata.class_names + chunk2.metadata.class_names)),
            imports=list(set(chunk1.metadata.imports + chunk2.metadata.imports))
        )
        
        return CodeChunk(
            content=combined_content,
            metadata=new_metadata,
            chunk_type=chunk1.chunk_type
        )
    
    def _split_large_chunks(self, chunks: List[CodeChunk]) -> List[CodeChunk]:
        """Split chunks that are too large."""
        result = []
        
        for chunk in chunks:
            if chunk.metadata.token_count <= self.config.tokens.max_tokens_per_chunk:
                result.append(chunk)
            else:
                # Split large chunk
                split_chunks = self._split_chunk(chunk)
                result.extend(split_chunks)
        
        return result
    
    def _split_chunk(self, chunk: CodeChunk) -> List[CodeChunk]:
        """Split a large chunk into smaller ones."""
        lines = chunk.content.splitlines()
        max_tokens = self.config.tokens.max_tokens_per_chunk
        
        # Simple line-based splitting
        current_lines = []
        current_tokens = 0
        result_chunks = []
        start_line = chunk.metadata.start_line
        
        for i, line in enumerate(lines):
            line_tokens = self.token_counter.count_tokens(line)
            
            if current_tokens + line_tokens > max_tokens and current_lines:
                # Create chunk from current lines
                chunk_content = '\n'.join(current_lines)
                end_line = start_line + len(current_lines) - 1
                
                new_metadata = ChunkMetadata(
                    parent_file=chunk.metadata.parent_file,
                    language=chunk.metadata.language,
                    start_line=start_line,
                    end_line=end_line,
                    token_count=current_tokens,
                    character_count=len(chunk_content),
                    line_count=len(current_lines),
                    primary_node_type=NodeType.BLOCK
                )
                
                result_chunks.append(CodeChunk(
                    content=chunk_content,
                    metadata=new_metadata,
                    chunk_type=ChunkType.BLOCK
                ))
                
                # Reset for next chunk
                current_lines = [line]
                current_tokens = line_tokens
                start_line = start_line + len(current_lines)
            else:
                current_lines.append(line)
                current_tokens += line_tokens
        
        # Add remaining lines as final chunk
        if current_lines:
            chunk_content = '\n'.join(current_lines)
            end_line = start_line + len(current_lines) - 1
            
            new_metadata = ChunkMetadata(
                parent_file=chunk.metadata.parent_file,
                language=chunk.metadata.language,
                start_line=start_line,
                end_line=end_line,
                token_count=current_tokens,
                character_count=len(chunk_content),
                line_count=len(current_lines),
                primary_node_type=NodeType.BLOCK
            )
            
            result_chunks.append(CodeChunk(
                content=chunk_content,
                metadata=new_metadata,
                chunk_type=ChunkType.BLOCK
            ))
        
        return result_chunks
