"""Semantic-aware chunking strategy for intelligent code analysis."""

import time
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from .base_strategy import ChunkingStrategy
from ..models import CodeChunk, ChunkingContext, ChunkingResult, ChunkMetadata, ChunkType, NodeType
from ..config import ChunkingConfig
from ..utils import TokenCounter
from ..parsers import BaseParser, ParseResult
from ..exceptions import ChunkingError, ParsingError


logger = logging.getLogger(__name__)


class SemanticBoundary(str, Enum):
    """Types of semantic boundaries."""
    CLASS_DEFINITION = "class_definition"
    FUNCTION_DEFINITION = "function_definition"
    CONTROL_FLOW = "control_flow"
    EXCEPTION_HANDLING = "exception_handling"
    IMPORT_BLOCK = "import_block"
    VARIABLE_BLOCK = "variable_block"
    COMMENT_BLOCK = "comment_block"


@dataclass
class SemanticUnit:
    """Represents a semantic unit in the code."""
    boundary_type: SemanticBoundary
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    content: str
    semantic_weight: float
    dependencies: List[str]
    scope_level: int
    contains_nested: bool


class SemanticStrategy(ChunkingStrategy):
    """
    semantic-aware chunking strategy.
    
    This strategy:
    1. Analyzes code semantics using AST and heuristics
    2. Identifies logical code boundaries and relationships
    3. Creates chunks that preserve semantic coherence
    4. Maintains context and dependencies across chunks
    5. Provides semantic analysis and metrics
    """
    
    def __init__(self, config: ChunkingConfig, token_counter: TokenCounter, 
                 parser: Optional[BaseParser] = None):
        super().__init__(config, token_counter, parser)
        self.strategy_name = "semantic"
        
        # Semantic analysis configuration
        self.max_semantic_depth = 5
        self.preserve_scope_boundaries = True
        self.merge_related_units = True
        self.include_semantic_context = True
        
        # Semantic weights for different boundary types
        self.boundary_weights = {
            SemanticBoundary.CLASS_DEFINITION: 1.0,
            SemanticBoundary.FUNCTION_DEFINITION: 0.9,
            SemanticBoundary.CONTROL_FLOW: 0.7,
            SemanticBoundary.EXCEPTION_HANDLING: 0.8,
            SemanticBoundary.IMPORT_BLOCK: 0.6,
            SemanticBoundary.VARIABLE_BLOCK: 0.5,
            SemanticBoundary.COMMENT_BLOCK: 0.3
        }
        
        # Performance metrics
        self.semantic_units_found = 0
        self.boundaries_analyzed = 0
        self.chunks_merged = 0
        self.scope_preservations = 0
        self.context_enrichments = 0
        
        logger.debug(f"SemanticStrategy initialized with max_depth={self.max_semantic_depth}")
    
    def can_handle(self, file_path: Path, content: str, 
                  context: ChunkingContext) -> bool:
        """Check if this strategy can handle the given content."""
        if not self.parser:
            return False
        
        # Check if file has structured code that benefits from semantic analysis
        structured_indicators = [
            'class ', 'def ', 'function ', 'if ', 'for ', 'while ',
            'try:', 'except:', 'import ', 'from '
        ]
        
        content_lower = content.lower()
        indicator_count = sum(1 for indicator in structured_indicators 
                            if indicator in content_lower)
        
        # Need at least 3 structured elements for semantic analysis to be worthwhile
        return indicator_count >= 3
    
    def get_priority(self, file_path: Path, content: str,
                    context: ChunkingContext) -> float:
        """Get priority score for this strategy."""
        if not self.can_handle(file_path, content, context):
            return 0.0
        
        # Analyze code structure complexity
        structure_score = self._analyze_structure_complexity(content)
        
        # High priority for well-structured code
        if structure_score >= 0.8:
            return 0.9
        elif structure_score >= 0.6:
            return 0.75
        elif structure_score >= 0.4:
            return 0.6
        
        return 0.4
    
    def chunk_content(self, content: str, file_path: Path, 
                     context: ChunkingContext) -> ChunkingResult:
        """Chunk content based on semantic boundaries with meaningful units."""
        start_time = time.time()
        
        try:
            if not self.parser:
                raise ChunkingError("No parser available for semantic chunking")
            
            # Parse the content for semantic analysis
            parse_result = self._parse_content(content, file_path)
            
            # Create meaningful semantic chunks
            chunks = self._create_meaningful_semantic_chunks(parse_result, content, file_path, context)
            
            # Create result
            result = ChunkingResult(
                source_file=file_path,
                strategy_used=self.strategy_name
            )
            
            for chunk in chunks:
                result.add_chunk(chunk)
            
            result.processing_time_ms = (time.time() - start_time) * 1000
            self._chunks_created += len(result.chunks)
            
            logger.info(f"Semantic strategy created {len(result.chunks)} meaningful chunks")
            
            return result
            
        except Exception as e:
            logger.error(f"Semantic chunking failed: {e}")
            self._errors.append(str(e))
            raise ChunkingError(f"Semantic chunking failed: {e}")
    
    def _create_meaningful_semantic_chunks(self, parse_result: ParseResult, content: str,
                                         file_path: Path, context: ChunkingContext) -> List[CodeChunk]:
        """Create semantically meaningful chunks that preserve complete units."""
        chunks = []
        content_lines = content.split('\n')
        
        if not parse_result.ast or not hasattr(parse_result.ast, 'root_node'):
            # Fallback to heuristic chunking
            return self._create_heuristic_semantic_chunks(content_lines, file_path, context)
        
        root_node = parse_result.ast.root_node
        processed_lines = set()
        
        # 1. Extract import blocks first
        import_chunks = self._extract_import_blocks(root_node, content_lines, file_path, context, processed_lines)
        chunks.extend(import_chunks)
        
        # 2. Extract complete classes (with all their methods)
        class_chunks = self._extract_complete_classes(root_node, content_lines, file_path, context, processed_lines)
        chunks.extend(class_chunks)
        
        # 3. Extract standalone functions
        function_chunks = self._extract_standalone_functions(root_node, content_lines, file_path, context, processed_lines)
        chunks.extend(function_chunks)
        
        # 4. Extract global variables and constants
        global_chunks = self._extract_global_variables(root_node, content_lines, file_path, context, processed_lines)
        chunks.extend(global_chunks)
        
        # 5. Extract any remaining meaningful code blocks
        remaining_chunks = self._extract_remaining_blocks(content_lines, file_path, context, processed_lines)
        chunks.extend(remaining_chunks)
        
        # Sort chunks by start line to maintain order
        chunks.sort(key=lambda c: c.metadata.start_line)
        
        return chunks
    
    def _analyze_structure_complexity(self, content: str) -> float:
        """Analyze the structural complexity of the code."""
        lines = content.split('\n')
        structure_indicators = {
            'class ': 0.2,
            'def ': 0.15,
            'function ': 0.15,
            'if ': 0.1,
            'for ': 0.1,
            'while ': 0.1,
            'try:': 0.1,
            'except:': 0.1
        }
        
        complexity_score = 0.0
        total_lines = len(lines)
        
        for line in lines:
            line_lower = line.strip().lower()
            for indicator, weight in structure_indicators.items():
                if line_lower.startswith(indicator):
                    complexity_score += weight
        
        # Normalize by file size
        normalized_score = min(complexity_score / max(total_lines / 50, 1), 1.0)
        
        return normalized_score
    
    def _parse_content(self, content: str, file_path: Path) -> ParseResult:
        """Parse content for semantic analysis."""
        try:
            if not self.parser:
                raise ParsingError(f"No parser available for file {file_path}")
            return self.parser.parse(content, file_path)
        except Exception as e:
            raise ParsingError(f"Failed to parse {file_path}: {e}")
    
    def _identify_semantic_units(self, parse_result: ParseResult, content: str) -> List[SemanticUnit]:
        """Identify complete, meaningful semantic units in the parsed code."""
        semantic_units = []
        content_lines = content.split('\n')
        
        # Primary approach: Identify complete logical units (classes, functions, etc.)
        if parse_result.ast and hasattr(parse_result.ast, 'root_node'):
            semantic_units = self._extract_complete_semantic_units(parse_result.ast.root_node, content, content_lines)
        
        # If AST parsing failed or no units found, fall back to heuristic approach
        if not semantic_units:
            semantic_units = self._extract_heuristic_semantic_units(content_lines)
        
        # Ensure units are complete and non-overlapping
        return self._ensure_complete_semantic_units(semantic_units, content_lines)
    
    def _extract_complete_semantic_units(self, root_node, content: str, content_lines: List[str]) -> List[SemanticUnit]:
        """Extract complete semantic units that preserve full context."""
        units = []
        
        # Find top-level definitions (classes, functions, imports)
        for node in root_node.children:
            if not hasattr(node, 'type'):
                continue
                
            unit = None
            
            if node.type == 'class_definition':
                unit = self._extract_complete_class(node, content, content_lines)
            elif node.type in ['function_definition', 'method_definition']:
                unit = self._extract_complete_function(node, content, content_lines)
            elif node.type in ['import_statement', 'import_from_statement']:
                # Group imports together rather than individual statements
                if not units or units[-1].boundary_type != SemanticBoundary.IMPORT_BLOCK:
                    unit = self._extract_import_block(node, content, content_lines, root_node)
            elif node.type in ['if_statement', 'for_statement', 'while_statement', 'try_statement']:
                # Only extract standalone control structures (not those inside functions/classes)
                if self._is_top_level_control_structure(node):
                    unit = self._extract_complete_control_structure(node, content, content_lines)
            
            if unit:
                units.append(unit)
        
        return units
    
    def _is_top_level_control_structure(self, node) -> bool:
        """Check if a control structure is at the top level (not inside a function/class)."""
        current = node.parent if hasattr(node, 'parent') else None
        while current:
            if hasattr(current, 'type') and current.type in ['function_definition', 'method_definition', 'class_definition']:
                return False
            current = current.parent if hasattr(current, 'parent') else None
        return True
    
    def _extract_complete_class(self, node, content: str, content_lines: List[str]) -> SemanticUnit:
        """Extract a complete class definition with all its methods and context."""
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        
        # Expand to include decorators and docstrings before the class
        expanded_start = self._find_logical_start(start_line, content_lines)
        
        # Expand to include any trailing comments or related code
        expanded_end = self._find_logical_end(end_line, content_lines)
        
        # Extract the complete content
        complete_content = '\n'.join(content_lines[expanded_start-1:expanded_end])
        
        return SemanticUnit(
            boundary_type=SemanticBoundary.CLASS_DEFINITION,
            start_line=expanded_start,
            end_line=expanded_end,
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            content=complete_content,
            semantic_weight=1.0,  # Highest weight for complete classes
            dependencies=self._extract_class_dependencies(complete_content),
            scope_level=0,  # Top-level class
            contains_nested=self._contains_methods_or_nested_classes(node)
        )
    
    def _extract_complete_function(self, node, content: str, content_lines: List[str]) -> SemanticUnit:
        """Extract a complete function with decorators, docstring, and full body."""
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        
        # Include decorators and comments before function
        expanded_start = self._find_logical_start(start_line, content_lines)
        
        # Include any trailing comments
        expanded_end = self._find_logical_end(end_line, content_lines)
        
        # Extract complete content
        complete_content = '\n'.join(content_lines[expanded_start-1:expanded_end])
        
        # Check if this is a security-sensitive function
        is_security_sensitive = self._is_security_sensitive_function(complete_content)
        semantic_weight = 0.95 if is_security_sensitive else 0.9
        
        return SemanticUnit(
            boundary_type=SemanticBoundary.FUNCTION_DEFINITION,
            start_line=expanded_start,
            end_line=expanded_end,
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            content=complete_content,
            semantic_weight=semantic_weight,
            dependencies=self._extract_function_dependencies(complete_content),
            scope_level=self._calculate_function_scope_level(node),
            contains_nested=self._contains_nested_functions(node)
        )
    
    def _extract_import_block(self, node, content: str, content_lines: List[str], root_node) -> SemanticUnit:
        """Extract a complete import block (group consecutive imports)."""
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        
        # Find the start of the import block
        block_start = start_line
        for i in range(start_line - 1, 0, -1):
            line = content_lines[i - 1].strip()
            if line.startswith(('import ', 'from ')) or line.startswith('#') or not line:
                block_start = i
            else:
                break
        
        # Find the end of the import block
        block_end = end_line
        for i in range(end_line, len(content_lines)):
            line = content_lines[i].strip()
            if line.startswith(('import ', 'from ')) or line.startswith('#') or not line:
                block_end = i + 1
            else:
                break
        
        # Extract complete import block
        complete_content = '\n'.join(content_lines[block_start-1:block_end])
        
        return SemanticUnit(
            boundary_type=SemanticBoundary.IMPORT_BLOCK,
            start_line=block_start,
            end_line=block_end,
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            content=complete_content,
            semantic_weight=0.6,
            dependencies=self._extract_import_dependencies(complete_content),
            scope_level=0,
            contains_nested=False
        )
    
    def _extract_complete_control_structure(self, node, content: str, content_lines: List[str]) -> SemanticUnit:
        """Extract complete control structures with full context."""
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        
        # Include any comments before the control structure
        expanded_start = self._find_logical_start(start_line, content_lines)
        
        # Ensure we capture the complete structure including else/elif/except blocks
        expanded_end = self._find_complete_control_end(node, end_line, content_lines)
        
        complete_content = '\n'.join(content_lines[expanded_start-1:expanded_end])
        
        # Determine semantic weight based on security relevance
        security_keywords = ['password', 'auth', 'login', 'token', 'secret', 'key', 'admin', 'sql', 'query']
        is_security_relevant = any(keyword in complete_content.lower() for keyword in security_keywords)
        semantic_weight = 0.85 if is_security_relevant else 0.7
        
        boundary_type = SemanticBoundary.EXCEPTION_HANDLING if node.type == 'try_statement' else SemanticBoundary.CONTROL_FLOW
        
        return SemanticUnit(
            boundary_type=boundary_type,
            start_line=expanded_start,
            end_line=expanded_end,
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            content=complete_content,
            semantic_weight=semantic_weight,
            dependencies=self._extract_control_dependencies(complete_content),
            scope_level=self._calculate_function_scope_level(node),
            contains_nested=self._contains_nested_control(node)
        )
    
    def _remove_overlapping_units(self, units: List[SemanticUnit]) -> List[SemanticUnit]:
        """Remove overlapping semantic units, keeping the most specific ones."""
        if not units:
            return units
            
        non_overlapping = []
        current_unit = units[0]
        
        for next_unit in units[1:]:
            # Check if units overlap
            if (current_unit.start_line <= next_unit.start_line <= current_unit.end_line or
                next_unit.start_line <= current_unit.start_line <= next_unit.end_line):
                
                # Keep the more specific unit (smaller range or higher priority boundary)
                current_range = current_unit.end_line - current_unit.start_line
                next_range = next_unit.end_line - next_unit.start_line
                
                # Prefer smaller, more specific units
                if next_range < current_range:
                    current_unit = next_unit
                # If same size, prefer function/class definitions over general blocks
                elif (next_range == current_range and 
                      next_unit.boundary_type in [SemanticBoundary.FUNCTION_DEFINITION, SemanticBoundary.CLASS_DEFINITION] and
                      current_unit.boundary_type not in [SemanticBoundary.FUNCTION_DEFINITION, SemanticBoundary.CLASS_DEFINITION]):
                    current_unit = next_unit
            else:
                # No overlap, add current unit and move to next
                non_overlapping.append(current_unit)
                current_unit = next_unit
        
        # Add the last unit
        non_overlapping.append(current_unit)
        return non_overlapping
    
    def _create_semantic_unit(self, node, content: str, content_bytes: bytes) -> Optional[SemanticUnit]:
        """Create a semantic unit from an AST node."""
        try:
            if not hasattr(node, 'type') or not hasattr(node, 'start_point'):
                return None
            
            # Map node types to semantic boundaries
            boundary_mapping = {
                'class_definition': SemanticBoundary.CLASS_DEFINITION,
                'function_definition': SemanticBoundary.FUNCTION_DEFINITION,
                'method_definition': SemanticBoundary.FUNCTION_DEFINITION,
                'if_statement': SemanticBoundary.CONTROL_FLOW,
                'for_statement': SemanticBoundary.CONTROL_FLOW,
                'while_statement': SemanticBoundary.CONTROL_FLOW,
                'try_statement': SemanticBoundary.EXCEPTION_HANDLING,
                'import_statement': SemanticBoundary.IMPORT_BLOCK,
                'import_from_statement': SemanticBoundary.IMPORT_BLOCK
            }
            
            boundary_type = boundary_mapping.get(node.type)
            if not boundary_type:
                return None
            
            # Extract position information
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            start_byte = node.start_byte
            end_byte = node.end_byte
            
            # Extract content
            unit_content = content[start_byte:end_byte]
            
            # Calculate semantic properties
            semantic_weight = self.boundary_weights.get(boundary_type, 0.5)
            dependencies = self._extract_dependencies(unit_content, boundary_type)
            scope_level = self._calculate_scope_level(node)
            contains_nested = self._has_nested_structures(node)
            
            return SemanticUnit(
                boundary_type=boundary_type,
                start_line=start_line,
                end_line=end_line,
                start_byte=start_byte,
                end_byte=end_byte,
                content=unit_content,
                semantic_weight=semantic_weight,
                dependencies=dependencies,
                scope_level=scope_level,
                contains_nested=contains_nested
            )
            
        except Exception as e:
            logger.debug(f"Failed to create semantic unit: {e}")
            return None
    
    def _extract_dependencies(self, content: str, boundary_type: SemanticBoundary) -> List[str]:
        """Extract dependencies for a semantic unit."""
        dependencies = []
        
        if boundary_type == SemanticBoundary.IMPORT_BLOCK:
            # Extract imported modules/functions
            lines = content.split('\n')
            for line in lines:
                if 'import ' in line:
                    # Simple extraction - would be more sophisticated in production
                    parts = line.replace('from ', '').replace('import ', '').split()
                    dependencies.extend(parts)
        
        elif boundary_type in [SemanticBoundary.FUNCTION_DEFINITION, SemanticBoundary.CLASS_DEFINITION]:
            # Extract function calls and variable references
            import re
            # Find function calls
            call_pattern = r'(\w+)\s*\('
            calls = re.findall(call_pattern, content)
            dependencies.extend(calls)
        
        return list(set(dependencies))  # Remove duplicates
    
    def _calculate_scope_level(self, node) -> int:
        """Calculate the scope level of a node."""
        level = 0
        current = node.parent if hasattr(node, 'parent') else None
        
        while current:
            if hasattr(current, 'type'):
                if current.type in ['class_definition', 'function_definition', 'method_definition']:
                    level += 1
            current = current.parent if hasattr(current, 'parent') else None
        
        return level
    
    def _has_nested_structures(self, node) -> bool:
        """Check if a node contains nested structures."""
        if not hasattr(node, 'children'):
            return False
        
        nested_types = {'class_definition', 'function_definition', 'method_definition'}
        
        for child in node.children:
            if hasattr(child, 'type') and child.type in nested_types:
                return True
        
        return False
    
    def _analyze_semantic_boundaries(self, semantic_units: List[SemanticUnit], 
                                   content: str) -> List[SemanticUnit]:
        """Analyze and refine semantic boundaries."""
        if not semantic_units:
            return []
        
        refined_boundaries = []
        content_lines = content.split('\n')
        
        for unit in semantic_units:
            # Refine boundary based on semantic analysis
            refined_unit = self._refine_boundary(unit, content_lines)
            refined_boundaries.append(refined_unit)
        
        # Merge consecutive units of the same type if beneficial
        merged_boundaries = self._merge_consecutive_units(refined_boundaries)
        
        return merged_boundaries
    
    def _refine_boundary(self, unit: SemanticUnit, content_lines: List[str]) -> SemanticUnit:
        """Refine the boundary of a semantic unit."""
        # Look for better start boundary (include comments, decorators)
        refined_start = unit.start_line
        for i in range(unit.start_line - 2, 0, -1):  # Look backwards
            line = content_lines[i - 1].strip()  # Convert to 0-indexed
            if line.startswith('#') or line.startswith('@'):
                refined_start = i
            elif line:  # Non-empty, non-comment line
                break
        
        # Look for better end boundary (include trailing comments)
        refined_end = unit.end_line
        for i in range(unit.end_line, min(len(content_lines), unit.end_line + 3)):
            line = content_lines[i - 1].strip()  # Convert to 0-indexed
            if line.startswith('#'):
                refined_end = i
            elif line:  # Non-empty, non-comment line
                break
        
        # Create refined unit
        refined_unit = SemanticUnit(
            boundary_type=unit.boundary_type,
            start_line=refined_start,
            end_line=refined_end,
            start_byte=unit.start_byte,
            end_byte=unit.end_byte,
            content=unit.content,
            semantic_weight=unit.semantic_weight,
            dependencies=unit.dependencies,
            scope_level=unit.scope_level,
            contains_nested=unit.contains_nested
        )
        
        return refined_unit
    
    def _merge_consecutive_units(self, units: List[SemanticUnit]) -> List[SemanticUnit]:
        """Merge consecutive units of compatible types."""
        if len(units) <= 1:
            return units
        
        merged = []
        current = units[0]
        
        for next_unit in units[1:]:
            if self._should_merge_units(current, next_unit):
                current = self._merge_semantic_units(current, next_unit)
            else:
                merged.append(current)
                current = next_unit
        
        merged.append(current)
        return merged
    
    def _should_merge_units(self, unit1: SemanticUnit, unit2: SemanticUnit) -> bool:
        """Determine if two semantic units should be merged."""
        # Merge units of the same type that are adjacent
        if unit1.boundary_type == unit2.boundary_type:
            # Check if they're adjacent (with small gap allowed)
            gap = unit2.start_line - unit1.end_line
            if gap <= 2:  # Allow small gaps for whitespace
                return True
        
        # Merge import blocks
        if (unit1.boundary_type == SemanticBoundary.IMPORT_BLOCK and
            unit2.boundary_type == SemanticBoundary.IMPORT_BLOCK):
            return True
        
        return False
    
    def _merge_semantic_units(self, unit1: SemanticUnit, unit2: SemanticUnit) -> SemanticUnit:
        """Merge two semantic units."""
        return SemanticUnit(
            boundary_type=unit1.boundary_type,
            start_line=unit1.start_line,
            end_line=unit2.end_line,
            start_byte=unit1.start_byte,
            end_byte=unit2.end_byte,
            content=unit1.content + '\n' + unit2.content,
            semantic_weight=max(unit1.semantic_weight, unit2.semantic_weight),
            dependencies=list(set(unit1.dependencies + unit2.dependencies)),
            scope_level=min(unit1.scope_level, unit2.scope_level),
            contains_nested=unit1.contains_nested or unit2.contains_nested
        )
    
    def _create_semantic_chunks(self, boundaries: List[SemanticUnit], content: str,
                               file_path: Path, context: ChunkingContext) -> List[CodeChunk]:
        """Create chunks based on semantic boundaries."""
        chunks = []
        content_lines = content.split('\n')
        
        for unit in boundaries:
            chunk = self._create_single_semantic_chunk(unit, content_lines, file_path, context)
            if chunk:
                chunks.append(chunk)
        
        return chunks
    
    def _create_single_semantic_chunk(self, unit: SemanticUnit, content_lines: List[str],
                                     file_path: Path, context: ChunkingContext) -> Optional[CodeChunk]:
        """Create a chunk for a single semantic unit."""
        try:
            # Extract chunk content
            chunk_content = '\n'.join(content_lines[unit.start_line-1:unit.end_line])
            
            # Check token limits
            token_count = self.token_counter.count_tokens(chunk_content)
            if token_count > self.config.tokens.max_tokens_per_chunk:
                # Try to split large semantic units
                chunk_content = self._handle_large_semantic_unit(unit, chunk_content)
                token_count = self.token_counter.count_tokens(chunk_content)
            
            # Create metadata
            metadata = ChunkMetadata(
                parent_file=file_path,
                language=self._get_language_from_extension(file_path),
                start_line=unit.start_line,
                end_line=unit.end_line,
                start_byte=unit.start_byte,
                end_byte=unit.end_byte,
                token_count=token_count,
                character_count=len(chunk_content),
                line_count=unit.end_line - unit.start_line + 1,
                primary_node_type=self._boundary_to_node_type(unit.boundary_type),
                node_types=[self._boundary_to_node_type(unit.boundary_type)],
                function_names=self._extract_function_names(chunk_content, unit.boundary_type),
                class_names=self._extract_class_names(chunk_content, unit.boundary_type),
                imports=unit.dependencies if unit.boundary_type == SemanticBoundary.IMPORT_BLOCK else [],
                function_calls=unit.dependencies if unit.boundary_type != SemanticBoundary.IMPORT_BLOCK else [],
                variable_references=[],
                complexity_score=self._calculate_semantic_complexity(unit)
            )
            
            # Determine chunk type
            chunk_type = self._boundary_to_chunk_type(unit.boundary_type)
            
            # Create chunk
            chunk = CodeChunk(
                content=chunk_content,
                metadata=metadata,
                chunk_type=chunk_type,
                priority_weight=unit.semantic_weight,
                focus_score=self._calculate_semantic_focus_score(unit, context)
            )
            
            return chunk
            
        except Exception as e:
            logger.warning(f"Failed to create semantic chunk: {e}")
            return None
    
    def _boundary_to_node_type(self, boundary_type: SemanticBoundary) -> NodeType:
        """Convert semantic boundary to node type."""
        mapping = {
            SemanticBoundary.CLASS_DEFINITION: NodeType.CLASS_DEF,
            SemanticBoundary.FUNCTION_DEFINITION: NodeType.FUNCTION_DEF,
            SemanticBoundary.CONTROL_FLOW: NodeType.IF_STMT,
            SemanticBoundary.EXCEPTION_HANDLING: NodeType.TRY_STMT,
            SemanticBoundary.IMPORT_BLOCK: NodeType.IMPORT_STMT,
            SemanticBoundary.VARIABLE_BLOCK: NodeType.BLOCK,
            SemanticBoundary.COMMENT_BLOCK: NodeType.BLOCK
        }
        
        return mapping.get(boundary_type, NodeType.BLOCK)
    
    def _boundary_to_chunk_type(self, boundary_type: SemanticBoundary) -> ChunkType:
        """Convert semantic boundary to chunk type."""
        mapping = {
            SemanticBoundary.CLASS_DEFINITION: ChunkType.CLASS,
            SemanticBoundary.FUNCTION_DEFINITION: ChunkType.FUNCTION,
            SemanticBoundary.CONTROL_FLOW: ChunkType.BLOCK,
            SemanticBoundary.EXCEPTION_HANDLING: ChunkType.BLOCK,
            SemanticBoundary.IMPORT_BLOCK: ChunkType.CONTEXT,
            SemanticBoundary.VARIABLE_BLOCK: ChunkType.BLOCK,
            SemanticBoundary.COMMENT_BLOCK: ChunkType.CONTEXT
        }
        
        return mapping.get(boundary_type, ChunkType.BLOCK)
    
    def _get_language_from_extension(self, file_path: Path) -> str:
        """Get language from file extension."""
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.cpp': 'cpp',
            '.c': 'c',
            '.cs': 'csharp'
        }
        
        return extension_map.get(file_path.suffix.lower(), 'unknown')
    
    def _extract_function_names(self, content: str, boundary_type: SemanticBoundary) -> List[str]:
        """Extract function names from content."""
        if boundary_type != SemanticBoundary.FUNCTION_DEFINITION:
            return []
        
        import re
        # Simple regex for function names
        pattern = r'def\s+(\w+)\s*\('
        matches = re.findall(pattern, content)
        return matches
    
    def _extract_class_names(self, content: str, boundary_type: SemanticBoundary) -> List[str]:
        """Extract class names from content."""
        if boundary_type != SemanticBoundary.CLASS_DEFINITION:
            return []
        
        import re
        # Simple regex for class names
        pattern = r'class\s+(\w+)[\s\(:]'
        matches = re.findall(pattern, content)
        return matches
    
    def _calculate_semantic_complexity(self, unit: SemanticUnit) -> float:
        """Calculate complexity score for a semantic unit."""
        base_complexity = unit.semantic_weight
        
        # Boost for nested structures
        if unit.contains_nested:
            base_complexity += 0.2
        
        # Boost for deep scope levels
        base_complexity += unit.scope_level * 0.1
        
        # Boost for many dependencies
        if len(unit.dependencies) > 5:
            base_complexity += 0.1
        
        return min(base_complexity, 1.0)
    
    def _calculate_semantic_focus_score(self, unit: SemanticUnit, context: ChunkingContext) -> float:
        """Calculate focus score for a semantic unit."""
        focus_score = unit.semantic_weight
        
        # Check relevance to existing findings
        if context.existing_findings:
            for finding in context.existing_findings:
                if any(dep in finding.description for dep in unit.dependencies):
                    focus_score = max(focus_score, 0.8)
        
        # Higher focus for classes and functions
        if unit.boundary_type in [SemanticBoundary.CLASS_DEFINITION, SemanticBoundary.FUNCTION_DEFINITION]:
            focus_score = max(focus_score, 0.6)
        
        return focus_score
    
    def _handle_large_semantic_unit(self, unit: SemanticUnit, content: str) -> str:
        """Handle semantic units that exceed token limits."""
        lines = content.split('\n')
        
        # Keep semantic boundaries intact, truncate content if necessary
        if len(lines) <= 5:  # Don't truncate very small units
            return content
        
        # Keep first and last few lines to preserve semantic structure
        preserved_lines = lines[:3] + ['    # ... content truncated ...'] + lines[-2:]
        return '\n'.join(preserved_lines)
    
    def _merge_related_chunks(self, chunks: List[CodeChunk], 
                             semantic_units: List[SemanticUnit]) -> List[CodeChunk]:
        """Merge semantically related chunks."""
        if len(chunks) <= 1:
            return chunks
        
        merged = []
        processed = set()
        
        for i, chunk in enumerate(chunks):
            if i in processed:
                continue
            
            current = chunk
            
            # Look for related chunks to merge
            for j in range(i + 1, len(chunks)):
                if j in processed:
                    continue
                
                if self._are_chunks_related(current, chunks[j], semantic_units):
                    current = self._merge_semantic_chunks(current, chunks[j])
                    processed.add(j)
                    self.chunks_merged += 1
            
            merged.append(current)
            processed.add(i)
        
        return merged
    
    def _are_chunks_related(self, chunk1: CodeChunk, chunk2: CodeChunk,
                           semantic_units: List[SemanticUnit]) -> bool:
        """Check if two chunks are semantically related."""
        # Check if chunks are adjacent
        if abs(chunk1.metadata.end_line - chunk2.metadata.start_line) <= 3:
            return True
        
        # Check for common dependencies
        deps1 = set(chunk1.metadata.function_calls + chunk1.metadata.imports)
        deps2 = set(chunk2.metadata.function_calls + chunk2.metadata.imports)
        
        if len(deps1 & deps2) >= 2:  # At least 2 common dependencies
            return True
        
        return False
    
    def _merge_semantic_chunks(self, chunk1: CodeChunk, chunk2: CodeChunk) -> CodeChunk:
        """Merge two semantically related chunks."""
        # Combine content
        combined_content = chunk1.content + '\n\n' + chunk2.content
        
        # Create merged metadata
        merged_metadata = ChunkMetadata(
            parent_file=chunk1.metadata.parent_file,
            language=chunk1.metadata.language,
            start_line=min(chunk1.metadata.start_line, chunk2.metadata.start_line),
            end_line=max(chunk1.metadata.end_line, chunk2.metadata.end_line),
            start_byte=min(chunk1.metadata.start_byte or 0, chunk2.metadata.start_byte or 0),
            end_byte=max(chunk1.metadata.end_byte or 0, chunk2.metadata.end_byte or 0),
            token_count=self.token_counter.count_tokens(combined_content),
            character_count=len(combined_content),
            line_count=len(combined_content.split('\n')),
            primary_node_type=chunk1.metadata.primary_node_type,
            node_types=list(set(chunk1.metadata.node_types + chunk2.metadata.node_types)),
            function_names=list(set(chunk1.metadata.function_names + chunk2.metadata.function_names)),
            class_names=list(set(chunk1.metadata.class_names + chunk2.metadata.class_names)),
            imports=list(set(chunk1.metadata.imports + chunk2.metadata.imports)),
            function_calls=list(set(chunk1.metadata.function_calls + chunk2.metadata.function_calls)),
            variable_references=list(set(chunk1.metadata.variable_references + chunk2.metadata.variable_references)),
            complexity_score=max(chunk1.metadata.complexity_score or 0.0, chunk2.metadata.complexity_score or 0.0)
        )
        
        # Create merged chunk
        return CodeChunk(
            content=combined_content,
            metadata=merged_metadata,
            chunk_type=chunk1.chunk_type,
            priority_weight=max(chunk1.priority_weight, chunk2.priority_weight),
            focus_score=max(chunk1.focus_score, chunk2.focus_score)
        )

    # ================== NEW SEMANTIC ANALYSIS HELPER METHODS ==================
    
    def _extract_heuristic_semantic_units(self, content_lines: List[str]) -> List[SemanticUnit]:
        """Fallback heuristic approach when AST parsing fails."""
        units = []
        i = 0
        
        while i < len(content_lines):
            line = content_lines[i].strip()
            
            if line.startswith('class '):
                unit = self._extract_heuristic_class(i, content_lines)
                if unit:
                    units.append(unit)
                    i = unit.end_line
                continue
            elif line.startswith('def '):
                unit = self._extract_heuristic_function(i, content_lines)
                if unit:
                    units.append(unit)
                    i = unit.end_line
                continue
            elif line.startswith(('import ', 'from ')):
                unit = self._extract_heuristic_imports(i, content_lines)
                if unit:
                    units.append(unit)
                    i = unit.end_line
                continue
            
            i += 1
        
        return units
    
    def _extract_heuristic_class(self, start_idx: int, content_lines: List[str]) -> Optional[SemanticUnit]:
        """Extract class using indentation heuristics."""
        start_line = start_idx + 1
        indent_level = len(content_lines[start_idx]) - len(content_lines[start_idx].lstrip())
        
        end_idx = start_idx + 1
        while end_idx < len(content_lines):
            line = content_lines[end_idx]
            if line.strip() and len(line) - len(line.lstrip()) <= indent_level and not line.strip().startswith('#'):
                break
            end_idx += 1
        
        end_line = end_idx
        content = '\n'.join(content_lines[start_idx:end_idx])
        
        return SemanticUnit(
            boundary_type=SemanticBoundary.CLASS_DEFINITION,
            start_line=start_line,
            end_line=end_line,
            start_byte=0, end_byte=0,
            content=content,
            semantic_weight=1.0,
            dependencies=self._extract_class_dependencies(content),
            scope_level=0,
            contains_nested=True
        )
    
    def _extract_heuristic_function(self, start_idx: int, content_lines: List[str]) -> Optional[SemanticUnit]:
        """Extract function using indentation heuristics."""
        start_line = start_idx + 1
        indent_level = len(content_lines[start_idx]) - len(content_lines[start_idx].lstrip())
        
        end_idx = start_idx + 1
        while end_idx < len(content_lines):
            line = content_lines[end_idx]
            if line.strip() and len(line) - len(line.lstrip()) <= indent_level and not line.strip().startswith('#'):
                break
            end_idx += 1
        
        end_line = end_idx
        content = '\n'.join(content_lines[start_idx:end_idx])
        
        return SemanticUnit(
            boundary_type=SemanticBoundary.FUNCTION_DEFINITION,
            start_line=start_line,
            end_line=end_line,
            start_byte=0, end_byte=0,
            content=content,
            semantic_weight=0.9,
            dependencies=self._extract_function_dependencies(content),
            scope_level=1 if indent_level > 0 else 0,
            contains_nested=False
        )
    
    def _extract_heuristic_imports(self, start_idx: int, content_lines: List[str]) -> Optional[SemanticUnit]:
        """Extract import block using heuristics."""
        start_line = start_idx + 1
        end_idx = start_idx
        
        # Group consecutive imports
        while end_idx < len(content_lines):
            line = content_lines[end_idx].strip()
            if line.startswith(('import ', 'from ')) or not line or line.startswith('#'):
                end_idx += 1
            else:
                break
        
        end_line = end_idx
        content = '\n'.join(content_lines[start_idx:end_idx])
        
        return SemanticUnit(
            boundary_type=SemanticBoundary.IMPORT_BLOCK,
            start_line=start_line,
            end_line=end_line,
            start_byte=0, end_byte=0,
            content=content,
            semantic_weight=0.6,
            dependencies=self._extract_import_dependencies(content),
            scope_level=0,
            contains_nested=False
        )
    
    def _ensure_complete_semantic_units(self, units: List[SemanticUnit], content_lines: List[str]) -> List[SemanticUnit]:
        """Ensure semantic units are complete and non-overlapping."""
        if not units:
            return units
        
        # Sort units by start line
        sorted_units = sorted(units, key=lambda u: u.start_line)
        
        # Remove overlaps and ensure completeness
        complete_units = []
        for unit in sorted_units:
            # Ensure the unit is complete (expand to logical boundaries)
            complete_unit = self._expand_to_logical_boundaries(unit, content_lines)
            
            # Check for overlap with previous units
            if complete_units:
                last_unit = complete_units[-1]
                if complete_unit.start_line <= last_unit.end_line:
                    # Merge overlapping units if they're compatible
                    if self._are_units_compatible_for_merge(last_unit, complete_unit):
                        complete_units[-1] = self._merge_semantic_units(last_unit, complete_unit)
                        continue
                    else:
                        # Adjust boundaries to prevent overlap
                        complete_unit = self._adjust_unit_boundaries(complete_unit, last_unit)
            
            complete_units.append(complete_unit)
        
        return complete_units
    
    def _expand_to_logical_boundaries(self, unit: SemanticUnit, content_lines: List[str]) -> SemanticUnit:
        """Expand a semantic unit to logical boundaries."""
        # Expand start to include decorators, comments
        expanded_start = self._find_logical_start(unit.start_line, content_lines)
        
        # Expand end to include trailing elements
        expanded_end = self._find_logical_end(unit.end_line, content_lines)
        
        # Update content
        expanded_content = '\n'.join(content_lines[expanded_start-1:expanded_end])
        
        return SemanticUnit(
            boundary_type=unit.boundary_type,
            start_line=expanded_start,
            end_line=expanded_end,
            start_byte=unit.start_byte,
            end_byte=unit.end_byte,
            content=expanded_content,
            semantic_weight=unit.semantic_weight,
            dependencies=unit.dependencies,
            scope_level=unit.scope_level,
            contains_nested=unit.contains_nested
        )
    
    def _find_logical_start(self, start_line: int, content_lines: List[str]) -> int:
        """Find the logical start of a semantic unit (include decorators, comments)."""
        logical_start = start_line
        
        # Look backwards for decorators, comments, and docstrings
        for i in range(start_line - 2, 0, -1):
            line = content_lines[i - 1].strip()
            if (line.startswith('@') or  # Decorators
                line.startswith('#') or  # Comments
                line.startswith('"""') or line.startswith("'''") or  # Docstrings
                not line):  # Empty lines
                logical_start = i
            else:
                break
        
        return logical_start
    
    def _find_logical_end(self, end_line: int, content_lines: List[str]) -> int:
        """Find the logical end of a semantic unit (include trailing comments)."""
        logical_end = end_line
        
        # Look forward for trailing comments and empty lines
        for i in range(end_line, min(len(content_lines), end_line + 3)):
            line = content_lines[i - 1].strip() if i <= len(content_lines) else ""
            if line.startswith('#') or not line:
                logical_end = i
            else:
                break
        
        return logical_end
    
    def _find_complete_control_end(self, node, initial_end: int, content_lines: List[str]) -> int:
        """Find the complete end of a control structure including else/elif/except blocks."""
        # For now, use the AST node's end point
        # In a more sophisticated implementation, we would traverse the AST
        # to find all related blocks (else, elif, except, finally)
        return initial_end
    
    def _are_units_compatible_for_merge(self, unit1: SemanticUnit, unit2: SemanticUnit) -> bool:
        """Check if two semantic units can be merged."""
        # Merge same types
        if unit1.boundary_type == unit2.boundary_type:
            return True
        
        # Merge imports
        if (unit1.boundary_type == SemanticBoundary.IMPORT_BLOCK and
            unit2.boundary_type == SemanticBoundary.IMPORT_BLOCK):
            return True
        
        # Don't merge different major types
        return False
    
    def _adjust_unit_boundaries(self, unit: SemanticUnit, previous_unit: SemanticUnit) -> SemanticUnit:
        """Adjust unit boundaries to prevent overlap."""
        if unit.start_line <= previous_unit.end_line:
            # Start the unit after the previous one ends
            adjusted_start = previous_unit.end_line + 1
            
            # Update content
            content_lines = unit.content.split('\n')
            lines_to_skip = adjusted_start - unit.start_line
            if lines_to_skip > 0 and lines_to_skip < len(content_lines):
                adjusted_content = '\n'.join(content_lines[lines_to_skip:])
            else:
                adjusted_content = unit.content
            
            return SemanticUnit(
                boundary_type=unit.boundary_type,
                start_line=adjusted_start,
                end_line=unit.end_line,
                start_byte=unit.start_byte,
                end_byte=unit.end_byte,
                content=adjusted_content,
                semantic_weight=unit.semantic_weight,
                dependencies=unit.dependencies,
                scope_level=unit.scope_level,
                contains_nested=unit.contains_nested
            )
        
        return unit
    
    def _extract_class_dependencies(self, content: str) -> List[str]:
        """Extract dependencies for a class (inheritance, imports used)."""
        dependencies = []
        
        # Extract inheritance
        import re
        inheritance_pattern = r'class\s+\w+\s*\(\s*([^)]+)\s*\):'
        matches = re.findall(inheritance_pattern, content)
        for match in matches:
            base_classes = [cls.strip() for cls in match.split(',')]
            dependencies.extend(base_classes)
        
        # Extract function calls and method calls
        call_pattern = r'(\w+)\s*\('
        calls = re.findall(call_pattern, content)
        dependencies.extend(calls)
        
        return list(set(dependencies))
    
    def _extract_function_dependencies(self, content: str) -> List[str]:
        """Extract dependencies for a function."""
        dependencies = []
        
        import re
        # Function calls
        call_pattern = r'(\w+)\s*\('
        calls = re.findall(call_pattern, content)
        dependencies.extend(calls)
        
        # Variable assignments and references
        var_pattern = r'(\w+)\s*='
        variables = re.findall(var_pattern, content)
        dependencies.extend(variables)
        
        return list(set(dependencies))
    
    def _extract_import_dependencies(self, content: str) -> List[str]:
        """Extract imported modules and functions."""
        dependencies = []
        
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('import '):
                module = line.replace('import ', '').split()[0]
                dependencies.append(module)
            elif line.startswith('from '):
                parts = line.split()
                if len(parts) >= 4 and parts[2] == 'import':
                    module = parts[1]
                    imports = ' '.join(parts[3:]).split(',')
                    dependencies.append(module)
                    dependencies.extend([imp.strip() for imp in imports])
        
        return list(set(dependencies))
    
    def _extract_control_dependencies(self, content: str) -> List[str]:
        """Extract dependencies for control structures."""
        dependencies = []
        
        import re
        # Function calls within control structure
        call_pattern = r'(\w+)\s*\('
        calls = re.findall(call_pattern, content)
        dependencies.extend(calls)
        
        # Variables used in conditions
        var_pattern = r'if\s+([^:]+):'
        conditions = re.findall(var_pattern, content)
        for condition in conditions:
            # Extract variable names from conditions
            vars_in_condition = re.findall(r'\b(\w+)\b', condition)
            dependencies.extend(vars_in_condition)
        
        return list(set(dependencies))
    
    def _is_security_sensitive_function(self, content: str) -> bool:
        """Check if a function is security-sensitive."""
        security_keywords = [
            'password', 'auth', 'login', 'token', 'secret', 'key', 'admin',
            'sql', 'query', 'execute', 'eval', 'exec', 'input', 'raw_input',
            'subprocess', 'os.system', 'shell', 'command', 'pickle', 'marshal'
        ]
        
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in security_keywords)
    
    def _calculate_function_scope_level(self, node) -> int:
        """Calculate the scope level of a function within classes."""
        level = 0
        current = node.parent if hasattr(node, 'parent') else None
        
        while current:
            if hasattr(current, 'type') and current.type in ['class_definition', 'function_definition']:
                level += 1
            current = current.parent if hasattr(current, 'parent') else None
        
        return level
    
    def _contains_methods_or_nested_classes(self, node) -> bool:
        """Check if a class contains methods or nested classes."""
        if not hasattr(node, 'children'):
            return False
        
        for child in node.children:
            if hasattr(child, 'type') and child.type in ['function_definition', 'method_definition', 'class_definition']:
                return True
        
        return False
    
    def _contains_nested_functions(self, node) -> bool:
        """Check if a function contains nested functions."""
        if not hasattr(node, 'children'):
            return False
        
        def check_children(n):
            if hasattr(n, 'type') and n.type in ['function_definition', 'method_definition']:
                return True
            if hasattr(n, 'children'):
                return any(check_children(child) for child in n.children)
            return False
        
        return any(check_children(child) for child in node.children)
    
    def _contains_nested_control(self, node) -> bool:
        """Check if a control structure contains nested control structures."""
        if not hasattr(node, 'children'):
            return False
        
        control_types = {'if_statement', 'for_statement', 'while_statement', 'try_statement'}
        
        def check_children(n):
            if hasattr(n, 'type') and n.type in control_types:
                return True
            if hasattr(n, 'children'):
                return any(check_children(child) for child in n.children)
            return False
        
        return any(check_children(child) for child in node.children)
    
    def _enrich_semantic_context(self, chunks: List[CodeChunk], 
                                semantic_units: List[SemanticUnit], content: str) -> List[CodeChunk]:
        """Enrich chunks with semantic context."""
        enriched = []
        
        for chunk in chunks:
            # Find related semantic units
            related_units = [u for u in semantic_units 
                           if self._is_unit_related_to_chunk(u, chunk)]
            
            if related_units:
                enriched_chunk = self._add_semantic_context(chunk, related_units, content)
                enriched.append(enriched_chunk)
                self.context_enrichments += 1
            else:
                enriched.append(chunk)
        
        return enriched
    
    def _is_unit_related_to_chunk(self, unit: SemanticUnit, chunk: CodeChunk) -> bool:
        """Check if a semantic unit is related to a chunk."""
        # Check overlap
        unit_range = set(range(unit.start_line, unit.end_line + 1))
        chunk_range = set(range(chunk.metadata.start_line, chunk.metadata.end_line + 1))
        
        return bool(unit_range & chunk_range)
    
    def _add_semantic_context(self, chunk: CodeChunk, related_units: List[SemanticUnit],
                             content: str) -> CodeChunk:
        """Add semantic context to a chunk."""
        # Enhance metadata with semantic information
        enhanced_chunk = chunk.model_copy()
        
        # Add semantic dependencies
        all_deps = []
        for unit in related_units:
            all_deps.extend(unit.dependencies)
        
        # Update metadata
        enhanced_chunk.metadata.function_calls = list(set(
            enhanced_chunk.metadata.function_calls + all_deps
        ))
        
        # Update complexity score based on semantic analysis
        semantic_complexity = sum(unit.semantic_weight for unit in related_units)
        enhanced_chunk.metadata.complexity_score = max(
            enhanced_chunk.metadata.complexity_score or 0,
            semantic_complexity / len(related_units)
        )
        
        return enhanced_chunk
    
    def _create_semantic_relationships(self, chunks: List[CodeChunk],
                                     semantic_units: List[SemanticUnit]) -> List[Any]:
        """Create semantic relationships between chunks."""
        relationships = []
        
        # Create dependency relationships
        for i, chunk1 in enumerate(chunks):
            for j, chunk2 in enumerate(chunks):
                if i != j:
                    if self._have_semantic_relationship(chunk1, chunk2, semantic_units):
                        relationships.append({
                            'type': 'semantic_dependency',
                            'source': chunk1.metadata.chunk_id,
                            'target': chunk2.metadata.chunk_id,
                            'strength': self._calculate_relationship_strength(chunk1, chunk2)
                        })
        
        return relationships
    
    def _have_semantic_relationship(self, chunk1: CodeChunk, chunk2: CodeChunk,
                                   semantic_units: List[SemanticUnit]) -> bool:
        """Check if two chunks have a semantic relationship."""
        # Check for shared dependencies
        deps1 = set(chunk1.metadata.function_calls + chunk1.metadata.imports)
        deps2 = set(chunk2.metadata.function_calls + chunk2.metadata.imports)
        
        return len(deps1 & deps2) > 0
    
    def _calculate_relationship_strength(self, chunk1: CodeChunk, chunk2: CodeChunk) -> float:
        """Calculate the strength of relationship between chunks."""
        deps1 = set(chunk1.metadata.function_calls + chunk1.metadata.imports)
        deps2 = set(chunk2.metadata.function_calls + chunk2.metadata.imports)
        
        if not deps1 or not deps2:
            return 0.0
        
        common_deps = len(deps1 & deps2)
        total_deps = len(deps1 | deps2)
        
        return common_deps / total_deps if total_deps > 0 else 0.0
    
    def get_strategy_metrics(self) -> Dict[str, Any]:
        """Get semantic strategy metrics."""
        base_metrics = super().get_strategy_metrics()
        
        semantic_metrics = {
            'semantic_units_found': self.semantic_units_found,
            'boundaries_analyzed': self.boundaries_analyzed,
            'chunks_merged': self.chunks_merged,
            'scope_preservations': self.scope_preservations,
            'context_enrichments': self.context_enrichments,
            'semantic_efficiency': self._chunks_created / max(self.semantic_units_found, 1),
            'boundary_types_used': list(self.boundary_weights.keys())
        }
        
        base_metrics.update(semantic_metrics)
        return base_metrics
    
    # New meaningful semantic chunking methods
    
    def _extract_import_blocks(self, root_node, content_lines: List[str], file_path: Path, 
                              context: ChunkingContext, processed_lines: set) -> List[CodeChunk]:
        """Extract import blocks as semantic units."""
        chunks = []
        import_ranges = []
        
        # Find all import statements and group them
        for node in root_node.children:
            if hasattr(node, 'type') and node.type in ['import_statement', 'import_from_statement']:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                import_ranges.append((start_line, end_line))
        
        if not import_ranges:
            return chunks
        
        # Group consecutive imports
        import_ranges.sort()
        grouped_imports = []
        current_group = [import_ranges[0]]
        
        for start, end in import_ranges[1:]:
            # If imports are close together (within 2 lines), group them
            if start <= current_group[-1][1] + 2:
                current_group.append((start, end))
            else:
                grouped_imports.append(current_group)
                current_group = [(start, end)]
        
        if current_group:
            grouped_imports.append(current_group)
        
        # Create chunks for each import group
        for group in grouped_imports:
            group_start = group[0][0]
            group_end = group[-1][1]
            
            # Include any comments or blank lines before/after imports
            expanded_start = max(1, group_start)
            expanded_end = min(len(content_lines), group_end)
            
            # Get content
            chunk_content = '\n'.join(content_lines[expanded_start-1:expanded_end])
            
            # Extract import names
            import_names = []
            for line_num in range(expanded_start, expanded_end + 1):
                if line_num <= len(content_lines):
                    line = content_lines[line_num - 1].strip()
                    if line.startswith(('import ', 'from ')):
                        import_names.append(line.split()[1] if line.startswith('import') else line.split()[1])
            
            # Create chunk
            chunk = self._create_chunk_from_lines(
                expanded_start, expanded_end, chunk_content, file_path,
                ChunkType.CONTEXT, NodeType.IMPORT_STMT, imports=import_names
            )
            
            if chunk:
                chunks.append(chunk)
                processed_lines.update(range(expanded_start, expanded_end + 1))
        
        return chunks
    
    def _extract_complete_classes(self, root_node, content_lines: List[str], file_path: Path,
                                 context: ChunkingContext, processed_lines: set) -> List[CodeChunk]:
        """Extract complete class definitions with all methods."""
        chunks = []
        
        for node in root_node.children:
            if hasattr(node, 'type') and node.type == 'class_definition':
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                
                # Skip if already processed
                if any(line in processed_lines for line in range(start_line, end_line + 1)):
                    continue
                
                # Extract class name
                class_name = self._extract_node_identifier(node)
                
                # Include decorators and docstrings before class
                expanded_start = self._find_logical_start(start_line, content_lines)
                expanded_end = self._find_logical_end(end_line, content_lines)
                
                # Get complete class content
                chunk_content = '\n'.join(content_lines[expanded_start-1:expanded_end])
                
                # Extract method names from the class
                method_names = self._extract_methods_from_class(node)
                
                # Create chunk
                chunk = self._create_chunk_from_lines(
                    expanded_start, expanded_end, chunk_content, file_path,
                    ChunkType.CLASS, NodeType.CLASS_DEF, 
                    class_names=[class_name] if class_name else [],
                    function_names=method_names
                )
                
                if chunk:
                    chunks.append(chunk)
                    processed_lines.update(range(expanded_start, expanded_end + 1))
        
        return chunks
    
    def _extract_standalone_functions(self, root_node, content_lines: List[str], file_path: Path,
                                    context: ChunkingContext, processed_lines: set) -> List[CodeChunk]:
        """Extract standalone functions (not methods inside classes)."""
        chunks = []
        
        for node in root_node.children:
            if hasattr(node, 'type') and node.type in ['function_definition', 'async_function_definition']:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                
                # Skip if already processed (e.g., method inside a class)
                if any(line in processed_lines for line in range(start_line, end_line + 1)):
                    continue
                
                # Extract function name
                function_name = self._extract_node_identifier(node)
                
                # Include decorators and docstrings
                expanded_start = self._find_logical_start(start_line, content_lines)
                expanded_end = self._find_logical_end(end_line, content_lines)
                
                # Get complete function content
                chunk_content = '\n'.join(content_lines[expanded_start-1:expanded_end])
                
                # Create chunk
                chunk = self._create_chunk_from_lines(
                    expanded_start, expanded_end, chunk_content, file_path,
                    ChunkType.FUNCTION, NodeType.FUNCTION_DEF,
                    function_names=[function_name] if function_name else []
                )
                
                if chunk:
                    chunks.append(chunk)
                    processed_lines.update(range(expanded_start, expanded_end + 1))
        
        return chunks
    
    def _extract_global_variables(self, root_node, content_lines: List[str], file_path: Path,
                                 context: ChunkingContext, processed_lines: set) -> List[CodeChunk]:
        """Extract global variable assignments and constants."""
        chunks = []
        global_assignments = []
        
        # Find assignment statements at module level
        for node in root_node.children:
            if hasattr(node, 'type') and node.type in ['assignment', 'expression_statement']:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                
                # Skip if already processed
                if any(line in processed_lines for line in range(start_line, end_line + 1)):
                    continue
                
                # Check if this looks like a global variable/constant
                line_content = content_lines[start_line - 1].strip()
                if '=' in line_content and not line_content.startswith((' ', '\t')):
                    global_assignments.append((start_line, end_line, line_content))
        
        # Group nearby global assignments
        if global_assignments:
            global_assignments.sort()
            grouped_globals = []
            current_group = [global_assignments[0]]
            
            for start, end, content in global_assignments[1:]:
                # Group if within 3 lines of each other
                if start <= current_group[-1][1] + 3:
                    current_group.append((start, end, content))
                else:
                    grouped_globals.append(current_group)
                    current_group = [(start, end, content)]
            
            if current_group:
                grouped_globals.append(current_group)
            
            # Create chunks for global variable groups
            for group in grouped_globals:
                group_start = group[0][0]
                group_end = group[-1][1]
                
                # Include comments before globals
                expanded_start = self._find_logical_start(group_start, content_lines)
                
                chunk_content = '\n'.join(content_lines[expanded_start-1:group_end])
                
                # Create chunk
                chunk = self._create_chunk_from_lines(
                    expanded_start, group_end, chunk_content, file_path,
                    ChunkType.CONTEXT, NodeType.BLOCK
                )
                
                if chunk:
                    chunks.append(chunk)
                    processed_lines.update(range(expanded_start, group_end + 1))
        
        return chunks
    
    def _extract_remaining_blocks(self, content_lines: List[str], file_path: Path,
                                 context: ChunkingContext, processed_lines: set) -> List[CodeChunk]:
        """Extract any remaining unprocessed code blocks."""
        chunks = []
        unprocessed_ranges = []
        
        # Find unprocessed line ranges
        current_start = None
        for i in range(1, len(content_lines) + 1):
            if i not in processed_lines:
                line = content_lines[i - 1].strip()
                # Skip empty lines and comments only
                if line and not line.startswith('#'):
                    if current_start is None:
                        current_start = i
            else:
                if current_start is not None:
                    unprocessed_ranges.append((current_start, i - 1))
                    current_start = None
        
        # Handle last range
        if current_start is not None:
            unprocessed_ranges.append((current_start, len(content_lines)))
        
        # Create chunks for remaining blocks
        for start, end in unprocessed_ranges:
            if end - start >= 2:  # Only create chunks for meaningful blocks
                chunk_content = '\n'.join(content_lines[start-1:end])
                
                chunk = self._create_chunk_from_lines(
                    start, end, chunk_content, file_path,
                    ChunkType.BLOCK, NodeType.BLOCK
                )
                
                if chunk:
                    chunks.append(chunk)
        
        return chunks
    
    def _create_heuristic_semantic_chunks(self, content_lines: List[str], file_path: Path,
                                        context: ChunkingContext) -> List[CodeChunk]:
        """Fallback heuristic chunking when AST parsing fails."""
        chunks = []
        current_chunk_start = 1
        current_chunk_lines = []
        
        for i, line in enumerate(content_lines, 1):
            stripped = line.strip()
            
            # Start new chunk on class/function definitions
            if (stripped.startswith(('class ', 'def ', 'async def ')) and 
                current_chunk_lines and len(current_chunk_lines) > 3):
                
                # Finish current chunk
                chunk_content = '\n'.join(current_chunk_lines)
                chunk = self._create_chunk_from_lines(
                    current_chunk_start, i - 1, chunk_content, file_path,
                    ChunkType.BLOCK, NodeType.BLOCK
                )
                if chunk:
                    chunks.append(chunk)
                
                # Start new chunk
                current_chunk_start = i
                current_chunk_lines = [line]
            else:
                current_chunk_lines.append(line)
        
        # Handle last chunk
        if current_chunk_lines:
            chunk_content = '\n'.join(current_chunk_lines)
            chunk = self._create_chunk_from_lines(
                current_chunk_start, len(content_lines), chunk_content, file_path,
                ChunkType.BLOCK, NodeType.BLOCK
            )
            if chunk:
                chunks.append(chunk)
        
        return chunks
    
    def _create_chunk_from_lines(self, start_line: int, end_line: int, content: str,
                               file_path: Path, chunk_type: ChunkType, node_type: NodeType,
                               class_names: Optional[List[str]] = None, function_names: Optional[List[str]] = None,
                               imports: Optional[List[str]] = None) -> Optional[CodeChunk]:
        """Helper to create a chunk from line range."""
        try:
            token_count = self.token_counter.count_tokens(content)
            
            # Skip tiny chunks
            if token_count < 5:
                return None
            
            metadata = ChunkMetadata(
                parent_file=file_path,
                language=self._get_language_from_extension(file_path),
                start_line=start_line,
                end_line=end_line,
                token_count=token_count,
                character_count=len(content),
                line_count=end_line - start_line + 1,
                primary_node_type=node_type,
                node_types=[node_type],
                class_names=class_names or [],
                function_names=function_names or [],
                imports=imports or [],
                function_calls=[],
                variable_references=[],
                complexity_score=1.0
            )
            
            return CodeChunk(
                content=content,
                metadata=metadata,
                chunk_type=chunk_type,
                focus_score=0.8,
                priority_weight=1.0
            )
            
        except Exception as e:
            logger.warning(f"Failed to create chunk: {e}")
            return None
    
    def _extract_node_identifier(self, node) -> Optional[str]:
        """Extract identifier name from AST node."""
        try:
            if hasattr(node, 'child_by_field_name'):
                name_node = node.child_by_field_name('name')
                if name_node and hasattr(name_node, 'text'):
                    return name_node.text.decode('utf-8')
            return None
        except:
            return None
    
    def _extract_methods_from_class(self, class_node) -> List[str]:
        """Extract method names from a class node."""
        methods = []
        try:
            if hasattr(class_node, 'children'):
                for child in class_node.children:
                    if hasattr(child, 'type') and child.type in ['function_definition', 'async_function_definition']:
                        method_name = self._extract_node_identifier(child)
                        if method_name:
                            methods.append(method_name)
        except:
            pass
        return methods
        
        return {**base_metrics, **semantic_metrics}
    
    def reset_metrics(self) -> None:
        """Reset all metrics."""
        super().reset_metrics()
        self.semantic_units_found = 0
        self.boundaries_analyzed = 0
        self.chunks_merged = 0
        self.scope_preservations = 0
        self.context_enrichments = 0
    
    def _walk_tree(self, node):
        """Recursively walk AST tree yielding all nodes."""
        yield node
        if hasattr(node, 'children'):
            for child in node.children:
                yield from self._walk_tree(child)
