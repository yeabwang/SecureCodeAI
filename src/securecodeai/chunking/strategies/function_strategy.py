"""Function-based chunking strategy for production code analysis.
This lacks some of the implmentations and will get back to it later
"""

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


class FunctionComplexity(str, Enum):
    """Function complexity levels."""
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    VERY_COMPLEX = "very_complex"


@dataclass
class FunctionInfo:
    """Information about a detected function."""
    name: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    parameters: List[str]
    return_type: Optional[str]
    complexity: FunctionComplexity
    is_async: bool
    is_static: bool
    is_private: bool
    docstring: Optional[str]
    calls_made: List[str]
    variables_used: List[str]
    nested_functions: List[str]


class FunctionBasedStrategy(ChunkingStrategy):
    """
    function-based chunking strategy.
    
    This strategy:
    1. Identifies function boundaries using AST analysis
    2. Creates chunks at function granularity
    3. Handles nested functions and complex control flow
    4. Maintains function context and dependencies
    5. Provides function-level metrics and analysis
    """
    
    def __init__(self, config: ChunkingConfig, token_counter: TokenCounter, 
                 parser: Optional[BaseParser] = None):
        super().__init__(config, token_counter, parser)
        self.strategy_name = "function_based"
        
        # Function detection configuration
        self.min_function_lines = 3
        self.max_function_tokens = config.tokens.max_tokens_per_chunk
        self.include_docstrings = True
        self.include_decorators = True
        self.preserve_function_context = True
        
        # Complexity thresholds
        self.complexity_thresholds = {
            FunctionComplexity.SIMPLE: 5,
            FunctionComplexity.MODERATE: 15,
            FunctionComplexity.COMPLEX: 30,
            FunctionComplexity.VERY_COMPLEX: float('inf')
        }
        
        # Performance metrics
        self.functions_detected = 0
        self.functions_chunked = 0
        self.nested_functions_handled = 0
        self.complex_functions = 0
        self.context_additions = 0
        
        logger.debug(f"FunctionBasedStrategy initialized with max_tokens={self.max_function_tokens}")
    
    def can_handle(self, file_path: Path, content: str, 
                  context: ChunkingContext) -> bool:
        """Check if this strategy can handle the given content."""
        if not self.parser:
            return False
        
        # Check if file extension is supported
        supported_extensions = {'.py', '.js', '.ts', '.java', '.go', '.cpp', '.c', '.cs'}
        if file_path.suffix.lower() not in supported_extensions:
            return False
        
        # Quick check for function-like patterns
        function_indicators = ['def ', 'function ', 'func ', 'public ', 'private ', 'static ']
        content_lower = content.lower()
        
        return any(indicator in content_lower for indicator in function_indicators)
    
    def get_priority(self, file_path: Path, content: str,
                    context: ChunkingContext) -> float:
        """Get priority score for this strategy."""
        if not self.can_handle(file_path, content, context):
            return 0.0
        
        # Count potential functions
        function_count = self._estimate_function_count(content)
        
        if function_count == 0:
            return 0.1  # Very low priority
        
        # High priority for files with many well-defined functions
        if function_count >= 5:
            return 0.85
        elif function_count >= 3:
            return 0.75
        elif function_count >= 1:
            return 0.65
        
        return 0.4
    
    def chunk_content(self, content: str, file_path: Path, 
                     context: ChunkingContext) -> ChunkingResult:
        """Chunk content based on function boundaries."""
        start_time = time.time()
        
        try:
            if not self.parser:
                raise ChunkingError("No parser available for function-based chunking")
            
            # Parse the content
            parse_result = self._parse_content(content, file_path)
            
            # Extract function information
            functions = self._extract_functions(parse_result, content)
            self.functions_detected = len(functions)
            
            # Create chunks for functions
            chunks = self._create_function_chunks(functions, content, file_path, context)
            
            # Add context chunks if needed
            chunks = self._add_context_chunks(chunks, content, file_path, functions)
            
            # Create result
            result = ChunkingResult(
                source_file=file_path,
                strategy_used=self.strategy_name
            )
            
            for chunk in chunks:
                result.add_chunk(chunk)
            
            # Add function relationships
            result.chunk_relationships = self._create_function_relationships(functions, chunks)
            
            result.processing_time_ms = (time.time() - start_time) * 1000
            self._chunks_created += len(result.chunks)
            
            logger.debug(f"Function-based strategy created {len(result.chunks)} chunks "
                        f"from {len(functions)} functions")
            
            return result
            
        except Exception as e:
            logger.error(f"Function-based chunking failed: {e}")
            self._errors.append(str(e))
            raise ChunkingError(f"Function-based chunking failed: {e}")
    
    def _estimate_function_count(self, content: str) -> int:
        """Estimate the number of functions in the content."""
        lines = content.split('\n')
        count = 0
        
        for line in lines:
            stripped = line.strip()
            if (stripped.startswith('def ') or 
                stripped.startswith('function ') or
                'function ' in stripped or
                stripped.startswith('func ')):
                count += 1
        
        return count
    
    def _parse_content(self, content: str, file_path: Path) -> ParseResult:
        """Parse content using the configured parser."""
        try:
            if not self.parser:
                raise ParsingError(f"No parser available for file {file_path}")
            return self.parser.parse(content, file_path)
        except Exception as e:
            raise ParsingError(f"Failed to parse {file_path}: {e}")
    
    def _extract_functions(self, parse_result: ParseResult, content: str) -> List[FunctionInfo]:
        """Extract function information from parse result."""
        functions = []
        content_lines = content.split('\n')
        
        # Walk the AST to find function definitions
        if parse_result.ast and hasattr(parse_result.ast, 'root_node'):
            for node in self._walk_tree(parse_result.ast.root_node):
                if self._is_function_node(node):
                    func_info = self._create_function_info(node, content_lines, content)
                    if func_info:
                        functions.append(func_info)
        
        return sorted(functions, key=lambda f: f.start_line)
    
    def _is_function_node(self, node) -> bool:
        """Check if a node represents a function definition."""
        if not hasattr(node, 'type'):
            return False
        
        function_types = {
            'function_definition',
            'function_declaration', 
            'method_definition',
            'function_expression',
            'arrow_function',
            'lambda'
        }
        
        return node.type in function_types
    
    def _create_function_info(self, node, content_lines: List[str], full_content: str) -> Optional[FunctionInfo]:
        """Create function information from AST node."""
        try:
            # Extract basic position information
            start_line = node.start_point[0] + 1  # Convert to 1-based
            end_line = node.end_point[0] + 1
            start_byte = node.start_byte
            end_byte = node.end_byte
            
            # Extract function name
            name = self._extract_function_name(node)
            if not name:
                return None
            
            # Extract function content
            func_content = full_content[start_byte:end_byte]
            
            # Analyze function complexity
            complexity = self._calculate_complexity(func_content)
            
            # Extract function details
            parameters = self._extract_parameters(node)
            return_type = self._extract_return_type(node)
            is_async = self._is_async_function(node)
            is_static = self._is_static_function(node)
            is_private = self._is_private_function(name)
            docstring = self._extract_docstring(func_content)
            calls_made = self._extract_function_calls(func_content)
            variables_used = self._extract_variables(func_content)
            nested_functions = self._extract_nested_functions(func_content)
            
            return FunctionInfo(
                name=name,
                start_line=start_line,
                end_line=end_line,
                start_byte=start_byte,
                end_byte=end_byte,
                parameters=parameters,
                return_type=return_type,
                complexity=complexity,
                is_async=is_async,
                is_static=is_static,
                is_private=is_private,
                docstring=docstring,
                calls_made=calls_made,
                variables_used=variables_used,
                nested_functions=nested_functions
            )
            
        except Exception as e:
            logger.warning(f"Failed to extract function info: {e}")
            return None
    
    def _extract_function_name(self, node) -> Optional[str]:
        """Extract function name from AST node."""
        # This is language-specific and would need proper implementation
        # For now, return a placeholder
        if hasattr(node, 'child_by_field_name'):
            name_node = node.child_by_field_name('name')
            if name_node:
                return name_node.text.decode('utf-8')
        
        return "unknown_function"
    
    def _calculate_complexity(self, func_content: str) -> FunctionComplexity:
        """Calculate function complexity based on content."""
        # Simplified complexity calculation
        lines = func_content.split('\n')
        line_count = len([line for line in lines if line.strip()])
        
        # Count complexity indicators
        complexity_indicators = ['if ', 'for ', 'while ', 'try ', 'except ', 'elif ']
        complexity_score = sum(func_content.count(indicator) for indicator in complexity_indicators)
        
        # Combine line count and complexity score
        total_score = line_count + complexity_score * 2
        
        if total_score <= self.complexity_thresholds[FunctionComplexity.SIMPLE]:
            return FunctionComplexity.SIMPLE
        elif total_score <= self.complexity_thresholds[FunctionComplexity.MODERATE]:
            return FunctionComplexity.MODERATE
        elif total_score <= self.complexity_thresholds[FunctionComplexity.COMPLEX]:
            return FunctionComplexity.COMPLEX
        else:
            return FunctionComplexity.VERY_COMPLEX
    
    def _extract_parameters(self, node) -> List[str]:
        """Extract function parameters."""
        # Simplified implementation
        return []
    
    def _extract_return_type(self, node) -> Optional[str]:
        """Extract function return type."""
        # Simplified implementation
        return None
    
    def _is_async_function(self, node) -> bool:
        """Check if function is async."""
        # Simplified implementation
        return False
    
    def _is_static_function(self, node) -> bool:
        """Check if function is static."""
        # Simplified implementation
        return False
    
    def _is_private_function(self, name: str) -> bool:
        """Check if function is private based on naming convention."""
        return name.startswith('_') or name.startswith('__')
    
    def _extract_docstring(self, func_content: str) -> Optional[str]:
        """Extract function docstring."""
        lines = func_content.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                # Find end of docstring
                quote_type = '"""' if '"""' in stripped else "'''"
                docstring_lines = [stripped]
                
                if stripped.count(quote_type) >= 2:  # Single line docstring
                    return stripped.strip(quote_type).strip()
                
                # Multi-line docstring
                for j in range(i + 1, len(lines)):
                    docstring_lines.append(lines[j])
                    if quote_type in lines[j]:
                        break
                
                return '\n'.join(docstring_lines).strip(quote_type).strip()
        
        return None
    
    def _extract_function_calls(self, func_content: str) -> List[str]:
        """Extract function calls made within the function."""
        # Simplified implementation - would use AST in production
        calls = []
        lines = func_content.split('\n')
        
        for line in lines:
            # Simple pattern matching for function calls
            import re
            pattern = r'(\w+)\s*\('
            matches = re.findall(pattern, line)
            calls.extend(matches)
        
        return list(set(calls))  # Remove duplicates
    
    def _extract_variables(self, func_content: str) -> List[str]:
        """Extract variable references."""
        # Simplified implementation
        variables = []
        lines = func_content.split('\n')
        
        for line in lines:
            # Simple pattern for variable assignments
            if '=' in line and not line.strip().startswith('#'):
                parts = line.split('=')
                if len(parts) >= 2:
                    var_name = parts[0].strip().split()[-1]
                    if var_name.isidentifier():
                        variables.append(var_name)
        
        return list(set(variables))
    
    def _extract_nested_functions(self, func_content: str) -> List[str]:
        """Extract nested function names."""
        nested = []
        lines = func_content.split('\n')
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('def ') and line != func_content.split('\n')[0]:
                # Extract function name
                parts = stripped.split('(')
                if len(parts) > 0:
                    func_name = parts[0].replace('def ', '').strip()
                    nested.append(func_name)
        
        return nested
    
    def _create_function_chunks(self, functions: List[FunctionInfo], content: str,
                               file_path: Path, context: ChunkingContext) -> List[CodeChunk]:
        """Create chunks for detected functions."""
        chunks = []
        content_lines = content.split('\n')
        
        for func in functions:
            chunk = self._create_single_function_chunk(func, content, content_lines, file_path, context)
            if chunk:
                chunks.append(chunk)
                self.functions_chunked += 1
                
                if func.complexity in [FunctionComplexity.COMPLEX, FunctionComplexity.VERY_COMPLEX]:
                    self.complex_functions += 1
                
                if func.nested_functions:
                    self.nested_functions_handled += len(func.nested_functions)
        
        return chunks
    
    def _create_single_function_chunk(self, func: FunctionInfo, full_content: str,
                                     content_lines: List[str], file_path: Path, 
                                     context: ChunkingContext) -> Optional[CodeChunk]:
        """Create a chunk for a single function."""
        try:
            # Extract function content with optional context
            start_line = func.start_line
            end_line = func.end_line
            
            # Include decorators if present
            if self.include_decorators:
                start_line = self._find_decorator_start(content_lines, func.start_line)
            
            # Extract content
            chunk_content = '\n'.join(content_lines[start_line-1:end_line])
            
            # Check token limit
            token_count = self.token_counter.count_tokens(chunk_content)
            if token_count > self.max_function_tokens:
                # Try to truncate or split complex function
                chunk_content = self._handle_large_function(func, chunk_content, token_count)
                token_count = self.token_counter.count_tokens(chunk_content)
            
            # Create metadata
            metadata = ChunkMetadata(
                parent_file=file_path,
                language=self._get_language_from_extension(file_path),
                start_line=start_line,
                end_line=end_line,
                start_byte=func.start_byte,
                end_byte=func.end_byte,
                token_count=token_count,
                character_count=len(chunk_content),
                line_count=end_line - start_line + 1,
                primary_node_type=NodeType.FUNCTION_DEF,
                node_types=[NodeType.FUNCTION_DEF],
                function_names=[func.name],
                class_names=[],
                imports=[],
                function_calls=func.calls_made,
                variable_references=func.variables_used,
                complexity_score=self._complexity_to_score(func.complexity)
            )
            
            # Create chunk
            chunk = CodeChunk(
                content=chunk_content,
                metadata=metadata,
                chunk_type=ChunkType.FUNCTION,
                priority_weight=self._calculate_function_priority(func),
                focus_score=self._calculate_function_focus_score(func, context)
            )
            
            return chunk
            
        except Exception as e:
            logger.warning(f"Failed to create chunk for function {func.name}: {e}")
            return None
    
    def _find_decorator_start(self, content_lines: List[str], func_start_line: int) -> int:
        """Find the start line including decorators."""
        start_line = func_start_line
        
        # Look backwards for decorators
        for i in range(func_start_line - 2, -1, -1):  # -2 because lines are 1-indexed
            line = content_lines[i].strip()
            if line.startswith('@'):
                start_line = i + 1  # Convert back to 1-indexed
            elif line and not line.startswith('#'):
                break  # Stop at first non-decorator, non-comment line
        
        return start_line
    
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
    
    def _complexity_to_score(self, complexity: FunctionComplexity) -> float:
        """Convert complexity enum to numeric score."""
        complexity_scores = {
            FunctionComplexity.SIMPLE: 0.2,
            FunctionComplexity.MODERATE: 0.4,
            FunctionComplexity.COMPLEX: 0.7,
            FunctionComplexity.VERY_COMPLEX: 1.0
        }
        
        return complexity_scores.get(complexity, 0.5)
    
    def _calculate_function_priority(self, func: FunctionInfo) -> float:
        """Calculate priority weight for a function."""
        base_priority = 0.5
        
        # Boost for public functions
        if not func.is_private:
            base_priority += 0.2
        
        # Boost for complex functions
        if func.complexity in [FunctionComplexity.COMPLEX, FunctionComplexity.VERY_COMPLEX]:
            base_priority += 0.2
        
        # Boost for functions with many dependencies
        if len(func.calls_made) > 5:
            base_priority += 0.1
        
        return min(base_priority, 1.0)
    
    def _calculate_function_focus_score(self, func: FunctionInfo, context: ChunkingContext) -> float:
        """Calculate focus score based on function characteristics."""
        focus_score = 0.0
        
        # Check if function is mentioned in existing findings
        if context.existing_findings:
            for finding in context.existing_findings:
                if func.name in finding.description or func.name in str(finding.location):
                    focus_score = max(focus_score, 0.8)
        
        # Security-related function names get higher focus
        security_keywords = ['auth', 'login', 'password', 'token', 'encrypt', 'decrypt', 'validate']
        if any(keyword in func.name.lower() for keyword in security_keywords):
            focus_score = max(focus_score, 0.6)
        
        # Complex functions get moderate focus
        if func.complexity in [FunctionComplexity.COMPLEX, FunctionComplexity.VERY_COMPLEX]:
            focus_score = max(focus_score, 0.4)
        
        return focus_score
    
    def _handle_large_function(self, func: FunctionInfo, content: str, token_count: int) -> str:
        """Handle functions that exceed token limits."""
        if token_count <= self.max_function_tokens:
            return content
        
        # Try to keep function signature and first part
        lines = content.split('\n')
        
        # Always keep function definition line
        result_lines = [lines[0]]
        current_tokens = self.token_counter.count_tokens(lines[0])
        
        # Add lines until we hit the limit
        for line in lines[1:]:
            line_tokens = self.token_counter.count_tokens(line)
            if current_tokens + line_tokens > self.max_function_tokens * 0.9:  # Leave some buffer
                result_lines.append("    # ... function content truncated ...")
                break
            
            result_lines.append(line)
            current_tokens += line_tokens
        
        return '\n'.join(result_lines)
    
    def _add_context_chunks(self, function_chunks: List[CodeChunk], content: str,
                           file_path: Path, functions: List[FunctionInfo]) -> List[CodeChunk]:
        """Add context chunks for imports, globals, etc."""
        if not self.preserve_function_context:
            return function_chunks
        
        context_chunks = []
        content_lines = content.split('\n')
        
        # Create context chunk for file header (imports, globals, etc.)
        header_content = self._extract_file_header(content_lines, functions)
        if header_content:
            header_chunk = self._create_header_chunk(header_content, file_path)
            if header_chunk:
                context_chunks.append(header_chunk)
                self.context_additions += 1
        
        # Combine context and function chunks
        all_chunks = context_chunks + function_chunks
        
        return all_chunks
    
    def _extract_file_header(self, content_lines: List[str], functions: List[FunctionInfo]) -> str:
        """Extract file header content (imports, globals, etc.)."""
        if not functions:
            return ""
        
        # Find first function
        first_func_line = min(func.start_line for func in functions)
        
        # Extract everything before first function
        header_lines = []
        for i, line in enumerate(content_lines[:first_func_line - 1]):
            # Skip empty lines at the end
            if line.strip() or any(content_lines[j].strip() for j in range(i + 1, first_func_line - 1)):
                header_lines.append(line)
        
        return '\n'.join(header_lines).strip()
    
    def _create_header_chunk(self, header_content: str, file_path: Path) -> Optional[CodeChunk]:
        """Create a context chunk for file header."""
        if not header_content.strip():
            return None
        
        token_count = self.token_counter.count_tokens(header_content)
        
        metadata = ChunkMetadata(
            parent_file=file_path,
            language=self._get_language_from_extension(file_path),
            start_line=1,
            end_line=len(header_content.split('\n')),
            start_byte=0,
            end_byte=len(header_content.encode('utf-8')),
            token_count=token_count,
            character_count=len(header_content),
            line_count=len(header_content.split('\n')),
            primary_node_type=NodeType.IMPORT_STMT,
            node_types=[NodeType.IMPORT_STMT],
            function_names=[],
            class_names=[],
            imports=self._extract_imports_from_header(header_content),
            function_calls=[],
            variable_references=[]
        )
        
        return CodeChunk(
            content=header_content,
            metadata=metadata,
            chunk_type=ChunkType.CONTEXT,
            priority_weight=0.3,  # Lower priority for context
            focus_score=0.1
        )
    
    def _extract_imports_from_header(self, header_content: str) -> List[str]:
        """Extract import statements from header."""
        imports = []
        lines = header_content.split('\n')
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('import ') or stripped.startswith('from '):
                imports.append(stripped)
        
        return imports
    
    def _create_function_relationships(self, functions: List[FunctionInfo], 
                                     chunks: List[CodeChunk]) -> List[Any]:
        """Create relationships between function chunks."""
        relationships = []
        
        # Create function call relationships
        for func in functions:
            for called_func in func.calls_made:
                # Find chunks for both functions
                caller_chunk = next((c for c in chunks if func.name in c.metadata.function_names), None)
                callee_chunk = next((c for c in chunks if called_func in c.metadata.function_names), None)
                
                if caller_chunk and callee_chunk:
                    # Create relationship (this would be a proper relationship object in production)
                    relationships.append({
                        'type': 'function_call',
                        'source': caller_chunk.metadata.chunk_id,
                        'target': callee_chunk.metadata.chunk_id,
                        'function_name': called_func
                    })
        
        return relationships
    
    def get_strategy_metrics(self) -> Dict[str, Any]:
        """Get function-based strategy metrics."""
        base_metrics = super().get_strategy_metrics()
        
        function_metrics = {
            'functions_detected': self.functions_detected,
            'functions_chunked': self.functions_chunked,
            'nested_functions_handled': self.nested_functions_handled,
            'complex_functions': self.complex_functions,
            'context_additions': self.context_additions,
            'chunking_efficiency': self.functions_chunked / max(self.functions_detected, 1),
            'complexity_distribution': self._get_complexity_distribution()
        }
        
        return {**base_metrics, **function_metrics}
    
    def _get_complexity_distribution(self) -> Dict[str, int]:
        """Get distribution of function complexities processed."""
        # This would track complexity distribution in a real implementation
        return {
            'simple': 0,
            'moderate': 0,
            'complex': 0,
            'very_complex': 0
        }
    
    def reset_metrics(self) -> None:
        """Reset all metrics."""
        super().reset_metrics()
        self.functions_detected = 0
        self.functions_chunked = 0
        self.nested_functions_handled = 0
    
    def _walk_tree(self, node):
        """Recursively walk AST tree yielding all nodes."""
        yield node
        if hasattr(node, 'children'):
            for child in node.children:
                yield from self._walk_tree(child)
        self.complex_functions = 0
        self.context_additions = 0
