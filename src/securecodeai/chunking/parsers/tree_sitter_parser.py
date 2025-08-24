"""Tree-sitter based parser for intelligent code chunking."""

import time
import logging
from typing import List, Dict, Optional, Any, Set, Tuple
from pathlib import Path

import tree_sitter
from tree_sitter import Language, Parser

from .base import BaseParser, ParseResult, ParserCapability
from ..models import NodeType
from ..exceptions import ParsingError, LanguageNotSupportedError


logger = logging.getLogger(__name__)


class TreeSitterParser(BaseParser):
    """Production-grade parser using tree-sitter."""
    
    # Language to tree-sitter binding mapping
    LANGUAGE_BINDINGS = {
        'python': 'tree_sitter_python',
        'javascript': 'tree_sitter_javascript', 
        'typescript': 'tree_sitter_typescript',
        'go': 'tree_sitter_go',
        'java': 'tree_sitter_java'
    }
    
    # File extensions mapping
    EXTENSION_MAP = {
        'python': ['.py', '.pyw'],
        'javascript': ['.js', '.jsx', '.mjs'],
        'typescript': ['.ts', '.tsx'],
        'go': ['.go'],
        'java': ['.java']
    }
    
    # Node type mappings
    NODE_TYPE_MAP = {
        'python': {
            'function_definition': NodeType.FUNCTION_DEF,
            'async_function_definition': NodeType.FUNCTION_DEF,
            'class_definition': NodeType.CLASS_DEF,
            'import_statement': NodeType.IMPORT_STMT,
            'import_from_statement': NodeType.IMPORT_STMT,
            'if_statement': NodeType.IF_STMT,
            'for_statement': NodeType.FOR_STMT,
            'while_statement': NodeType.WHILE_STMT,
            'try_statement': NodeType.TRY_STMT,
            'with_statement': NodeType.BLOCK
        },
        'javascript': {
            'function_declaration': NodeType.FUNCTION_DEF,
            'function_expression': NodeType.FUNCTION_DEF,
            'arrow_function': NodeType.FUNCTION_DEF,
            'method_definition': NodeType.METHOD_DEF,
            'class_declaration': NodeType.CLASS_DEF,
            'import_statement': NodeType.IMPORT_STMT,
            'if_statement': NodeType.IF_STMT,
            'for_statement': NodeType.FOR_STMT,
            'while_statement': NodeType.WHILE_STMT,
            'try_statement': NodeType.TRY_STMT
        },
        'typescript': {
            'function_declaration': NodeType.FUNCTION_DEF,
            'function_expression': NodeType.FUNCTION_DEF,
            'arrow_function': NodeType.FUNCTION_DEF,
            'method_definition': NodeType.METHOD_DEF,
            'class_declaration': NodeType.CLASS_DEF,
            'interface_declaration': NodeType.CLASS_DEF,
            'import_statement': NodeType.IMPORT_STMT,
            'if_statement': NodeType.IF_STMT,
            'for_statement': NodeType.FOR_STMT,
            'while_statement': NodeType.WHILE_STMT,
            'try_statement': NodeType.TRY_STMT
        },
        'go': {
            'function_declaration': NodeType.FUNCTION_DEF,
            'method_declaration': NodeType.METHOD_DEF,
            'type_declaration': NodeType.CLASS_DEF,
            'import_declaration': NodeType.IMPORT_STMT,
            'if_statement': NodeType.IF_STMT,
            'for_statement': NodeType.FOR_STMT,
            'range_clause': NodeType.FOR_STMT
        },
        'java': {
            'method_declaration': NodeType.METHOD_DEF,
            'constructor_declaration': NodeType.METHOD_DEF,
            'class_declaration': NodeType.CLASS_DEF,
            'interface_declaration': NodeType.CLASS_DEF,
            'import_declaration': NodeType.IMPORT_STMT,
            'if_statement': NodeType.IF_STMT,
            'for_statement': NodeType.FOR_STMT,
            'while_statement': NodeType.WHILE_STMT,
            'try_statement': NodeType.TRY_STMT
        }
    }
    
    def __init__(self, language: str):
        super().__init__(language)
        
        if language not in self.LANGUAGE_BINDINGS:
            raise LanguageNotSupportedError(language)
        
        # Set capabilities
        self.capabilities = {
            ParserCapability.SYNTAX_TREE,
            ParserCapability.SEMANTIC_ANALYSIS,
            ParserCapability.ERROR_RECOVERY,
            ParserCapability.DEPENDENCY_ANALYSIS
        }
        
        # Initialize tree-sitter
        self._initialize_parser()
    
    def _initialize_parser(self) -> None:
        """Initialize tree-sitter parser for the language."""
        try:
            binding_name = self.LANGUAGE_BINDINGS[self.language]
            
            # Import the language binding
            import importlib
            binding_module = importlib.import_module(binding_name)
            
            # Get the language - try different ways to access the language
            ts_language = None
            if hasattr(binding_module, 'language'):
                # For newer bindings
                ts_language_func = binding_module.language
                if callable(ts_language_func):
                    ts_language = ts_language_func()
                else:
                    ts_language = ts_language_func
            elif hasattr(binding_module, 'LANGUAGE'):
                # For older bindings
                ts_language = binding_module.LANGUAGE
            else:
                raise ImportError(f"Cannot find language in {binding_name}")
                
            # Create Language object from PyCapsule if needed
            from tree_sitter import Language
            if not isinstance(ts_language, Language):
                ts_language = Language(ts_language)
            
            # Create parser
            self._parser_instance = Parser()
            
            # Set the language using the new API
            self._parser_instance.language = ts_language
            
            logger.info(f"Tree-sitter parser initialized for {self.language}")
            
        except ImportError as e:
            raise LanguageNotSupportedError(
                self.language,
                details={
                    "error": str(e),
                    "required_binding": self.LANGUAGE_BINDINGS[self.language]
                }
            )
        except Exception as e:
            raise ParsingError(f"Failed to initialize parser for {self.language}: {e}")
    
    @property
    def supported_extensions(self) -> List[str]:
        """Get file extensions supported by this parser."""
        return self.EXTENSION_MAP.get(self.language, [])
    
    def parse(self, source_code: str, file_path: Optional[Path] = None) -> ParseResult:
        """Parse source code using tree-sitter."""
        start_time = time.time()
        
        try:
            # Check if parser is initialized
            if self._parser_instance is None:
                raise ParsingError(f"Parser not initialized for language {self.language}")
            
            # Parse with tree-sitter
            source_bytes = source_code.encode('utf-8')
            tree = self._parser_instance.parse(source_bytes)
            
            # Create parse result
            result = ParseResult(
                ast=tree,
                language=self.language,
                source_code=source_code,
                file_path=file_path
            )
            
            # Extract semantic information
            self._extract_semantic_info(tree.root_node, source_code, result)
            
            # Record performance
            result.parse_time_ms = (time.time() - start_time) * 1000
            
            return result
            
        except Exception as e:
            raise ParsingError(f"Failed to parse {self.language} code: {e}", 
                             file_path=str(file_path) if file_path else None)
    
    def _extract_semantic_info(self, root_node: Any, source_code: str, 
                              result: ParseResult) -> None:
        """Extract semantic information from AST."""
        lines = source_code.splitlines()
        
        def traverse_node(node: Any) -> None:
            node_type = node.type
            
            if self._is_function_node(node_type):
                func_info = self._extract_function_info(node, lines)
                if func_info:
                    result.functions.append(func_info)
            
            elif self._is_class_node(node_type):
                class_info = self._extract_class_info(node, lines)
                if class_info:
                    result.classes.append(class_info)
            
            elif self._is_import_node(node_type):
                import_info = self._extract_import_info(node, lines)
                if import_info:
                    result.imports.append(import_info)
            
            # Traverse children
            for child in node.children:
                traverse_node(child)
        
        traverse_node(root_node)
    
    def _is_function_node(self, node_type: str) -> bool:
        """Check if node type represents a function."""
        function_types = {
            'function_definition', 'async_function_definition',  # Python
            'function_declaration', 'function_expression', 'arrow_function',  # JS
            'method_definition', 'method_declaration', 'constructor_declaration'  # Various
        }
        return node_type in function_types
    
    def _is_class_node(self, node_type: str) -> bool:
        """Check if node type represents a class."""
        class_types = {
            'class_definition',  # Python
            'class_declaration',  # JS/TS/Java
            'interface_declaration',  # TS/Java
            'type_declaration'  # Go
        }
        return node_type in class_types
    
    def _is_import_node(self, node_type: str) -> bool:
        """Check if node type represents an import."""
        import_types = {
            'import_statement', 'import_from_statement',  # Python
            'import_declaration'  # Java/Go
        }
        return node_type in import_types
    
    def _extract_function_info(self, node: Any, lines: List[str]) -> Optional[Dict[str, Any]]:
        """Extract function information from AST node."""
        try:
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            
            # Find function name
            name = self._get_function_name(node)
            
            # Extract parameters
            params = self._get_function_parameters(node)
            
            # Calculate complexity (basic)
            complexity = self._calculate_node_complexity(node)
            
            return {
                'name': name,
                'start_line': start_line,
                'end_line': end_line,
                'parameters': params,
                'complexity': complexity,
                'node_type': node.type,
                'line_count': end_line - start_line + 1
            }
        
        except Exception as e:
            logger.warning(f"Failed to extract function info: {e}")
            return None
    
    def _extract_class_info(self, node: Any, lines: List[str]) -> Optional[Dict[str, Any]]:
        """Extract class information from AST node."""
        try:
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            
            # Find class name
            name = self._get_class_name(node)
            
            # Find methods
            methods = []
            for child in node.children:
                if self._is_function_node(child.type):
                    method_name = self._get_function_name(child)
                    if method_name:
                        methods.append(method_name)
            
            return {
                'name': name,
                'start_line': start_line,
                'end_line': end_line,
                'methods': methods,
                'node_type': node.type,
                'line_count': end_line - start_line + 1
            }
        
        except Exception as e:
            logger.warning(f"Failed to extract class info: {e}")
            return None
    
    def _extract_import_info(self, node: Any, lines: List[str]) -> Optional[Dict[str, Any]]:
        """Extract import information from AST node."""
        try:
            start_line = node.start_point[0] + 1
            
            # Get import text
            import_text = lines[start_line - 1] if start_line <= len(lines) else ""
            
            # Extract module name (simplified)
            module = self._get_import_module(node, import_text)
            
            return {
                'module': module,
                'line': start_line,
                'text': import_text.strip(),
                'node_type': node.type
            }
        
        except Exception as e:
            logger.warning(f"Failed to extract import info: {e}")
            return None
    
    def _get_function_name(self, node: Any) -> str:
        """Extract function name from AST node."""
        # Look for identifier child
        for child in node.children:
            if child.type == 'identifier':
                return child.text.decode('utf-8')
        
        return "unknown_function"
    
    def _get_class_name(self, node: Any) -> str:
        """Extract class name from AST node."""
        # Look for identifier child
        for child in node.children:
            if child.type == 'identifier' or child.type == 'type_identifier':
                return child.text.decode('utf-8')
        
        return "unknown_class"
    
    def _get_function_parameters(self, node: Any) -> List[str]:
        """Extract function parameters from AST node."""
        params = []
        
        # Look for parameter list
        for child in node.children:
            if 'parameter' in child.type or child.type == 'formal_parameters':
                for param_child in child.children:
                    if param_child.type == 'identifier':
                        params.append(param_child.text.decode('utf-8'))
        
        return params
    
    def _get_import_module(self, node: Any, import_text: str) -> str:
        """Extract module name from import."""
        # Simple heuristic - can be improved
        if 'import' in import_text:
            parts = import_text.split()
            for i, part in enumerate(parts):
                if part == 'import' and i + 1 < len(parts):
                    return parts[i + 1].strip(';,')
                elif part == 'from' and i + 1 < len(parts):
                    return parts[i + 1].strip(';,')
        
        return "unknown_module"
    
    def _calculate_node_complexity(self, node: Any) -> int:
        """Calculate basic complexity for a node."""
        complexity = 1  # Base complexity
        
        # Add complexity for control flow nodes
        control_flow_types = {
            'if_statement', 'for_statement', 'while_statement',
            'try_statement', 'except_clause', 'catch_clause'
        }
        
        def count_complexity(n: Any) -> int:
            count = 0
            if n.type in control_flow_types:
                count += 1
            
            for child in n.children:
                count += count_complexity(child)
            
            return count
        
        complexity += count_complexity(node)
        return complexity
    
    def is_valid_syntax(self, source_code: str) -> bool:
        """Check if source code has valid syntax."""
        try:
            # Check if parser is initialized
            if self._parser_instance is None:
                return False
            
            source_bytes = source_code.encode('utf-8')
            tree = self._parser_instance.parse(source_bytes)
            
            # Check for syntax errors
            return not self._has_syntax_errors(tree.root_node)
        
        except Exception:
            return False
    
    def _has_syntax_errors(self, node: Any) -> bool:
        """Check if AST has syntax errors."""
        if node.type == 'ERROR':
            return True
        
        for child in node.children:
            if self._has_syntax_errors(child):
                return True
        
        return False
    
    def get_node_type(self, node: Any) -> Optional[NodeType]:
        """Get NodeType for tree-sitter node."""
        node_type_map = self.NODE_TYPE_MAP.get(self.language, {})
        return node_type_map.get(node.type)
    
    def find_semantic_chunks(self, parse_result: ParseResult, 
                           max_lines: int = 100) -> List[Tuple[int, int, NodeType]]:
        """Find semantic chunks using tree-sitter AST."""
        chunks = []
        
        def traverse_for_chunks(node: Any, parent_start: int = 1) -> None:
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            line_count = end_line - start_line + 1
            
            node_type = self.get_node_type(node)
            
            # If this is a significant node within size limits
            if node_type and line_count <= max_lines:
                chunks.append((start_line, end_line, node_type))
            elif node_type and line_count > max_lines:
                # Split large nodes
                sub_chunks = self._split_large_chunk(
                    start_line, end_line, node_type, max_lines
                )
                chunks.extend(sub_chunks)
            else:
                # Continue traversing children
                for child in node.children:
                    traverse_for_chunks(child, start_line)
        
        if parse_result.ast:
            traverse_for_chunks(parse_result.ast.root_node)
        
        return sorted(chunks)
    
    def validate_chunk_boundaries(self, start_line: int, end_line: int,
                                 parse_result: ParseResult) -> bool:
        """Validate chunk boundaries using tree-sitter."""
        try:
            lines = parse_result.source_code.splitlines()
            chunk_code = '\n'.join(lines[start_line-1:end_line])
            
            # Parse the chunk
            return self.is_valid_syntax(chunk_code)
        
        except Exception:
            return False
