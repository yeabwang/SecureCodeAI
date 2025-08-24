"""Base parser interface for intelligent code chunking."""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any, Set, Tuple
from pathlib import Path
from enum import Enum

from ..models import NodeType, ChunkMetadata
from ..exceptions import ParsingError, LanguageNotSupportedError


class ParserCapability(str, Enum):
    """Capabilities that a parser can support."""
    
    SYNTAX_TREE = "syntax_tree"
    SEMANTIC_ANALYSIS = "semantic_analysis"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    ERROR_RECOVERY = "error_recovery"
    INCREMENTAL_PARSING = "incremental_parsing"


class ParseResult:
    """Result of parsing operation."""
    
    def __init__(self, 
                 ast: Any,
                 language: str,
                 source_code: str,
                 file_path: Optional[Path] = None):
        self.ast = ast
        self.language = language
        self.source_code = source_code
        self.file_path = file_path
        
        # Analysis results
        self.functions: List[Dict[str, Any]] = []
        self.classes: List[Dict[str, Any]] = []
        self.imports: List[Dict[str, Any]] = []
        self.variables: List[Dict[str, Any]] = []
        self.comments: List[Dict[str, Any]] = []
        
        # Metadata
        self.line_count = len(source_code.splitlines()) if source_code else 0
        self.character_count = len(source_code) if source_code else 0
        self.parsing_errors: List[str] = []
        self.warnings: List[str] = []
        
        # Performance metrics
        self.parse_time_ms: Optional[float] = None
        self.memory_usage_mb: Optional[float] = None
    
    def get_node_at_line(self, line_number: int) -> Optional[Any]:
        """Get AST node at specific line number."""
        # This would need to be implemented by concrete parsers
        return None
    
    def get_nodes_in_range(self, start_line: int, end_line: int) -> List[Any]:
        """Get AST nodes in line range."""
        # This would need to be implemented by concrete parsers
        return []
    
    def get_semantic_boundaries(self) -> List[Tuple[int, int, NodeType]]:
        """Get semantic boundaries in the code."""
        boundaries = []
        
        # Add function boundaries
        for func in self.functions:
            if 'start_line' in func and 'end_line' in func:
                boundaries.append((
                    func['start_line'],
                    func['end_line'],
                    NodeType.FUNCTION_DEF
                ))
        
        # Add class boundaries
        for cls in self.classes:
            if 'start_line' in cls and 'end_line' in cls:
                boundaries.append((
                    cls['start_line'],
                    cls['end_line'],
                    NodeType.CLASS_DEF
                ))
        
        return sorted(boundaries)


class BaseParser(ABC):
    """Abstract base class for code parsers."""
    
    def __init__(self, language: str):
        self.language = language
        self.capabilities: Set[ParserCapability] = set()
        self._parser_instance: Optional[Any] = None
    
    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """Get file extensions supported by this parser."""
        pass
    
    @abstractmethod
    def parse(self, source_code: str, file_path: Optional[Path] = None) -> ParseResult:
        """Parse source code and return parse result."""
        pass
    
    @abstractmethod
    def is_valid_syntax(self, source_code: str) -> bool:
        """Check if source code has valid syntax."""
        pass
    
    def supports_capability(self, capability: ParserCapability) -> bool:
        """Check if parser supports a specific capability."""
        return capability in self.capabilities
    
    def extract_functions(self, parse_result: ParseResult) -> List[Dict[str, Any]]:
        """Extract function definitions from parse result."""
        return parse_result.functions
    
    def extract_classes(self, parse_result: ParseResult) -> List[Dict[str, Any]]:
        """Extract class definitions from parse result."""
        return parse_result.classes
    
    def extract_imports(self, parse_result: ParseResult) -> List[Dict[str, Any]]:
        """Extract import statements from parse result."""
        return parse_result.imports
    
    def extract_dependencies(self, parse_result: ParseResult) -> Dict[str, List[str]]:
        """Extract dependencies from parse result."""
        dependencies = {
            'imports': [],
            'function_calls': [],
            'variable_references': []
        }
        
        # Extract from imports
        for imp in parse_result.imports:
            if 'module' in imp:
                dependencies['imports'].append(imp['module'])
        
        return dependencies
    
    def get_node_type(self, node: Any) -> Optional[NodeType]:
        """Get the NodeType for an AST node."""
        # This should be implemented by concrete parsers
        return None
    
    def find_semantic_chunks(self, parse_result: ParseResult, 
                           max_lines: int = 100) -> List[Tuple[int, int, NodeType]]:
        """Find semantic chunks in the parsed code."""
        chunks = []
        boundaries = parse_result.get_semantic_boundaries()
        
        for start_line, end_line, node_type in boundaries:
            if end_line - start_line <= max_lines:
                chunks.append((start_line, end_line, node_type))
            else:
                # Split large chunks
                sub_chunks = self._split_large_chunk(
                    start_line, end_line, node_type, max_lines
                )
                chunks.extend(sub_chunks)
        
        return chunks
    
    def _split_large_chunk(self, start_line: int, end_line: int, 
                          node_type: NodeType, max_lines: int) -> List[Tuple[int, int, NodeType]]:
        """Split a large semantic chunk into smaller ones."""
        chunks = []
        current_start = start_line
        
        while current_start < end_line:
            current_end = min(current_start + max_lines, end_line)
            chunks.append((current_start, current_end, NodeType.BLOCK))
            current_start = current_end
        
        return chunks
    
    def validate_chunk_boundaries(self, start_line: int, end_line: int,
                                 parse_result: ParseResult) -> bool:
        """Validate that chunk boundaries don't break syntax."""
        try:
            lines = parse_result.source_code.splitlines()
            chunk_code = '\n'.join(lines[start_line-1:end_line])
            return self.is_valid_syntax(chunk_code)
        except Exception:
            return False
    
    def get_complexity_metrics(self, parse_result: ParseResult) -> Dict[str, float]:
        """Get complexity metrics for the parsed code."""
        metrics = {
            'cyclomatic_complexity': 0.0,
            'cognitive_complexity': 0.0,
            'nesting_depth': 0.0,
            'function_count': len(parse_result.functions),
            'class_count': len(parse_result.classes),
            'lines_of_code': parse_result.line_count
        }
        
        # Basic complexity estimation
        if parse_result.line_count > 0:
            metrics['complexity_per_line'] = (
                metrics['function_count'] + metrics['class_count']
            ) / parse_result.line_count
        
        return metrics


class LanguageDetector:
    """Utility class for detecting programming languages."""
    
    # File extension to language mapping
    EXTENSION_MAP = {
        '.py': 'python',
        '.js': 'javascript', 
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.go': 'go',
        '.java': 'java',
        '.php': 'php',
        '.c': 'c',
        '.cpp': 'cpp',
        '.cxx': 'cpp',
        '.cc': 'cpp',
        '.rs': 'rust',
        '.rb': 'ruby'
    }
    
    # Language patterns for content-based detection
    LANGUAGE_PATTERNS = {
        'python': [
            r'#!/usr/bin/env python',
            r'#!/usr/bin/python',
            r'# -\*- coding: utf-8 -\*-',
            r'def\s+\w+\s*\(',
            r'import\s+\w+',
            r'from\s+\w+\s+import'
        ],
        'javascript': [
            r'#!/usr/bin/env node',
            r'function\s+\w+\s*\(',
            r'var\s+\w+\s*=',
            r'let\s+\w+\s*=',
            r'const\s+\w+\s*=',
            r'require\s*\(',
            r'module\.exports'
        ],
        'typescript': [
            r'interface\s+\w+',
            r'type\s+\w+\s*=',
            r'class\s+\w+\s*implements',
            r':\s*\w+\s*=',
            r'export\s+interface',
            r'import\s+type'
        ],
        'go': [
            r'package\s+\w+',
            r'import\s*\(',
            r'func\s+\w+\s*\(',
            r'type\s+\w+\s+struct',
            r'go\s+func'
        ],
        'java': [
            r'package\s+[\w\.]+;',
            r'import\s+[\w\.]+;',
            r'public\s+class\s+\w+',
            r'private\s+\w+\s+\w+',
            r'public\s+static\s+void\s+main'
        ]
    }
    
    @classmethod
    def detect_by_extension(cls, file_path: Path) -> Optional[str]:
        """Detect language by file extension."""
        return cls.EXTENSION_MAP.get(file_path.suffix.lower())
    
    @classmethod
    def detect_by_content(cls, content: str, hint: Optional[str] = None) -> Optional[str]:
        """Detect language by content analysis."""
        import re
        
        # If hint provided, try it first
        if hint and hint in cls.LANGUAGE_PATTERNS:
            patterns = cls.LANGUAGE_PATTERNS[hint]
            for pattern in patterns:
                if re.search(pattern, content, re.MULTILINE):
                    return hint
        
        # Try all languages
        scores = {}
        for language, patterns in cls.LANGUAGE_PATTERNS.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, content, re.MULTILINE):
                    score += 1
            if score > 0:
                scores[language] = score
        
        if scores:
            return max(scores.keys(), key=lambda k: scores[k])
        
        return None
    
    @classmethod
    def detect_language(cls, file_path: Path, content: Optional[str] = None) -> str:
        """Detect language using multiple methods."""
        # Try extension first
        language = cls.detect_by_extension(file_path)
        if language:
            return language
        
        # Try content analysis if available
        if content:
            language = cls.detect_by_content(content)
            if language:
                return language
        
        # Default fallback
        return 'text'
