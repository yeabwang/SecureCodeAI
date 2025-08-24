"""Custom exception hierarchy for intelligent code chunking."""

from typing import Optional, Any


class ChunkingError(Exception):
    """Base exception for all chunking-related errors."""
    
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ParsingError(ChunkingError):
    """Raised when code parsing fails."""
    
    def __init__(self, message: str, file_path: Optional[str] = None, 
                 line_number: Optional[int] = None, **kwargs):
        super().__init__(message, kwargs)
        self.file_path = file_path
        self.line_number = line_number


class LanguageNotSupportedError(ChunkingError):
    """Raised when attempting to chunk unsupported language."""
    
    def __init__(self, language: str, file_path: Optional[str] = None, details: Optional[dict] = None):
        message = f"Language '{language}' is not supported for chunking"
        error_details = {"language": language, "file_path": file_path}
        if details:
            error_details.update(details)
        super().__init__(message, error_details)
        self.language = language
        self.file_path = file_path


class TokenLimitExceededError(ChunkingError):
    """Raised when chunk exceeds token limits."""
    
    def __init__(self, current_tokens: int, max_tokens: int, 
                 chunk_content: Optional[str] = None):
        message = f"Chunk size {current_tokens} exceeds limit {max_tokens}"
        super().__init__(message, {
            "current_tokens": current_tokens,
            "max_tokens": max_tokens
        })
        self.current_tokens = current_tokens
        self.max_tokens = max_tokens
        self.chunk_content = chunk_content


class SyntaxBoundaryViolationError(ChunkingError):
    """Raised when chunking would break syntax boundaries."""
    
    def __init__(self, message: str, node_type: Optional[str] = None,
                 start_line: Optional[int] = None, end_line: Optional[int] = None):
        super().__init__(message, {
            "node_type": node_type,
            "start_line": start_line,
            "end_line": end_line
        })
        self.node_type = node_type
        self.start_line = start_line
        self.end_line = end_line


class ChunkValidationError(ChunkingError):
    """Raised when chunk validation fails."""
    
    def __init__(self, message: str, chunk_id: Optional[str] = None,
                 validation_rules: Optional[list] = None):
        super().__init__(message, {
            "chunk_id": chunk_id,
            "validation_rules": validation_rules
        })
        self.chunk_id = chunk_id
        self.validation_rules = validation_rules


class CacheError(ChunkingError):
    """Raised when cache operations fail."""
    
    def __init__(self, message: str, cache_key: Optional[str] = None,
                 operation: Optional[str] = None):
        super().__init__(message, {
            "cache_key": cache_key,
            "operation": operation
        })
        self.cache_key = cache_key
        self.operation = operation


class DependencyAnalysisError(ChunkingError):
    """Raised when dependency analysis fails."""
    
    def __init__(self, message: str, file_path: Optional[str] = None,
                 dependency_type: Optional[str] = None):
        super().__init__(message, {
            "file_path": file_path,
            "dependency_type": dependency_type
        })
        self.file_path = file_path
        self.dependency_type = dependency_type
