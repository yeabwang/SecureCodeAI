"""Language registry for managing parsers."""

import logging
from typing import Dict, List, Optional, Type, Set, Any
from pathlib import Path
from functools import lru_cache

from .base import BaseParser, LanguageDetector
from .tree_sitter_parser import TreeSitterParser
from ..config import SupportedLanguage
from ..exceptions import LanguageNotSupportedError, ParsingError


logger = logging.getLogger(__name__)


class LanguageRegistry:
    """Registry for managing language parsers."""
    
    def __init__(self):
        self._parsers: Dict[str, Type[BaseParser]] = {}
        self._parser_instances: Dict[str, BaseParser] = {}
        self._supported_extensions: Dict[str, str] = {}  # extension -> language
        
        # Register default parsers
        self._register_default_parsers()
    
    def _register_default_parsers(self) -> None:
        """Register default tree-sitter parsers."""
        tree_sitter_languages = [
            SupportedLanguage.PYTHON,
            SupportedLanguage.JAVASCRIPT,
            SupportedLanguage.TYPESCRIPT,
            SupportedLanguage.GO,
            SupportedLanguage.JAVA
        ]
        
        for language in tree_sitter_languages:
            try:
                self.register_parser(language.value, TreeSitterParser)
                logger.debug(f"Registered TreeSitterParser for {language.value}")
            except Exception as e:
                logger.warning(f"Failed to register parser for {language.value}: {e}")
    
    def register_parser(self, language: str, parser_class: Type[BaseParser]) -> None:
        """Register a parser class for a language."""
        self._parsers[language] = parser_class
        
        # Create instance to get supported extensions
        try:
            temp_instance = parser_class(language)
            for ext in temp_instance.supported_extensions:
                self._supported_extensions[ext] = language
            
            logger.info(f"Registered parser for {language} with extensions: {temp_instance.supported_extensions}")
        
        except Exception as e:
            logger.error(f"Failed to register parser for {language}: {e}")
            # Remove from registry if instantiation failed
            if language in self._parsers:
                del self._parsers[language]
    
    def get_parser(self, language: str) -> BaseParser:
        """Get parser instance for a language."""
        if language not in self._parsers:
            raise LanguageNotSupportedError(language)
        
        # Use cached instance if available
        if language in self._parser_instances:
            return self._parser_instances[language]
        
        # Create new instance
        try:
            parser_class = self._parsers[language]
            parser_instance = parser_class(language)
            self._parser_instances[language] = parser_instance
            return parser_instance
        
        except Exception as e:
            raise ParsingError(f"Failed to create parser for {language}: {e}")
    
    @lru_cache(maxsize=256)
    def get_parser_for_file(self, file_path: str, content_hint: Optional[str] = None) -> BaseParser:
        """Get parser for a specific file."""
        path = Path(file_path)
        
        # Try extension-based detection first
        language = self._supported_extensions.get(path.suffix.lower())
        
        if not language:
            # Try content-based detection
            language = LanguageDetector.detect_by_extension(path)
            
            if not language and content_hint:
                language = LanguageDetector.detect_by_content(content_hint)
        
        if not language or language not in self._parsers:
            # Fallback to Python parser as default
            language = SupportedLanguage.PYTHON.value
            if language not in self._parsers:
                raise LanguageNotSupportedError(f"No parser available for file: {file_path}")
        
        return self.get_parser(language)
    
    def get_supported_languages(self) -> List[str]:
        """Get list of supported languages."""
        return list(self._parsers.keys())
    
    def get_supported_extensions(self) -> Dict[str, str]:
        """Get mapping of extensions to languages."""
        return dict(self._supported_extensions)
    
    def is_language_supported(self, language: str) -> bool:
        """Check if a language is supported."""
        return language in self._parsers
    
    def is_file_supported(self, file_path: Path) -> bool:
        """Check if a file type is supported."""
        extension = file_path.suffix.lower()
        return extension in self._supported_extensions
    
    def get_parser_capabilities(self, language: str) -> Set[str]:
        """Get capabilities of a parser for a language."""
        if language not in self._parsers:
            return set()
        
        try:
            parser = self.get_parser(language)
            return {cap.value for cap in parser.capabilities}
        except Exception:
            return set()
    
    def validate_file_syntax(self, file_path: Path, content: str) -> bool:
        """Validate syntax of a file."""
        try:
            parser = self.get_parser_for_file(str(file_path), content)
            return parser.is_valid_syntax(content)
        except Exception:
            return False
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        return {
            'total_languages': len(self._parsers),
            'supported_languages': list(self._parsers.keys()),
            'total_extensions': len(self._supported_extensions),
            'supported_extensions': dict(self._supported_extensions),
            'cached_instances': len(self._parser_instances)
        }
    
    def clear_cache(self) -> None:
        """Clear cached parser instances."""
        self._parser_instances.clear()
        self.get_parser_for_file.cache_clear()
        logger.info("Parser registry cache cleared")


class ParserFactory:
    """Factory for creating parsers with dependency injection support."""
    
    def __init__(self, registry: Optional[LanguageRegistry] = None):
        self.registry = registry or LanguageRegistry()
    
    def create_parser(self, language: str, **kwargs) -> BaseParser:
        """Create parser with optional configuration."""
        parser = self.registry.get_parser(language)
        
        # Apply any configuration if supported
        for key, value in kwargs.items():
            if hasattr(parser, key):
                setattr(parser, key, value)
        
        return parser
    
    def create_parser_for_file(self, file_path: Path, 
                              content: Optional[str] = None,
                              **kwargs) -> BaseParser:
        """Create parser for a specific file."""
        parser = self.registry.get_parser_for_file(str(file_path), content)
        
        # Apply configuration
        for key, value in kwargs.items():
            if hasattr(parser, key):
                setattr(parser, key, value)
        
        return parser
    
    def get_best_parser(self, file_path: Path, content: str,
                       preferred_languages: Optional[List[str]] = None) -> BaseParser:
        """Get the best parser for a file considering preferences."""
        # Try preferred languages first
        if preferred_languages:
            for lang in preferred_languages:
                if self.registry.is_language_supported(lang):
                    try:
                        parser = self.registry.get_parser(lang)
                        if parser.is_valid_syntax(content):
                            return parser
                    except Exception:
                        continue
        
        # Fall back to automatic detection
        return self.registry.get_parser_for_file(str(file_path), content)


# Global registry instance
language_registry = LanguageRegistry()

# Global factory instance  
parser_factory = ParserFactory(language_registry)
