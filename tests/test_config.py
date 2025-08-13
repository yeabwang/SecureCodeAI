"""Test configuration management."""

import pytest
import tempfile
from pathlib import Path

from src.securecodeai.core.config import Config, StaticAnalysisConfig, LLMConfig


class TestConfig:
    """Test configuration management."""
    
    def test_default_config_creation(self):
        """Test creating default configuration."""
        config = Config.get_default_config()
        
        assert isinstance(config.static_analysis, StaticAnalysisConfig)
        assert isinstance(config.llm, LLMConfig)
        assert config.static_analysis.enable_bandit is True
        assert config.static_analysis.enable_safety is True
        assert config.static_analysis.enable_semgrep is True
    
    def test_config_from_dict(self):
        """Test creating config from dictionary."""
        config_dict = {
            'static_analysis': {
                'enable_bandit': False,
                'enable_safety': True,
            },
            'llm': {
                'model': 'test-model',
                'max_tokens': 2048,
            }
        }
        
        config = Config.load_from_dict(config_dict)
        
        assert config.static_analysis.enable_bandit is False
        assert config.static_analysis.enable_safety is True
        assert config.llm.model == 'test-model'
        assert config.llm.max_tokens == 2048
    
    def test_config_save_and_load(self, temp_dir):
        """Test saving and loading configuration."""
        config = Config.get_default_config()
        config.llm.model = 'test-model'
        config.static_analysis.enable_bandit = False
        
        config_file = temp_dir / 'test_config.yaml'
        config.save_to_file(config_file)
        
        assert config_file.exists()
        
        # Load and verify
        loaded_config = Config.load_from_file(config_file)
        assert loaded_config.llm.model == 'test-model'
        assert loaded_config.static_analysis.enable_bandit is False
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Create config without environment variables
        import os
        old_groq_key = os.environ.get('GROQ_API_KEY')
        old_groq_api = os.environ.get('GROQ_API')
        
        # Temporarily remove API keys from environment
        if 'GROQ_API_KEY' in os.environ:
            del os.environ['GROQ_API_KEY']
        if 'GROQ_API' in os.environ:
            del os.environ['GROQ_API']
        
        try:
            config = Config.get_default_config()
            
            # Valid config should have no issues except for missing API key
            issues = config.validate_config()
            # API key is not set in test environment, so expect that issue
            assert any('API key' in issue for issue in issues)
            
            # Test invalid confidence threshold
            config.scan.confidence_threshold = 1.5  # Invalid
            issues = config.validate_config()
            assert any('Confidence threshold' in issue for issue in issues)
        finally:
            # Restore environment variables
            if old_groq_key:
                os.environ['GROQ_API_KEY'] = old_groq_key
            if old_groq_api:
                os.environ['GROQ_API'] = old_groq_api
    
    def test_merge_with_cli_args(self):
        """Test merging config with CLI arguments."""
        config = Config.get_default_config()
        
        # Test merging
        merged = config.merge_with_cli_args(
            verbose=True,
            format='json',
            confidence_threshold=0.8
        )
        
        assert merged.output.verbose is True
        assert merged.output.format.value == 'json'
        assert merged.scan.confidence_threshold == 0.8
