"""Integration tests for SecureCodeAI core functionality."""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch

from securecodeai.core import SecurityAnalyzer, Config, ScanMode
from securecodeai.core.models import Finding, SeverityLevel
from securecodeai.llm import GroqClient


class TestIntegration:
    """Integration tests for the complete analysis pipeline."""
    
    def test_multi_tool_analysis_pipeline(self, sample_vulnerable_file):
        """Test complete static analysis workflow with multiple tools."""
        config = Config.get_default_config()
        config.llm.enable_classification = False  # Test static analysis only
        config.llm.enable_detailed_analysis = False
        
        analyzer = SecurityAnalyzer(config)
        
        # Test that all static analysis tools are initialized
        assert len(analyzer.static_orchestrator.analyzers) >= 3
        assert 'bandit' in analyzer.static_orchestrator.analyzers
        assert 'safety' in analyzer.static_orchestrator.analyzers
        assert 'semgrep' in analyzer.static_orchestrator.analyzers
        
        # Run analysis
        result = analyzer.analyze([sample_vulnerable_file])
        
        # Verify results
        assert result.total_files_analyzed >= 1
        assert len(result.findings) > 0
        assert result.tools_used  # Should have at least one tool
        
        # Verify findings have proper structure
        for finding in result.findings:
            assert finding.id
            assert finding.title
            assert finding.severity in SeverityLevel
            assert 0.0 <= finding.confidence <= 1.0
            assert finding.source_tool
            assert finding.location
    
    def test_finding_deduplication(self, sample_vulnerable_file):
        """Test cross-tool finding correlation and deduplication."""
        config = Config.get_default_config()
        config.llm.enable_classification = False
        config.llm.enable_detailed_analysis = False
        
        analyzer = SecurityAnalyzer(config)
        result = analyzer.analyze([sample_vulnerable_file])
        
        # Test that findings are properly deduplicated
        finding_keys = set()
        for finding in result.findings:
            # Create a key based on location and vulnerability type
            key = (finding.location.file_path, finding.location.start_line, finding.vulnerability_type)
            assert key not in finding_keys, f"Duplicate finding detected: {key}"
            finding_keys.add(key)
        
        # Verify deduplication statistics
        raw_findings = analyzer.static_orchestrator.analyze_paths([sample_vulnerable_file])
        deduplicated_findings = result.findings
        
        # Should have same or fewer findings after deduplication
        assert len(deduplicated_findings) <= len(raw_findings)
    
    @pytest.mark.asyncio
    async def test_groq_api_with_rate_limiting(self):
        """Test Groq LLM client robustness with rate limiting."""
        # Test with mock API responses
        with patch('securecodeai.llm.groq_client.Groq') as mock_groq_class:
            mock_client = Mock()
            mock_groq_class.return_value = mock_client
            
            # Mock successful response
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = "Test response"
            mock_response.choices[0].finish_reason = "stop"
            mock_response.usage.total_tokens = 50
            mock_client.chat.completions.create.return_value = mock_response
            
            groq_client = GroqClient(api_key="test-key")
            
            # Test single request
            response = groq_client.simple_completion("Test prompt")
            assert response == "Test response"
            
            # Test rate limiting tracking
            stats = groq_client.get_usage_stats()
            assert stats['total_requests'] == 1
            # The token count will be from tiktoken counting the input prompt, not the mock response
            assert stats['total_tokens'] > 0  # Just verify some tokens were counted
            
            # Test multiple requests
            for _ in range(5):
                groq_client.simple_completion("Test prompt")
            
            stats = groq_client.get_usage_stats()
            assert stats['total_requests'] == 6
            # Total tokens will be from tiktoken counting, not mock responses
            assert stats['total_tokens'] > 0  # Just verify tokens are being tracked
    
    def test_configuration_management(self, tmp_path):
        """Test config loading and validation across different sources."""
        # Test YAML config file
        config_file = tmp_path / "test_config.yaml"
        config_data = {
            'scan': {
                'mode': 'full',
                'severity_threshold': 'medium',
                'confidence_threshold': 0.7
            },
            'llm': {
                'enable_classification': True,
                'enable_detailed_analysis': False,
                'provider': 'groq',
                'model': 'llama3-70b-8192'
            }
        }
        
        import yaml
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        # Load config
        config = Config.load_from_file(config_file)
        assert config.scan.mode == ScanMode.FULL
        assert config.scan.severity_threshold == SeverityLevel.MEDIUM
        assert config.scan.confidence_threshold == 0.7
        assert config.llm.enable_classification == True
        assert config.llm.enable_detailed_analysis == False
        assert config.llm.model == 'llama3-70b-8192'
        
        # Test CLI arg merging
        cli_args = {
            'mode': 'fast',
            'confidence_threshold': 0.9
        }
        merged_config = config.merge_with_cli_args(**cli_args)
        assert merged_config.scan.mode == ScanMode.FAST
        assert merged_config.scan.confidence_threshold == 0.9
        assert merged_config.scan.severity_threshold == SeverityLevel.MEDIUM  # Unchanged
    
    def test_llm_integration_with_static_analysis(self, sample_vulnerable_file):
        """Test LLM enhancement of static analysis findings."""
        config = Config.get_default_config()
        config.llm.enable_classification = True
        config.llm.enable_detailed_analysis = False
        config.llm.api_key = "test-api-key"  # Set test API key
        
        # Mock Groq client to avoid real API calls
        with patch('securecodeai.llm.groq_client.Groq') as mock_groq_class:
            mock_client = Mock()
            mock_groq_class.return_value = mock_client
            
            # Mock LLM response with JSON
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = json.dumps({
                "valid": True,
                "remediation_advice": "Use parameterized queries to prevent SQL injection",
                "fix_suggestion": "Use cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
            })
            mock_response.choices[0].finish_reason = "stop"
            mock_response.usage.total_tokens = 150
            mock_client.chat.completions.create.return_value = mock_response
            
            analyzer = SecurityAnalyzer(config)
            result = analyzer.analyze([sample_vulnerable_file])
            
            # Verify LLM was called
            assert result.llm_requests_made > 0
            assert result.llm_tokens_used > 0
            
            # Verify LLM-enhanced findings exist
            llm_enhanced_findings = [f for f in result.findings if f.remediation_advice]
            assert len(llm_enhanced_findings) > 0
            
            # Verify remediation advice quality
            for finding in llm_enhanced_findings:
                assert finding.remediation_advice
                assert len(finding.remediation_advice) > 10  # Meaningful advice
                if finding.fix_suggestion:
                    assert len(finding.fix_suggestion) > 5  # Meaningful suggestion


@pytest.fixture
def sample_vulnerable_file(tmp_path):
    """Create a sample Python file with known vulnerabilities."""
    vulnerable_code = '''
import subprocess
import pickle
import hashlib

# Hardcoded password
PASSWORD = "admin123"

def execute_command(user_input):
    # Command injection vulnerability
    command = f"ls {user_input}"
    return subprocess.call(command, shell=True)

def load_data(data_file):
    # Unsafe deserialization
    with open(data_file, 'rb') as f:
        return pickle.load(f)

def hash_password(password):
    # Weak hash algorithm
    return hashlib.md5(password.encode()).hexdigest()

def query_user(user_id):
    # SQL injection potential
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''
    
    test_file = tmp_path / "vulnerable_test.py"
    test_file.write_text(vulnerable_code)
    return test_file
