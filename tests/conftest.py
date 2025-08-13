"""Test configuration."""

import pytest
from pathlib import Path
import tempfile
import os

# Test fixtures
@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture
def sample_python_file(temp_dir):
    """Create a sample Python file with security issues."""
    content = '''
import os
import subprocess

# Hardcoded password - security issue
PASSWORD = "secret123"

def unsafe_function(user_input):
    # Command injection vulnerability
    os.system(f"echo {user_input}")
    
    # SQL injection vulnerability (simulated)
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    
    return query

def safe_function():
    return "This is safe"
'''
    
    file_path = temp_dir / "test_code.py"
    file_path.write_text(content)
    return file_path

@pytest.fixture 
def sample_requirements_file(temp_dir):
    """Create a sample requirements file with vulnerabilities."""
    content = '''
django==2.0.0
requests==2.6.0
pyyaml==3.12
'''
    
    file_path = temp_dir / "requirements.txt" 
    file_path.write_text(content)
    return file_path

@pytest.fixture
def mock_groq_api_key():
    """Mock Groq API key for testing."""
    original = os.environ.get('GROQ_API_KEY')
    os.environ['GROQ_API_KEY'] = 'test-key'
    yield
    if original is not None:
        os.environ['GROQ_API_KEY'] = original
    else:
        os.environ.pop('GROQ_API_KEY', None)
