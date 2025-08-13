"""Test static analysis integration."""

import pytest
from unittest.mock import Mock, patch
from pathlib import Path

from src.securecodeai.static_analysis.base import BaseStaticAnalyzer
from src.securecodeai.core.models import Finding, SourceTool, SeverityLevel, VulnerabilityType, ConfidenceLevel, Location


class MockStaticAnalyzer(BaseStaticAnalyzer):
    """Mock static analyzer for testing."""
    
    def get_tool_name(self) -> str:
        return "mock_tool"
    
    def get_source_tool(self) -> SourceTool:
        return SourceTool.BANDIT
    
    def is_available(self) -> bool:
        return True
    
    def analyze_file(self, file_path: Path):
        # Return a mock finding
        location = Location(
            file_path=file_path,
            start_line=1
        )
        
        return [Finding(
            title="Mock vulnerability",
            description="This is a mock vulnerability",
            vulnerability_type=VulnerabilityType.OTHER,
            severity=SeverityLevel.MEDIUM,
            confidence=0.7,
            confidence_level=ConfidenceLevel.HIGH,
            location=location,
            source_tool=SourceTool.BANDIT
        )]
    
    def analyze_directory(self, directory_path: Path):
        return self.analyze_file(directory_path / "mock_file.py")


class TestBaseStaticAnalyzer:
    """Test base static analyzer functionality."""
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        config = {'test': 'value'}
        analyzer = MockStaticAnalyzer(config)
        
        assert analyzer.config == config
        assert analyzer.tool_name == "mock_tool"
        assert analyzer.is_available()
    
    def test_analyze_paths(self, temp_dir):
        """Test analyzing multiple paths."""
        analyzer = MockStaticAnalyzer({})
        
        # Create test files
        file1 = temp_dir / "test1.py"
        file1.write_text("# test file 1")
        
        file2 = temp_dir / "test2.py"  
        file2.write_text("# test file 2")
        
        findings = analyzer.analyze_paths([file1, file2])
        
        assert len(findings) == 2
        assert all(isinstance(f, Finding) for f in findings)
    
    def test_confidence_calculation(self):
        """Test confidence calculation."""
        analyzer = MockStaticAnalyzer({})
        
        # Test with tool confidence
        confidence = analyzer._calculate_confidence(0.9)
        assert confidence == 0.9
        
        # Test without tool confidence (should use default)
        confidence = analyzer._calculate_confidence()
        assert 0.0 <= confidence <= 1.0
    
    def test_finding_filtering(self):
        """Test finding filtering based on configuration."""
        config = {
            'minimum_confidence': 0.8,
            'severity_threshold': SeverityLevel.MEDIUM,
        }
        analyzer = MockStaticAnalyzer(config)
        
        location = Location(file_path=Path("test.py"), start_line=1)
        
        # High confidence finding - should be included
        high_conf_finding = Finding(
            title="High confidence",
            description="Test",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            confidence_level=ConfidenceLevel.VERY_HIGH,
            location=location,
            source_tool=SourceTool.BANDIT
        )
        
        # Low confidence finding - should be excluded
        low_conf_finding = Finding(
            title="Low confidence",
            description="Test",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=0.5,
            confidence_level=ConfidenceLevel.MEDIUM,
            location=location,
            source_tool=SourceTool.BANDIT
        )
        
        assert analyzer._should_include_finding(high_conf_finding) is True
        assert analyzer._should_include_finding(low_conf_finding) is False
