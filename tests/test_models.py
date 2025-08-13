"""Test core data models."""

import pytest
from datetime import datetime
from pathlib import Path

from securecodeai.core.models import (
    Finding, AnalysisResult, VulnerabilityType, SeverityLevel, 
    ConfidenceLevel, SourceTool, Location
)


class TestFinding:
    """Test Finding data model."""
    
    def test_finding_creation(self):
        """Test basic finding creation."""
        location = Location(
            file_path=Path("test.py"),
            start_line=10,
            end_line=12
        )
        
        finding = Finding(
            title="Test vulnerability",
            description="This is a test vulnerability",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            confidence_level=ConfidenceLevel.HIGH,
            location=location,
            source_tool=SourceTool.BANDIT
        )
        
        assert finding.title == "Test vulnerability"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == 0.8
        assert finding.location.file_path == Path("test.py")
        assert finding.location.start_line == 10
    
    def test_confidence_level_auto_calculation(self):
        """Test that confidence level is automatically calculated."""
        location = Location(file_path=Path("test.py"), start_line=1)
        
        # Test very high confidence
        finding = Finding(
            title="Test",
            description="Test",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=0.95,
            confidence_level=ConfidenceLevel.LOW,  # This should be overridden
            location=location,
            source_tool=SourceTool.BANDIT
        )
        
        assert finding.confidence_level == ConfidenceLevel.VERY_HIGH
        
        # Test medium confidence
        finding.confidence = 0.6
        finding = Finding.parse_obj(finding.dict())  # Re-validate
        assert finding.confidence_level == ConfidenceLevel.MEDIUM
    
    def test_location_validation(self):
        """Test location validation."""
        # Valid location
        location = Location(
            file_path=Path("test.py"),
            start_line=5,
            end_line=10
        )
        assert location.start_line == 5
        assert location.end_line == 10
        
        # Invalid location (end_line < start_line)
        with pytest.raises(ValueError):
            Location(
                file_path=Path("test.py"),
                start_line=10,
                end_line=5
            )


class TestAnalysisResult:
    """Test AnalysisResult data model."""
    
    def test_analysis_result_creation(self):
        """Test basic analysis result creation."""
        start_time = datetime.utcnow()
        result = AnalysisResult(
            start_time=start_time,
            target_paths=[Path("test.py")],
            tools_used=[SourceTool.BANDIT]
        )
        
        assert result.start_time == start_time
        assert result.target_paths == [Path("test.py")]
        assert result.tools_used == [SourceTool.BANDIT]
        assert len(result.findings) == 0
    
    def test_add_finding(self):
        """Test adding findings to analysis result."""
        result = AnalysisResult(
            start_time=datetime.utcnow(),
            target_paths=[Path("test.py")],
            tools_used=[SourceTool.BANDIT]
        )
        
        location = Location(file_path=Path("test.py"), start_line=1)
        finding = Finding(
            title="Test",
            description="Test vulnerability",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            confidence_level=ConfidenceLevel.HIGH,
            location=location,
            source_tool=SourceTool.BANDIT
        )
        
        result.add_finding(finding)
        
        assert len(result.findings) == 1
        assert result.findings_by_severity[SeverityLevel.HIGH] == 1
        assert result.findings_by_type[VulnerabilityType.SQL_INJECTION] == 1
        assert result.findings_by_tool[SourceTool.BANDIT] == 1
    
    def test_get_high_severity_findings(self):
        """Test filtering high severity findings."""
        result = AnalysisResult(
            start_time=datetime.utcnow(),
            target_paths=[Path("test.py")],
            tools_used=[SourceTool.BANDIT]
        )
        
        location = Location(file_path=Path("test.py"), start_line=1)
        
        # Add high severity finding
        high_finding = Finding(
            title="High severity",
            description="Test",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            confidence_level=ConfidenceLevel.HIGH,
            location=location,
            source_tool=SourceTool.BANDIT
        )
        
        # Add low severity finding
        low_finding = Finding(
            title="Low severity",
            description="Test",
            vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
            severity=SeverityLevel.LOW,
            confidence=0.6,
            confidence_level=ConfidenceLevel.MEDIUM,
            location=location,
            source_tool=SourceTool.BANDIT
        )
        
        result.add_finding(high_finding)
        result.add_finding(low_finding)
        
        high_findings = result.get_high_severity_findings()
        assert len(high_findings) == 1
        assert high_findings[0].severity == SeverityLevel.HIGH
    
    def test_duration_calculation(self):
        """Test duration calculation."""
        start_time = datetime.utcnow()
        result = AnalysisResult(
            start_time=start_time,
            target_paths=[Path("test.py")],
            tools_used=[SourceTool.BANDIT]
        )
        
        # Simulate end time
        import time
        time.sleep(0.1)  # 100ms
        end_time = datetime.utcnow()
        result.end_time = end_time
        
        # Re-validate to trigger duration calculation
        result = AnalysisResult.parse_obj(result.dict())
        
        assert result.duration_seconds is not None
        assert result.duration_seconds > 0.05  # At least 50ms
