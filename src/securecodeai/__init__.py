"""
SecureCodeAI: AI-powered security analysis tool.

This package provides intelligent security analysis combining static analysis
with LLM-based vulnerability detection and classification.
"""

__version__ = "0.1.0"
__author__ = "yeabwang"
__email__ = "yeabsiratesfaye781@gmail.com"

from .core.models import Finding, AnalysisResult, VulnerabilityType, SeverityLevel
from .core.analyzer import SecurityAnalyzer
from .core.config import Config

# For convenient imports
from .cli.main import main as cli_main

__all__ = [
    "Finding",
    "AnalysisResult", 
    "VulnerabilityType",
    "SeverityLevel",
    "SecurityAnalyzer",
    "Config",
    "cli_main",
]
