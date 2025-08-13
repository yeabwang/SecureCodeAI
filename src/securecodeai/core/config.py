"""Configuration management for SecureCodeAI."""

import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv

from .models import SeverityLevel, VulnerabilityType, SourceTool, ScanMode, OutputFormat


class StaticAnalysisConfig(BaseModel):
    """Configuration for static analysis tools."""
    
    # Tool enablement
    enable_bandit: bool = True
    enable_safety: bool = True
    enable_semgrep: bool = True
    
    # Bandit configuration
    bandit_config_file: Optional[Path] = None
    bandit_exclude_paths: List[str] = Field(default_factory=lambda: ["*/tests/*", "*/test_*"])
    bandit_skip_tests: bool = True
    
    # Safety configuration
    safety_db_update: bool = True
    safety_ignore_ids: List[str] = Field(default_factory=list)
    
    # Semgrep configuration
    semgrep_rules: List[str] = Field(default_factory=lambda: ["auto"])
    semgrep_config_file: Optional[Path] = None
    semgrep_exclude_patterns: List[str] = Field(default_factory=list)


class LLMConfig(BaseModel):
    """Configuration for LLM integration."""
    
    # Provider settings
    provider: str = "groq"
    model: str = "llama3-70b-8192"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    
    # Request configuration
    max_tokens: int = 4096
    temperature: float = 0.1
    timeout_seconds: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    
    # Rate limiting
    requests_per_minute: int = 60
    tokens_per_minute: int = 50000
    
    # Analysis configuration
    enable_classification: bool = True
    enable_detailed_analysis: bool = True
    enable_cross_validation: bool = True
    minimum_confidence_threshold: float = 0.3
    
    @validator('api_key', always=True)
    def load_api_key(cls, v):
        """Load API key from environment if not provided."""
        if v is None:
            return os.getenv('GROQ_API_KEY') or os.getenv('GROQ_API')
        return v


class ScanConfig(BaseModel):
    """Configuration for scanning behavior."""
    
    # Scan settings
    mode: ScanMode = ScanMode.FULL
    target_extensions: List[str] = Field(
        default_factory=lambda: [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php"]
    )
    exclude_patterns: List[str] = Field(
        default_factory=lambda: [
            "*/node_modules/*", "*/.git/*", "*/venv/*", "*/__pycache__/*",
            "*/dist/*", "*/build/*", "*/target/*"
        ]
    )
    max_file_size_mb: int = 10
    parallel_workers: int = 4
    
    # Filtering
    severity_threshold: SeverityLevel = SeverityLevel.LOW
    confidence_threshold: float = 0.3
    vulnerability_types: List[VulnerabilityType] = Field(default_factory=list)  # Empty = all types
    
    # Chunking configuration
    max_chunk_size: int = 4000  # tokens
    chunk_overlap: int = 200   # tokens
    enable_smart_chunking: bool = True


class OutputConfig(BaseModel):
    """Configuration for output formatting."""
    
    # Default output settings
    format: OutputFormat = OutputFormat.TABLE
    output_file: Optional[Path] = None
    include_code_snippets: bool = True
    include_remediation: bool = True
    
    # Report customization
    show_statistics: bool = True
    group_by_file: bool = False
    sort_by_severity: bool = True
    
    # Verbosity
    verbose: bool = False
    quiet: bool = False
    show_progress: bool = True


class Config(BaseModel):
    """Main configuration class for SecureCodeAI."""
    
    # Sub-configurations
    static_analysis: StaticAnalysisConfig = Field(default_factory=StaticAnalysisConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    
    # Global settings
    log_level: str = "INFO"
    log_file: Optional[Path] = None
    cache_enabled: bool = True
    cache_directory: Path = Field(default_factory=lambda: Path.home() / ".securecodeai" / "cache")
    
    @classmethod
    def load_from_file(cls, config_path: Path) -> "Config":
        """Load configuration from YAML file."""
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        return cls(**config_data)
    
    @classmethod
    def load_from_dict(cls, config_dict: Dict[str, Any]) -> "Config":
        """Load configuration from dictionary."""
        return cls(**config_dict)
    
    @classmethod
    def get_default_config(cls) -> "Config":
        """Get default configuration."""
        # Load environment variables
        load_dotenv()
        return cls()
    
    @classmethod
    def find_config_file(cls, start_path: Optional[Path] = None) -> Optional[Path]:
        """Find configuration file in current directory or parent directories."""
        if start_path is None:
            start_path = Path.cwd()
        
        config_names = [
            ".securecodeai.yaml",
            ".securecodeai.yml", 
            "securecodeai.yaml",
            "securecodeai.yml",
            "pyproject.toml"  # Look for [tool.securecodeai] section
        ]
        
        current_path = start_path.resolve()
        
        # Search up the directory tree
        while current_path != current_path.parent:
            for config_name in config_names:
                config_file = current_path / config_name
                if config_file.exists():
                    if config_name == "pyproject.toml":
                        # Check if it has securecodeai configuration
                        if cls._has_securecodeai_config(config_file):
                            return config_file
                    else:
                        return config_file
            current_path = current_path.parent
        
        return None
    
    @classmethod
    def _has_securecodeai_config(cls, pyproject_path: Path) -> bool:
        """Check if pyproject.toml has securecodeai configuration."""
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                return False
        
        try:
            with open(pyproject_path, 'rb') as f:
                data = tomllib.load(f)
            return "tool" in data and "securecodeai" in data["tool"]
        except Exception:
            return False
    
    @classmethod
    def load_from_pyproject(cls, pyproject_path: Path) -> "Config":
        """Load configuration from pyproject.toml file."""
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                raise ImportError("tomllib or tomli required to read pyproject.toml")
        
        with open(pyproject_path, 'rb') as f:
            data = tomllib.load(f)
        
        if "tool" not in data or "securecodeai" not in data["tool"]:
            raise ValueError("No [tool.securecodeai] section found in pyproject.toml")
        
        config_data = data["tool"]["securecodeai"]
        return cls(**config_data)
    
    def save_to_file(self, config_path: Path) -> None:
        """Save configuration to YAML file."""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dict and clean up for YAML serialization
        config_dict = self.dict()
        self._prepare_for_yaml(config_dict)
        
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)
    
    def _prepare_for_yaml(self, data: Any) -> Any:
        """Prepare data for YAML serialization."""
        if isinstance(data, dict):
            return {k: self._prepare_for_yaml(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._prepare_for_yaml(item) for item in data]
        elif isinstance(data, Path):
            return str(data)
        elif hasattr(data, 'value'):  # Enum
            return data.value
        else:
            return data
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        # Validate LLM configuration
        if self.llm.api_key is None:
            issues.append("LLM API key not configured")
        
        # Validate scan configuration
        if self.scan.confidence_threshold < 0 or self.scan.confidence_threshold > 1:
            issues.append("Confidence threshold must be between 0 and 1")
        
        if self.scan.max_file_size_mb <= 0:
            issues.append("Max file size must be positive")
        
        if self.scan.parallel_workers <= 0:
            issues.append("Parallel workers must be positive")
        
        # Validate output configuration
        if self.output.output_file and self.output.output_file.parent:
            if not self.output.output_file.parent.exists():
                issues.append(f"Output directory does not exist: {self.output.output_file.parent}")
        
        return issues
    
    def merge_with_cli_args(self, **cli_args) -> "Config":
        """Merge configuration with CLI arguments."""
        # Create a copy of current config
        config_dict = self.dict()
        
        # Map CLI arguments to config structure
        cli_mapping = {
            'verbose': 'output.verbose',
            'quiet': 'output.quiet',
            'format': 'output.format',
            'output': 'output.output_file',
            'severity_threshold': 'scan.severity_threshold',
            'confidence_threshold': 'scan.confidence_threshold',
            'parallel_workers': 'scan.parallel_workers',
        }
        
        for cli_key, cli_value in cli_args.items():
            if cli_value is not None and cli_key in cli_mapping:
                config_path = cli_mapping[cli_key].split('.')
                current = config_dict
                
                # Navigate to the right location in config dict
                for path_part in config_path[:-1]:
                    current = current[path_part]
                
                # Set the value
                current[config_path[-1]] = cli_value
        
        return Config(**config_dict)
