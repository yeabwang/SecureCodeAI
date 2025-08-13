"""Safety static analysis tool integration for dependency vulnerability scanning."""

import json
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..core.models import Finding, Location, SourceTool, SeverityLevel, VulnerabilityType, ConfidenceLevel
from .base import BaseStaticAnalyzer, ToolExecutionError


class SafetyAnalyzer(BaseStaticAnalyzer):
    """Integration with Safety for Python dependency vulnerability scanning."""
    
    def get_tool_name(self) -> str:
        return "safety"
    
    def get_source_tool(self) -> SourceTool:
        return SourceTool.SAFETY
    
    def is_available(self) -> bool:
        """Check if safety is available."""
        try:
            result = subprocess.run(
                ["safety", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def get_version(self) -> Optional[str]:
        """Get safety version."""
        try:
            result = subprocess.run(
                ["safety", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                # Extract version from output
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def get_supported_extensions(self) -> List[str]:
        """Safety analyzes Python requirements files."""
        return [".txt", ".in", ".pip", "requirements.txt", "requirements-dev.txt"]
    
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a requirements file with safety."""
        if not self._is_requirements_file(file_path):
            return []
        
        return self._run_safety_on_file(file_path)
    
    def analyze_directory(self, directory_path: Path) -> List[Finding]:
        """Analyze a directory for requirements files."""
        if not directory_path.exists() or not directory_path.is_dir():
            return []
        
        # Find requirements files
        requirements_files = []
        
        # Common requirements file patterns
        patterns = [
            "requirements.txt",
            "requirements-*.txt", 
            "dev-requirements.txt",
            "test-requirements.txt",
            "requirements/*.txt",
            "requirements/*.in",
            "Pipfile",
            "pyproject.toml",
        ]
        
        for pattern in patterns:
            for req_file in directory_path.glob(pattern):
                if req_file.is_file():
                    requirements_files.append(req_file)
        
        # Also check for virtual environment
        if self.config.get('check_environment', True):
            return self._run_safety_on_environment()
        
        # Analyze each requirements file
        all_findings = []
        for req_file in requirements_files:
            findings = self._run_safety_on_file(req_file)
            all_findings.extend(findings)
        
        return all_findings
    
    def _is_requirements_file(self, file_path: Path) -> bool:
        """Check if file is a requirements file."""
        if not file_path.exists():
            return False
        
        name = file_path.name.lower()
        
        # Check common requirements file names
        if any(pattern in name for pattern in [
            'requirements', 'req.txt', 'requirements.in', 
            'pipfile', 'pyproject.toml'
        ]):
            return True
        
        # Check if file contains dependency declarations
        try:
            content = file_path.read_text(encoding='utf-8')
            # Simple heuristic: if it contains package==version patterns
            if any(line.strip() and '==' in line for line in content.split('\n')[:10]):
                return True
        except Exception:
            pass
        
        return False
    
    def _run_safety_on_file(self, file_path: Path) -> List[Finding]:
        """Run safety on a specific requirements file."""
        try:
            cmd = ["safety", "check", "--json", "-r", str(file_path)]
            
            # Add configuration options
            if self.config.get('ignore_ids'):
                for ignore_id in self.config['ignore_ids']:
                    cmd.extend(["--ignore", str(ignore_id)])
            
            # Note: --update option removed in Safety CLI 3.x as database updates automatically
            
            self.logger.debug(f"Running safety command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            # Safety CLI 3.x returns different exit codes:
            # 0: No vulnerabilities found
            # 64: Warnings (e.g., deprecated packages) but no vulnerabilities  
            # 255: Vulnerabilities found
            if result.returncode not in [0, 64, 255]:
                error_msg = f"Safety failed with exit code {result.returncode}: {result.stderr}"
                self.logger.error(error_msg)
                raise ToolExecutionError(error_msg)
            
            return self._parse_safety_output(result.stdout, file_path)
            
        except subprocess.TimeoutExpired:
            raise ToolExecutionError("Safety analysis timed out")
        except Exception as e:
            raise ToolExecutionError(f"Failed to run safety: {e}")
    
    def _run_safety_on_environment(self) -> List[Finding]:
        """Run safety on the current Python environment."""
        try:
            cmd = ["safety", "check", "--json"]
            
            # Add configuration options
            if self.config.get('ignore_ids'):
                for ignore_id in self.config['ignore_ids']:
                    cmd.extend(["--ignore", str(ignore_id)])
            
            # Note: --update option removed in Safety CLI 3.x as database updates automatically
            
            self.logger.debug(f"Running safety on environment: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Safety CLI 3.x returns different exit codes:
            # 0: No vulnerabilities found
            # 64: Warnings (e.g., deprecated packages) but no vulnerabilities  
            # 255: Vulnerabilities found
            if result.returncode not in [0, 64, 255]:
                error_msg = f"Safety failed with exit code {result.returncode}: {result.stderr}"
                self.logger.error(error_msg)
                raise ToolExecutionError(error_msg)
            
            # For environment scan, create a virtual location
            env_location = Path("environment") / "installed_packages"
            return self._parse_safety_output(result.stdout, env_location)
            
        except subprocess.TimeoutExpired:
            raise ToolExecutionError("Safety environment analysis timed out")
        except Exception as e:
            raise ToolExecutionError(f"Failed to run safety on environment: {e}")
    
    def _parse_safety_output(self, output: str, source_file: Path) -> List[Finding]:
        """Parse safety JSON output into Finding objects."""
        findings = []
        
        try:
            if not output.strip():
                return findings
            
            vulnerabilities = json.loads(output)
            
            for vuln in vulnerabilities:
                finding = self._create_finding_from_vulnerability(vuln, source_file)
                if finding and self._should_include_finding(finding):
                    findings.append(finding)
            
            self.logger.info(f"Safety found {len(findings)} vulnerabilities in {source_file}")
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse safety output as JSON: {e}")
            self.logger.debug(f"Safety output was: {output}")
        except Exception as e:
            self.logger.error(f"Error parsing safety results: {e}")
        
        return findings
    
    def _create_finding_from_vulnerability(self, vuln: Dict[str, Any], source_file: Path) -> Optional[Finding]:
        """Create a Finding object from a safety vulnerability."""
        try:
            # Extract vulnerability information
            package = vuln.get('package', 'Unknown')
            installed_version = vuln.get('installed_version', 'Unknown')
            affected_versions = vuln.get('affected_versions', 'Unknown')
            advisory = vuln.get('advisory', '')
            vulnerability_id = vuln.get('vulnerability_id', '')
            cve = vuln.get('CVE', '')
            
            # Build title and description
            title = f"Vulnerable dependency: {package} {installed_version}"
            description = f"{advisory}\n\nAffected versions: {affected_versions}"
            if cve:
                description += f"\nCVE: {cve}"
            
            # Create location (line 1 since it's a dependency issue)
            location = Location(
                file_path=source_file,
                start_line=1,
                end_line=1
            )
            
            # Safety vulnerabilities are high confidence since they're known issues
            confidence = 0.95
            
            # Determine severity based on CVE score or default to HIGH for dependencies
            severity = self._determine_severity_from_vuln(vuln)
            
            finding = Finding(
                title=title,
                description=description,
                vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                severity=severity,
                confidence=confidence,
                confidence_level=ConfidenceLevel.VERY_HIGH,
                location=location,
                source_tool=SourceTool.SAFETY,
                rule_id=vulnerability_id,
                cwe_id=cve if cve else None,
                metadata={
                    'package': package,
                    'installed_version': installed_version,
                    'affected_versions': affected_versions,
                    'vulnerability_id': vulnerability_id,
                    'cve': cve,
                    'advisory': advisory,
                }
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error creating finding from safety vulnerability: {e}")
            self.logger.debug(f"Problematic vulnerability: {vuln}")
            return None
    
    def _determine_severity_from_vuln(self, vuln: Dict[str, Any]) -> SeverityLevel:
        """Determine severity from vulnerability data."""
        # Check if there's a severity field
        if 'severity' in vuln:
            severity_str = str(vuln['severity']).lower()
            if severity_str in ['critical', 'high']:
                return SeverityLevel.CRITICAL
            elif severity_str == 'medium':
                return SeverityLevel.HIGH
            elif severity_str == 'low':
                return SeverityLevel.MEDIUM
        
        # Check CVE for severity indicators
        cve = vuln.get('CVE', '')
        advisory = vuln.get('advisory', '').lower()
        
        # Look for severity keywords in advisory
        if any(word in advisory for word in ['critical', 'severe', 'remote code execution', 'rce']):
            return SeverityLevel.CRITICAL
        elif any(word in advisory for word in ['high', 'arbitrary code', 'injection']):
            return SeverityLevel.HIGH
        elif any(word in advisory for word in ['medium', 'moderate']):
            return SeverityLevel.MEDIUM
        elif any(word in advisory for word in ['low', 'minor']):
            return SeverityLevel.LOW
        
        # Default to HIGH for known vulnerabilities
        return SeverityLevel.HIGH
    
    def _get_severity_mapping(self) -> Dict[str, SeverityLevel]:
        """Safety-specific severity mapping."""
        return {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
        }
