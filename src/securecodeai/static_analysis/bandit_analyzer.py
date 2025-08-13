"""Bandit static analysis tool integration."""

import json
import subprocess
import tempfile
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..core.models import Finding, Location, SourceTool, SeverityLevel, VulnerabilityType, ConfidenceLevel
from .base import BaseStaticAnalyzer, ToolExecutionError


class BanditAnalyzer(BaseStaticAnalyzer):
    """Integration with Bandit security linter for Python."""
    
    def get_tool_name(self) -> str:
        return "bandit"
    
    def get_source_tool(self) -> SourceTool:
        return SourceTool.BANDIT
    
    def is_available(self) -> bool:
        """Check if bandit is available."""
        try:
            result = subprocess.run(
                ["bandit", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def get_version(self) -> Optional[str]:
        """Get bandit version."""
        try:
            result = subprocess.run(
                ["bandit", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                # Extract version from output like "bandit 1.7.5"
                return result.stdout.strip().split()[-1]
        except Exception:
            pass
        return None
    
    def get_supported_extensions(self) -> List[str]:
        """Bandit analyzes Python files."""
        return [".py"]
    
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a single Python file with bandit."""
        if not self.can_analyze_file(file_path):
            return []
        
        return self._run_bandit([str(file_path)])
    
    def analyze_directory(self, directory_path: Path) -> List[Finding]:
        """Analyze a directory with bandit."""
        if not directory_path.exists() or not directory_path.is_dir():
            return []
        
        return self._run_bandit([str(directory_path)])
    
    def _run_bandit(self, paths: List[str]) -> List[Finding]:
        """Run bandit on the given paths."""
        try:
            # Build command
            cmd = ["bandit", "-f", "json", "-r"] + paths
            
            # Add configuration options
            if self.config.get('skip_tests', True):
                cmd.extend(["-s", "B101,B601"])  # Skip assert and shell usage in tests
            
            if self.config.get('exclude_paths'):
                for exclude in self.config['exclude_paths']:
                    cmd.extend(["-x", exclude])
            
            if self.config.get('config_file'):
                cmd.extend(["-c", str(self.config['config_file'])])
            
            # Add severity level
            severity_level = self.config.get('severity_level', 'low')
            cmd.extend(["-l"])
            
            # Add confidence level
            confidence_level = self.config.get('confidence_level', 'low') 
            cmd.extend(["-i"])
            
            self.logger.debug(f"Running bandit command: {' '.join(cmd)}")
            
            # Run bandit
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Bandit returns non-zero exit code when issues are found
            # Only treat it as error if it's not 1 (which means issues found)
            if result.returncode not in [0, 1]:
                error_msg = f"Bandit failed with exit code {result.returncode}: {result.stderr}"
                self.logger.error(error_msg)
                raise ToolExecutionError(error_msg)
            
            return self._parse_bandit_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            raise ToolExecutionError("Bandit analysis timed out")
        except Exception as e:
            raise ToolExecutionError(f"Failed to run bandit: {e}")
    
    def _parse_bandit_output(self, output: str) -> List[Finding]:
        """Parse bandit JSON output into Finding objects."""
        findings = []
        
        try:
            if not output.strip():
                return findings
            
            data = json.loads(output)
            
            # Parse results
            for result in data.get('results', []):
                finding = self._create_finding_from_result(result)
                if finding and self._should_include_finding(finding):
                    findings.append(finding)
            
            self.logger.info(f"Bandit found {len(findings)} issues")
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse bandit output as JSON: {e}")
            self.logger.debug(f"Bandit output was: {output}")
        except Exception as e:
            self.logger.error(f"Error parsing bandit results: {e}")
        
        return findings
    
    def _create_finding_from_result(self, result: Dict[str, Any]) -> Optional[Finding]:
        """Create a Finding object from a bandit result."""
        try:
            # Extract basic information
            test_id = result.get('test_id', 'Unknown')
            test_name = result.get('test_name', 'Unknown Test')
            issue_text = result.get('issue_text', '')
            
            # File location
            filename = result.get('filename', '')
            line_number = result.get('line_number', 1)
            
            # Severity and confidence
            severity = self._normalize_severity(result.get('issue_severity', 'MEDIUM'))
            confidence_str = result.get('issue_confidence', 'MEDIUM')
            confidence = self._map_bandit_confidence(confidence_str)
            
            # Vulnerability type
            vuln_type = self._map_bandit_test_to_vulnerability_type(test_id, test_name)
            
            # Code context
            code = result.get('code', '')
            
            # Create location
            location = Location(
                file_path=Path(filename),
                start_line=line_number,
                end_line=line_number
            )
            
            # Create finding
            finding = Finding(
                title=f"Bandit {test_id}: {test_name}",
                description=issue_text,
                vulnerability_type=vuln_type,
                severity=severity,
                confidence=confidence,
                confidence_level=ConfidenceLevel.MEDIUM,  # Will be auto-calculated by validator
                location=location,
                source_tool=SourceTool.BANDIT,
                rule_id=test_id,
                code_snippet=code,
                metadata={
                    'bandit_test_id': test_id,
                    'bandit_test_name': test_name,
                    'bandit_confidence': confidence_str,
                    'bandit_severity': result.get('issue_severity'),
                }
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error creating finding from bandit result: {e}")
            self.logger.debug(f"Problematic result: {result}")
            return None
    
    def _map_bandit_confidence(self, bandit_confidence: str) -> float:
        """Map bandit confidence to float value."""
        confidence_map = {
            'HIGH': 0.9,
            'MEDIUM': 0.7,
            'LOW': 0.5,
        }
        return confidence_map.get(bandit_confidence.upper(), 0.7)
    
    def _map_bandit_test_to_vulnerability_type(self, test_id: str, test_name: str) -> VulnerabilityType:
        """Map bandit test IDs to vulnerability types."""
        # Mapping based on bandit test IDs
        mapping = {
            # Injection
            'B602': VulnerabilityType.COMMAND_INJECTION,  # subprocess_popen_with_shell_equals_true
            'B603': VulnerabilityType.COMMAND_INJECTION,  # subprocess_without_shell_equals_true
            'B604': VulnerabilityType.COMMAND_INJECTION,  # any_other_function_with_shell_equals_true
            'B605': VulnerabilityType.COMMAND_INJECTION,  # start_process_with_a_shell
            'B606': VulnerabilityType.COMMAND_INJECTION,  # start_process_with_no_shell
            'B607': VulnerabilityType.COMMAND_INJECTION,  # start_process_with_partial_path
            'B608': VulnerabilityType.SQL_INJECTION,      # hardcoded_sql_expressions
            'B201': VulnerabilityType.CODE_INJECTION,     # flask_debug_true
            
            # Cryptography
            'B301': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # pickle
            'B302': VulnerabilityType.UNSAFE_DESERIALIZATION,  # marshal
            'B303': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # md5
            'B304': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # des
            'B305': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # cipher
            'B306': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # mktemp_q
            'B307': VulnerabilityType.CODE_INJECTION,     # eval
            'B308': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # mark_safe
            'B309': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # httpsconnection
            'B310': VulnerabilityType.PATH_TRAVERSAL,     # urllib_urlopen
            'B311': VulnerabilityType.INSECURE_RANDOMNESS, # random
            'B312': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # telnetlib
            'B313': VulnerabilityType.CODE_INJECTION,     # xml_bad_cElementTree
            'B314': VulnerabilityType.CODE_INJECTION,     # xml_bad_ElementTree
            'B315': VulnerabilityType.CODE_INJECTION,     # xml_bad_expatreader
            'B316': VulnerabilityType.CODE_INJECTION,     # xml_bad_expatbuilder
            'B317': VulnerabilityType.CODE_INJECTION,     # xml_bad_sax
            'B318': VulnerabilityType.CODE_INJECTION,     # xml_bad_minidom
            'B319': VulnerabilityType.CODE_INJECTION,     # xml_bad_pulldom
            'B320': VulnerabilityType.CODE_INJECTION,     # xml_bad_xmlrpc
            'B321': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # ftplib
            'B322': VulnerabilityType.CODE_INJECTION,     # input
            'B323': VulnerabilityType.UNSAFE_DESERIALIZATION, # unverified_context
            
            # Hardcoded secrets
            'B105': VulnerabilityType.HARDCODED_SECRETS,  # hardcoded_password_string
            'B106': VulnerabilityType.HARDCODED_SECRETS,  # hardcoded_password_funcarg
            'B107': VulnerabilityType.HARDCODED_SECRETS,  # hardcoded_password_default
            'B108': VulnerabilityType.HARDCODED_SECRETS,  # hardcoded_tmp_directory
            
            # Security misconfiguration
            'B101': VulnerabilityType.SECURITY_MISCONFIGURATION,  # assert_used
            'B102': VulnerabilityType.CODE_INJECTION,             # exec_used
            'B103': VulnerabilityType.INSECURE_DEFAULTS,          # set_bad_file_permissions
            'B104': VulnerabilityType.BROKEN_ACCESS_CONTROL,      # hardcoded_bind_all_interfaces
            'B110': VulnerabilityType.CODE_INJECTION,             # try_except_pass
            'B112': VulnerabilityType.DENIAL_OF_SERVICE,          # try_except_continue
            
            # Others
            'B501': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # request_with_no_cert_validation
            'B502': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # ssl_with_bad_version
            'B503': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # ssl_with_bad_defaults
            'B504': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # ssl_with_no_version
            'B505': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # weak_cryptographic_key
            'B506': VulnerabilityType.WEAK_CRYPTOGRAPHY,  # yaml_load
            'B507': VulnerabilityType.XSS,               # ssh_no_host_key_verification
            'B601': VulnerabilityType.COMMAND_INJECTION,  # paramiko_calls
            'B701': VulnerabilityType.SECURITY_MISCONFIGURATION,  # jinja2_autoescape_false
            'B702': VulnerabilityType.SECURITY_MISCONFIGURATION,  # use_of_mako_templates
            'B703': VulnerabilityType.SECURITY_MISCONFIGURATION,  # django_mark_safe
        }
        
        return mapping.get(test_id, VulnerabilityType.OTHER)
    
    def _get_severity_mapping(self) -> Dict[str, SeverityLevel]:
        """Bandit-specific severity mapping."""
        return {
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM, 
            'low': SeverityLevel.LOW,
        }
