"""Semgrep static analysis tool integration."""

import json
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..core.models import Finding, Location, SourceTool, SeverityLevel, VulnerabilityType, ConfidenceLevel
from .base import BaseStaticAnalyzer, ToolExecutionError


class SemgrepAnalyzer(BaseStaticAnalyzer):
    """Integration with Semgrep for multi-language static analysis."""
    
    def get_tool_name(self) -> str:
        return "semgrep"
    
    def get_source_tool(self) -> SourceTool:
        return SourceTool.SEMGREP
    
    def is_available(self) -> bool:
        """Check if semgrep is available."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def get_version(self) -> Optional[str]:
        """Get semgrep version."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def get_supported_extensions(self) -> List[str]:
        """Semgrep supports many languages."""
        return [
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", 
            ".php", ".rb", ".c", ".cpp", ".cs", ".scala", ".kt"
        ]
    
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a single file with semgrep."""
        if not self.can_analyze_file(file_path):
            return []
        
        return self._run_semgrep([str(file_path)])
    
    def analyze_directory(self, directory_path: Path) -> List[Finding]:
        """Analyze a directory with semgrep."""
        if not directory_path.exists() or not directory_path.is_dir():
            return []
        
        return self._run_semgrep([str(directory_path)])
    
    def _run_semgrep(self, paths: List[str]) -> List[Finding]:
        """Run semgrep on the given paths."""
        try:
            # Build command
            cmd = ["semgrep", "--json", "--quiet"]
            
            # Add rules configuration
            rules = self.config.get('rules', ['auto'])
            for rule in rules:
                cmd.extend(["--config", rule])
            
            # Add configuration file if specified
            if self.config.get('config_file'):
                cmd.extend(["--config", str(self.config['config_file'])])
            
            # Add exclude patterns
            exclude_patterns = self.config.get('exclude_patterns', [])
            for pattern in exclude_patterns:
                cmd.extend(["--exclude", pattern])
            
            # Add severity filter
            severity = self.config.get('severity_filter')
            if severity:
                cmd.extend(["--severity", severity])
            
            # Add paths
            cmd.extend(paths)
            
            self.logger.debug(f"Running semgrep command: {' '.join(cmd)}")
            
            # Run semgrep
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Semgrep returns exit code 1 when findings are found
            if result.returncode not in [0, 1]:
                error_msg = f"Semgrep failed with exit code {result.returncode}: {result.stderr}"
                self.logger.error(error_msg)
                raise ToolExecutionError(error_msg)
            
            return self._parse_semgrep_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            raise ToolExecutionError("Semgrep analysis timed out")
        except Exception as e:
            raise ToolExecutionError(f"Failed to run semgrep: {e}")
    
    def _parse_semgrep_output(self, output: str) -> List[Finding]:
        """Parse semgrep JSON output into Finding objects."""
        findings: List[Finding] = []
        
        try:
            if not output.strip():
                return findings
            
            data = json.loads(output)
            
            # Parse results
            for result in data.get('results', []):
                finding = self._create_finding_from_result(result)
                if finding and self._should_include_finding(finding):
                    findings.append(finding)
            
            self.logger.info(f"Semgrep found {len(findings)} issues")
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse semgrep output as JSON: {e}")
            self.logger.debug(f"Semgrep output was: {output}")
        except Exception as e:
            self.logger.error(f"Error parsing semgrep results: {e}")
        
        return findings
    
    def _create_finding_from_result(self, result: Dict[str, Any]) -> Optional[Finding]:
        """Create a Finding object from a semgrep result."""
        try:
            # Extract basic information
            rule_id = result.get('check_id', 'Unknown')
            message = result.get('message', '')
            
            # File location
            path = result.get('path', '')
            start_line = result.get('start', {}).get('line', 1)
            end_line = result.get('end', {}).get('line', start_line)
            start_col = result.get('start', {}).get('col')
            end_col = result.get('end', {}).get('col')
            
            # Severity
            severity_str = result.get('extra', {}).get('severity', 'WARNING')
            severity = self._normalize_severity(severity_str)
            
            # Vulnerability type from rule ID
            vuln_type = self._map_semgrep_rule_to_vulnerability_type(rule_id, message)
            
            # Code snippet
            code = result.get('extra', {}).get('lines', '')
            
            # Confidence based on rule source and type
            confidence = self._calculate_semgrep_confidence(result)
            
            # Create location
            location = Location(
                file_path=Path(path),
                start_line=start_line,
                end_line=end_line,
                start_column=start_col,
                end_column=end_col
            )
            
            # Create finding
            finding = Finding(
                title=f"Semgrep: {rule_id}",
                description=message,
                vulnerability_type=vuln_type,
                severity=severity,
                confidence=confidence,
                confidence_level=ConfidenceLevel.MEDIUM,
                location=location,
                source_tool=SourceTool.SEMGREP,
                rule_id=rule_id,
                code_snippet=code,
                metadata={
                    'semgrep_rule_id': rule_id,
                    'semgrep_severity': severity_str,
                    'extra': result.get('extra', {}),
                }
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error creating finding from semgrep result: {e}")
            self.logger.debug(f"Problematic result: {result}")
            return None
    
    def _calculate_semgrep_confidence(self, result: Dict[str, Any]) -> float:
        """Calculate confidence for semgrep finding."""
        # Base confidence
        confidence = 0.75
        
        # Adjust based on rule metadata
        extra = result.get('extra', {})
        
        # Check if it's from a trusted ruleset
        rule_id = result.get('check_id', '')
        if any(trusted in rule_id for trusted in ['owasp', 'cwe', 'security']):
            confidence += 0.1
        
        # Check confidence metadata
        if 'confidence' in extra:
            conf_str = str(extra['confidence']).lower()
            if conf_str == 'high':
                confidence = 0.9
            elif conf_str == 'medium':
                confidence = 0.7
            elif conf_str == 'low':
                confidence = 0.5
        
        return min(1.0, confidence)
    
    def _map_semgrep_rule_to_vulnerability_type(self, rule_id: str, message: str) -> VulnerabilityType:
        """Map semgrep rule to vulnerability type."""
        rule_lower = rule_id.lower()
        message_lower = message.lower()
        
        # SQL Injection
        if any(term in rule_lower for term in ['sql-injection', 'sqli', 'sql_injection']):
            return VulnerabilityType.SQL_INJECTION
        
        # Command Injection
        if any(term in rule_lower for term in ['command-injection', 'cmd-injection', 'shell-injection']):
            return VulnerabilityType.COMMAND_INJECTION
        
        # XSS
        if any(term in rule_lower for term in ['xss', 'cross-site-scripting']):
            return VulnerabilityType.XSS
        
        # Path Traversal
        if any(term in rule_lower for term in ['path-traversal', 'directory-traversal', 'lfi']):
            return VulnerabilityType.PATH_TRAVERSAL
        
        # Cryptographic issues
        if any(term in rule_lower for term in ['crypto', 'weak-hash', 'md5', 'sha1', 'weak-cipher']):
            return VulnerabilityType.WEAK_CRYPTOGRAPHY
        
        # Hardcoded secrets
        if any(term in rule_lower for term in ['hardcoded', 'secret', 'password', 'api-key']):
            return VulnerabilityType.HARDCODED_SECRETS
        
        # Deserialization
        if any(term in rule_lower for term in ['deserialization', 'pickle', 'yaml.load']):
            return VulnerabilityType.UNSAFE_DESERIALIZATION
        
        # Authentication/Authorization
        if any(term in rule_lower for term in ['auth', 'authz', 'access-control']):
            return VulnerabilityType.BROKEN_ACCESS_CONTROL
        
        # Check message for additional context
        if any(term in message_lower for term in ['injection', 'inject']):
            if 'sql' in message_lower:
                return VulnerabilityType.SQL_INJECTION
            elif any(term in message_lower for term in ['command', 'shell', 'os']):
                return VulnerabilityType.COMMAND_INJECTION
            else:
                return VulnerabilityType.CODE_INJECTION
        
        return VulnerabilityType.OTHER
    
    def _get_severity_mapping(self) -> Dict[str, SeverityLevel]:
        """Semgrep-specific severity mapping."""
        return {
            'error': SeverityLevel.HIGH,
            'warning': SeverityLevel.MEDIUM,
            'info': SeverityLevel.LOW,
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
        }
