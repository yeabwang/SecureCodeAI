"""Output formatting utilities."""

import json
from typing import Dict, Any
from pathlib import Path
from datetime import datetime

from ..core.models import AnalysisResult, Finding, OutputFormat
from ..core.config import OutputConfig


class OutputFormatter:
    """Formats analysis results for different output formats."""
    
    def __init__(self, config: OutputConfig):
        self.config = config
    
    def format_result(self, result: AnalysisResult) -> str:
        """Format analysis result according to configuration."""
        if self.config.format == OutputFormat.JSON:
            return self._format_json(result)
        elif self.config.format == OutputFormat.SARIF:
            return self._format_sarif(result)
        elif self.config.format == OutputFormat.HTML:
            return self._format_html(result)
        elif self.config.format == OutputFormat.MARKDOWN:
            return self._format_markdown(result)
        else:  # Default to table
            return self._format_table(result)
    
    def _format_table(self, result: AnalysisResult) -> str:
        """Format as a human-readable table."""
        output = []
        
        # Header
        output.append("SecureCodeAI Analysis Results")
        output.append("=" * 50)
        output.append("")
        
        # Summary
        duration_str = f"{result.duration_seconds:.2f}" if result.duration_seconds is not None else "Unknown"
        output.append(f"Analysis completed in {duration_str} seconds")
        output.append(f"Files analyzed: {result.total_files_analyzed}")
        output.append(f"Total findings: {len(result.findings)}")
        output.append("")
        
        # Statistics
        if self.config.show_statistics and result.findings:
            output.append("Findings by Severity:")
            for severity, count in result.findings_by_severity.items():
                output.append(f"  {severity.value.capitalize()}: {count}")
            output.append("")
            
            output.append("Findings by Tool:")
            for tool, count in result.findings_by_tool.items():
                output.append(f"  {tool.value.capitalize()}: {count}")
            output.append("")
        
        # Findings
        if result.findings:
            # Sort findings
            sorted_findings = sorted(
                result.findings,
                key=lambda f: (
                    ['info', 'low', 'medium', 'high', 'critical'].index(f.severity.value),
                    -(f.confidence if f.confidence is not None else 0.0)
                ),
                reverse=True
            )
            
            output.append("Detailed Findings:")
            output.append("-" * 20)
            
            for i, finding in enumerate(sorted_findings, 1):
                output.append(f"\n{i}. {finding.title}")
                output.append(f"   Severity: {finding.severity.value.upper()}")
                
                # Handle potential None confidence values
                confidence_str = f"{finding.confidence:.2f}" if finding.confidence is not None else "Unknown"
                output.append(f"   Confidence: {confidence_str}")
                
                output.append(f"   Location: {finding.location.file_path}:{finding.location.start_line}")
                output.append(f"   Type: {finding.vulnerability_type.value}")
                
                if finding.description:
                    # Truncate long descriptions
                    desc = finding.description[:200] + "..." if len(finding.description) > 200 else finding.description
                    output.append(f"   Description: {desc}")
                
                if self.config.include_code_snippets and finding.code_snippet:
                    output.append("   Code:")
                    code_lines = finding.code_snippet.split('\n')
                    for line in code_lines[:5]:  # Show first 5 lines
                        output.append(f"     {line}")
                    if len(code_lines) > 5:
                        output.append("     ...")
        else:
            output.append("No security issues found! 🎉")
        
        return "\n".join(output)
    
    def _format_json(self, result: AnalysisResult) -> str:
        """Format as JSON."""
        # Convert to dict and handle serialization
        data = result.dict()
        
        # Convert Path objects to strings
        def convert_paths(obj):
            if isinstance(obj, dict):
                return {k: convert_paths(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_paths(item) for item in obj]
            elif isinstance(obj, Path):
                return str(obj)
            else:
                return obj
        
        data = convert_paths(data)
        
        return json.dumps(data, indent=2, default=str)
    
    def _format_sarif(self, result: AnalysisResult) -> str:
        """Format as SARIF (Static Analysis Results Interchange Format)."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecureCodeAI",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/yeabwang/securecodeai",
                            "rules": []
                        }
                    },
                    "artifacts": [],
                    "results": []
                }
            ]
        }
        
        run = sarif["runs"][0]
        
        # Add rules (unique vulnerability types found)
        rules_seen = set()
        for finding in result.findings:
            rule_id = finding.vulnerability_type.value
            if rule_id not in rules_seen:
                rules_seen.add(rule_id)
                run["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": finding.vulnerability_type.value.replace('_', ' ').title(),
                    "shortDescription": {
                        "text": finding.vulnerability_type.value.replace('_', ' ').title()
                    }
                })
        
        # Add artifacts (files)
        artifacts_seen = set()
        for finding in result.findings:
            file_path = str(finding.location.file_path)
            if file_path not in artifacts_seen:
                artifacts_seen.add(file_path)
                run["artifacts"].append({
                    "location": {
                        "uri": file_path
                    }
                })
        
        # Add results
        for finding in result.findings:
            level = {
                'info': 'note',
                'low': 'note', 
                'medium': 'warning',
                'high': 'error',
                'critical': 'error'
            }.get(finding.severity.value, 'warning')
            
            result_obj = {
                "ruleId": finding.vulnerability_type.value,
                "message": {
                    "text": finding.description
                },
                "level": level,
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(finding.location.file_path)
                            },
                            "region": {
                                "startLine": finding.location.start_line,
                                "endLine": finding.location.end_line or finding.location.start_line
                            }
                        }
                    }
                ]
            }
            
            if finding.code_snippet:
                result_obj["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": finding.code_snippet
                }
            
            run["results"].append(result_obj)
        
        return json.dumps(sarif, indent=2)
    
    def _format_html(self, result: AnalysisResult) -> str:
        """Format as HTML report."""
        # Simple HTML template for now
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SecureCodeAI Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #17a2b8; }}
        .info {{ border-left: 5px solid #6c757d; }}
        .code {{ background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SecureCodeAI Security Report</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Analysis completed in {result.duration_seconds:.2f} seconds</p>
        <p>Files analyzed: {result.total_files_analyzed}</p>
        <p>Total findings: {len(result.findings)}</p>
    </div>
"""
        
        if result.findings:
            html += "<h2>Findings</h2>"
            
            sorted_findings = sorted(
                result.findings,
                key=lambda f: (['info', 'low', 'medium', 'high', 'critical'].index(f.severity.value), -f.confidence),
                reverse=True
            )
            
            for finding in sorted_findings:
                html += f"""
    <div class="finding {finding.severity.value}">
        <h3>{finding.title}</h3>
        <p><strong>Severity:</strong> {finding.severity.value.upper()}</p>
        <p><strong>Confidence:</strong> {finding.confidence:.2f}</p>
        <p><strong>Location:</strong> {finding.location.file_path}:{finding.location.start_line}</p>
        <p><strong>Type:</strong> {finding.vulnerability_type.value}</p>
        <p><strong>Description:</strong> {finding.description}</p>
"""
                
                if self.config.include_code_snippets and finding.code_snippet:
                    html += f"""
        <div class="code">
            <strong>Code:</strong><br>
            <pre>{finding.code_snippet}</pre>
        </div>
"""
                
                html += "    </div>"
        else:
            html += "<p>No security issues found! 🎉</p>"
        
        html += """
</body>
</html>"""
        
        return html
    
    def _format_markdown(self, result: AnalysisResult) -> str:
        """Format as Markdown."""
        output = []
        
        # Header
        output.append("# SecureCodeAI Security Report")
        output.append("")
        output.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"**Analysis Time:** {result.duration_seconds:.2f} seconds" if result.duration_seconds is not None else "**Analysis Time:** Unknown")
        output.append(f"**Files Analyzed:** {result.total_files_analyzed}")
        output.append(f"**Total Findings:** {len(result.findings)}")
        output.append("")
        
        # Summary
        if result.findings:
            output.append("## Summary")
            output.append("")
            output.append("| Severity | Count |")
            output.append("|----------|-------|")
            for severity, count in result.findings_by_severity.items():
                output.append(f"| {severity.value.capitalize()} | {count} |")
            output.append("")
            
            # Findings
            output.append("## Findings")
            output.append("")
            
            sorted_findings = sorted(
                result.findings,
                key=lambda f: (['info', 'low', 'medium', 'high', 'critical'].index(f.severity.value), -f.confidence),
                reverse=True
            )
            
            for i, finding in enumerate(sorted_findings, 1):
                severity_emoji = {
                    'critical': '🔴',
                    'high': '🟠', 
                    'medium': '🟡',
                    'low': '🔵',
                    'info': '⚪'
                }.get(finding.severity.value, '❓')
                
                output.append(f"### {i}. {finding.title} {severity_emoji}")
                output.append("")
                output.append(f"- **Severity:** {finding.severity.value.upper()}")
                output.append(f"- **Confidence:** {finding.confidence:.2f}" if finding.confidence is not None else "- **Confidence:** Unknown")
                output.append(f"- **Location:** `{finding.location.file_path}:{finding.location.start_line}`")
                output.append(f"- **Type:** {finding.vulnerability_type.value}")
                output.append("")
                output.append(f"**Description:** {finding.description}")
                
                if self.config.include_code_snippets and finding.code_snippet:
                    output.append("")
                    output.append("**Code:**")
                    output.append("```")
                    output.append(finding.code_snippet)
                    output.append("```")
                
                output.append("")
        else:
            output.append("## Results")
            output.append("")
            output.append("No security issues found! 🎉")
        
        return "\n".join(output)
