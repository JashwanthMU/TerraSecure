"""
SARIF (Static Analysis Results Interchange Format) Formatter
-------------------------------------------------------------
Generates SARIF 2.1.0 format output for GitHub Security integration

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub: https://docs.github.com/en/code-security/code-scanning
"""

import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path


class SARIFFormatter:
    """
    SARIF formatter for TerraSecure scan results
    
    Converts TerraSecure findings into SARIF format compatible with:
    - GitHub Code Scanning
    - DevOps
    - GitLab Security Dashboard
    - VS Code SARIF Viewer
    """
    
    # SARIF severity mapping
    SEVERITY_MAP = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
        'info': 'note'
    }
    
    # Security severity levels (for GitHub)
    SECURITY_SEVERITY = {
        'critical': 9.0,
        'high': 7.0,
        'medium': 4.0,
        'low': 2.0,
        'info': 1.0
    }
    
    def __init__(self, tool_name: str = "TerraSecure", tool_version: str = "1.0.0"):
        """
        Initialize SARIF formatter
        
        Args:
            tool_name: Name of the scanning tool
            tool_version: Version of the scanning tool
        """
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.rules = {}  # Cache for rules
    
    def format(self, findings: List[Dict], scan_path: str = ".") -> Dict[str, Any]:
        """
        Convert TerraSecure findings to SARIF format
        
        Args:
            findings: List of security findings from TerraSecure
            scan_path: Base path that was scanned
            
        Returns:
            SARIF JSON structure
        """
        
        # Build rules from findings
        rules = self._build_rules(findings)
        
        # Build results
        results = self._build_results(findings, scan_path)
        
        # Construct SARIF document
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/JashwanthMU/TerraSecure",
                            "organization": "TerraSecure Team",
                            "semanticVersion": self.tool_version,
                            "rules": list(rules.values())
                        }
                    },
                    "results": results,
                    "automationDetails": {
                        "id": f"terrasecure/{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                    },
                    "columnKind": "utf16CodeUnits"
                }
            ]
        }
        
        return sarif
    
    def _build_rules(self, findings: List[Dict]) -> Dict[str, Dict]:
        """
        Build SARIF rules from findings
        
        Each unique rule ID gets a rule definition
        """
        rules = {}
        
        for finding in findings:
            rule_id = finding.get('rule_id', 'UNKNOWN')
            
            if rule_id not in rules:
                severity = finding.get('severity', 'medium').lower()
                
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.get('title', 'Security Finding'),
                    "shortDescription": {
                        "text": finding.get('title', 'Security issue detected')
                    },
                    "fullDescription": {
                        "text": finding.get('description', finding.get('title', ''))
                    },
                    "help": {
                        "text": self._build_help_text(finding),
                        "markdown": self._build_help_markdown(finding)
                    },
                    "defaultConfiguration": {
                        "level": self.SEVERITY_MAP.get(severity, 'warning')
                    },
                    "properties": {
                        "tags": ["security", "terraform", "iac"],
                        "precision": "high",
                        "security-severity": str(self.SECURITY_SEVERITY.get(severity, 5.0))
                    }
                }
                
                # Add CWE if available
                if 'cwe' in finding:
                    rules[rule_id]['properties']['cwe'] = finding['cwe']
        
        return rules
    
    def _build_results(self, findings: List[Dict], scan_path: str) -> List[Dict]:
        """
        Build SARIF results from findings
        """
        results = []
        
        for finding in findings:
            rule_id = finding.get('rule_id', 'UNKNOWN')
            severity = finding.get('severity', 'medium').lower()
            
            # Build location
            file_path = finding.get('file', 'unknown')
            
            # Make path relative to scan_path
            try:
                rel_path = str(Path(file_path).relative_to(scan_path))
            except (ValueError, TypeError):
                rel_path = file_path
            
            # Build result
            result = {
                "ruleId": rule_id,
                "level": self.SEVERITY_MAP.get(severity, 'warning'),
                "message": {
                    "text": finding.get('title', 'Security issue detected')
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": rel_path,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": finding.get('line', 1),
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "properties": {
                    "resource": finding.get('resource', 'unknown'),
                    "severity": severity
                }
            }
            
            # Add ML risk score if available
            if 'ml_risk_score' in finding:
                result['properties']['ml_risk_score'] = finding['ml_risk_score']
                result['properties']['ml_confidence'] = finding.get('ml_confidence', 0)
            
            # Add remediation if available
            if 'remediation' in finding:
                result['fixes'] = [
                    {
                        "description": {
                            "text": "Recommended fix"
                        },
                        "artifactChanges": [
                            {
                                "artifactLocation": {
                                    "uri": rel_path
                                },
                                "replacements": [
                                    {
                                        "deletedRegion": {
                                            "startLine": finding.get('line', 1)
                                        },
                                        "insertedContent": {
                                            "text": finding['remediation']
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            
            results.append(result)
        
        return results
    
    def _build_help_text(self, finding: Dict) -> str:
        """Build help text for rule"""
        parts = []
        
        if 'description' in finding:
            parts.append(finding['description'])
        
        if 'remediation' in finding:
            parts.append(f"\nRemediation: {finding['remediation']}")
        
        if 'references' in finding:
            parts.append(f"\nReferences: {', '.join(finding['references'])}")
        
        return '\n'.join(parts) if parts else finding.get('title', '')
    
    def _build_help_markdown(self, finding: Dict) -> str:
        """Build markdown help for rule"""
        parts = []
        
        # Title
        parts.append(f"## {finding.get('title', 'Security Finding')}")
        
        # Description
        if 'description' in finding:
            parts.append(f"\n{finding['description']}")
        
        # Severity
        severity = finding.get('severity', 'medium')
        parts.append(f"\n**Severity:** {severity.upper()}")
        
        # ML Analysis
        if 'ml_risk_score' in finding:
            risk = finding['ml_risk_score']
            conf = finding.get('ml_confidence', 0)
            parts.append(f"\n**ML Risk Score:** {risk:.0%} (confidence: {conf:.0%})")
        
        # Remediation
        if 'remediation' in finding:
            parts.append(f"\n### Remediation\n\n{finding['remediation']}")
        
        # References
        if 'references' in finding:
            parts.append("\n### References\n")
            for ref in finding['references']:
                parts.append(f"- {ref}")
        
        return '\n'.join(parts)
    
    def save(self, sarif_data: Dict, output_path: str):
        """
        Save SARIF data to file
        
        Args:
            sarif_data: SARIF JSON structure
            output_path: Path to save SARIF file
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)


def format_sarif(findings: List[Dict], scan_path: str = ".", output_path: str = None) -> Dict:
    """
    Convenience function to format findings as SARIF
    
    Args:
        findings: List of security findings
        scan_path: Base path that was scanned
        output_path: Optional path to save SARIF file
        
    Returns:
        SARIF JSON structure
    """
    formatter = SARIFFormatter()
    sarif = formatter.format(findings, scan_path)
    
    if output_path:
        formatter.save(sarif, output_path)
    
    return sarif



if __name__ == '__main__':

    sample_findings = [
        {
            'rule_id': 'AWS-S3-001',
            'title': 'S3 bucket with public access',
            'description': 'S3 bucket is publicly accessible',
            'severity': 'critical',
            'file': 'main.tf',
            'line': 10,
            'resource': 'aws_s3_bucket.example',
            'ml_risk_score': 0.95,
            'ml_confidence': 0.92,
            'remediation': 'Set acl = "private" and enable block_public_access',
            'references': [
                'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html'
            ]
        }
    ]
    

    sarif = format_sarif(sample_findings, scan_path=".", output_path="test.sarif")
    
    print(" SARIF formatted successfully!")
    print(f"   Rules: {len(sarif['runs'][0]['tool']['driver']['rules'])}")
    print(f"   Results: {len(sarif['runs'][0]['results'])}")