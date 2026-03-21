"""
SARIF Formatter for TerraSecure
--------------------------------
Generates SARIF 2.1.0 output for GitHub Security integration
"""

import json
from typing import List, Dict, Any


class SARIFFormatter:
    """
    Format security findings as SARIF 2.1.0
    
    SARIF (Static Analysis Results Interchange Format) is the standard
    format for security findings in GitHub Security tab.
    """
    
    def __init__(self, tool_name: str = "TerraSecure", tool_version: str = "2.0.0"):
        """
        Initialize SARIF formatter
        
        Args:
            tool_name: Name of the security tool
            tool_version: Version of the tool
        """
        self.tool_name = tool_name
        self.tool_version = tool_version
    
    def format(self, findings: List[Dict[str, Any]], scan_path: str = ".") -> Dict[str, Any]:
        """
        Format findings as SARIF 2.1.0
        
        Args:
            findings: List of security findings
            scan_path: Path that was scanned
            
        Returns:
            SARIF-formatted output as dict
        """
        
        # Build rules from unique findings
        rules = self._build_rules(findings)
        
        # Build results
        results = self._build_results(findings)
        
        # Build SARIF document
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/JashwanthMU/TerraSecure",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }
        
        return sarif
    
    def _build_rules(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build SARIF rules from findings"""
        
        rules_dict = {}
        
        for finding in findings:
            rule_id = finding.get('rule_id', 'TERRAFORM-SECURITY')
            
            if rule_id not in rules_dict:
                severity = finding.get('severity', 'warning').lower()
                
                # Map severity to SARIF level
                sarif_level = {
                    'critical': 'error',
                    'high': 'error',
                    'medium': 'warning',
                    'low': 'note'
                }.get(severity, 'warning')
                
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": finding.get('title', 'Security Issue'),
                    "shortDescription": {
                        "text": finding.get('title', 'Security misconfiguration detected')
                    },
                    "fullDescription": {
                        "text": finding.get('description', finding.get('title', 'Security issue'))
                    },
                    "defaultConfiguration": {
                        "level": sarif_level
                    },
                    "help": {
                        "text": finding.get('remediation', 'Review and fix this security issue'),
                        "markdown": finding.get('remediation', 'Review and fix this security issue')
                    },
                    "properties": {
                        "tags": ["security", "terraform", "iac"],
                        "precision": "high"
                    }
                }
        
        return list(rules_dict.values())
    
    def _build_results(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build SARIF results from findings"""
        
        results = []
        
        for finding in findings:
            rule_id = finding.get('rule_id', 'TERRAFORM-SECURITY')
            severity = finding.get('severity', 'warning').lower()
            
            # Map severity to SARIF level
            sarif_level = {
                'critical': 'error',
                'high': 'error',
                'medium': 'warning',
                'low': 'note'
            }.get(severity, 'warning')
            
            # Ensure line number is >= 1 (GitHub requirement)
            line_number = max(1, finding.get('line', 1))
            
            # Build result
            result = {
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {
                    "text": finding.get('title', 'Security issue detected')
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get('file', 'unknown'),
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": line_number,  # ← FIXED: Always >= 1
                                "startColumn": 1
                            }
                        },
                        "logicalLocations": [
                            {
                                "name": finding.get('resource', 'unknown'),
                                "kind": "resource"
                            }
                        ]
                    }
                ],
                "properties": {
                    "ml_risk_score": finding.get('ml_risk_score', 0.5),
                    "ml_confidence": finding.get('ml_confidence', 0.5)
                }
            }
            
            # Add remediation if available
            if finding.get('remediation'):
                result["fixes"] = [
                    {
                        "description": {
                            "text": "Apply security fix"
                        },
                        "artifactChanges": [
                            {
                                "artifactLocation": {
                                    "uri": finding.get('file', 'unknown'),
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "replacements": [
                                    {
                                        "deletedRegion": {
                                            "startLine": line_number  # ← FIXED: Always >= 1
                                        },
                                        "insertedContent": {
                                            "text": finding.get('remediation', '')
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            
            # Add references if available
            if finding.get('references'):
                result["relatedLocations"] = []
                for ref in finding['references']:
                    result["relatedLocations"].append({
                        "message": {
                            "text": ref
                        }
                    })
            
            results.append(result)
        
        return results


def format_sarif(findings: List[Dict[str, Any]], 
                 tool_name: str = "TerraSecure",
                 tool_version: str = "2.0.0",
                 scan_path: str = ".") -> Dict[str, Any]:
    """
    Convenience function to format findings as SARIF
    
    Args:
        findings: List of security findings
        tool_name: Name of the security tool
        tool_version: Version of the tool
        scan_path: Path that was scanned
        
    Returns:
        SARIF-formatted output as dict
    """
    formatter = SARIFFormatter(tool_name, tool_version)
    return formatter.format(findings, scan_path)