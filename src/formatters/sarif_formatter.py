import json
from typing import List, Dict, Any


class SARIFFormatter:
    
    def __init__(self, tool_name: str = "TerraSecure", tool_version: str = "2.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version
    
    def format(self, findings: List[Dict[str, Any]], scan_path: str = ".") -> Dict[str, Any]:

        rules = self._build_rules(findings)
        results = self._build_results(findings)
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
        
        results = []
        
        for finding in findings:
            rule_id = finding.get('rule_id', 'TERRAFORM-SECURITY')
            severity = finding.get('severity', 'warning').lower()
            
            sarif_level = {
                'critical': 'error',
                'high': 'error',
                'medium': 'warning',
                'low': 'note'
            }.get(severity, 'warning')

            line_number = max(1, finding.get('line', 1))
            message_text = finding.get('title', 'Security issue detected')
            if finding.get('references'):
                refs = finding['references']
                if isinstance(refs, list) and refs:
                    message_text += "\n\n" + "\n".join(refs)

            result = {
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {
                    "text": message_text
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get('file', 'unknown'),
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": line_number,
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
                                            "startLine": line_number
                                        },
                                        "insertedContent": {
                                            "text": finding.get('remediation', '')[:500]  
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            
            results.append(result)
        
        return results


def format_sarif(findings: List[Dict[str, Any]], 
                 tool_name: str = "TerraSecure",
                 tool_version: str = "2.0.0",
                 scan_path: str = ".") -> Dict[str, Any]:
    formatter = SARIFFormatter(tool_name, tool_version)
    return formatter.format(findings, scan_path)
