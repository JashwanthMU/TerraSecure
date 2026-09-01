import json
from typing import List, Dict, Any


class SARIFFormatter:

    def __init__(self, tool_name: str = "TerraSecure", tool_version: str = "2.1.0"):
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
                    "results": results,
                    "properties": {
                        "cloudBreakdown": self._cloud_breakdown(findings)
                    }
                }
            ]
        }

        return sarif

    SECURITY_SEVERITY = {
        'critical': '9.0',
        'high': '7.0',
        'medium': '4.0',
        'low': '1.0',
    }

    def _finding_title(self, finding: Dict[str, Any]) -> str:
        """Rule engines emit 'message', not 'title'/'description'. Fall back
        through both so real finding text reaches SARIF instead of the
        generic 'Security Issue' placeholder."""
        return finding.get('title') or finding.get('message', 'Security misconfiguration detected')

    def _finding_resource_name(self, finding: Dict[str, Any]) -> str:
        """Analyzer sets 'resource_name', not 'resource'."""
        return finding.get('resource') or finding.get('resource_name', 'unknown')

    def _cloud_breakdown(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        breakdown: Dict[str, int] = {}
        for finding in findings:
            cloud = finding.get('cloud', 'unknown')
            breakdown[cloud] = breakdown.get(cloud, 0) + 1
        return breakdown

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

                cloud = finding.get('cloud', 'unknown')
                title = self._finding_title(finding)

                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": title,
                    "shortDescription": {
                        "text": title
                    },
                    "fullDescription": {
                        "text": finding.get('description', title)
                    },
                    "defaultConfiguration": {
                        "level": sarif_level
                    },
                    "help": {
                        "text": finding.get('remediation', 'Review and fix this security issue'),
                        "markdown": finding.get('remediation', 'Review and fix this security issue')
                    },
                    "properties": {
                        # 'cloud' lets GitHub's Security tab and any SARIF
                        # consumer filter/group findings by provider.
                        "tags": ["security", "terraform", "iac", cloud],
                        "cloud": cloud,
                        # Standard GitHub code-scanning convention: a
                        # 0.0-10.0 score (as a string) used to rank and
                        # color-code findings in the Security tab.
                        "security-severity": self.SECURITY_SEVERITY.get(severity, '4.0'),
                        "precision": "high"
                    }
                }

        return list(rules_dict.values())

    def _build_results(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        results = []

        for finding in findings:
            rule_id = finding.get('rule_id', 'TERRAFORM-SECURITY')
            severity = finding.get('severity', 'warning').lower()
            cloud = finding.get('cloud', 'unknown')

            sarif_level = {
                'critical': 'error',
                'high': 'error',
                'medium': 'warning',
                'low': 'note'
            }.get(severity, 'warning')

            line_number = max(1, finding.get('line', 1))
            message_text = self._finding_title(finding)
            if finding.get('references'):
                refs = finding['references']
                if isinstance(refs, list) and refs:
                    message_text += "\n\n" + "\n".join(refs)

            properties = {
                "cloud": cloud
            }
            # Only attach ML properties when ML actually ran on this
            # finding (AWS-only today). Defaulting to 0.5/0.5 for every
            # provider would fabricate a score for Azure/GCP findings
            # that were never scored by the model.
            if 'ml_risk_score' in finding:
                properties["ml_risk_score"] = finding.get('ml_risk_score')
                properties["ml_confidence"] = finding.get('ml_confidence', 0.0)

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
                                "name": self._finding_resource_name(finding),
                                "kind": "resource"
                            }
                        ]
                    }
                ],
                "properties": properties
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
                 tool_version: str = "2.1.0",
                 scan_path: str = ".") -> Dict[str, Any]:
    formatter = SARIFFormatter(tool_name, tool_version)
    return formatter.format(findings, scan_path)