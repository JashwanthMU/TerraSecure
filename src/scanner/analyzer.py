import os
import json
from typing import Dict, List, Any
from pathlib import Path
from scanner.parser import TerraformParser
from rules.security_rules import SecurityRules


# Machine Learning
try:
    from ml.ml_analyzer import MLAnalyzer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("   ML analyzer not available")

# LLM Integration - Try Bedrock first, fallback to legacy
LLM_AVAILABLE = False
LLMAnalyzer = None

try:
    from llm.bedrock_analyzer import BedrockAnalyzer
    LLMAnalyzer = BedrockAnalyzer
    LLM_AVAILABLE = True
    print("  Using AWS Bedrock (Claude 3 Haiku)")
except ImportError as e:
    print(f"   Bedrock not available: {e}")
    try:
        from llm.llm_analyzer import LLMAnalyzer
        LLM_AVAILABLE = True
        print("  Using legacy LLM fallback")
    except ImportError:
        print("   No LLM available - using rule-based detection only")
        LLM_AVAILABLE = False
class SecurityAnalyzer:
    """Analyzes Terraform resources for security issues"""
    
    def __init__(self):
        """Initialize security analyzer with all components"""
    
        # Initialize ML analyzer
        if ML_AVAILABLE:
            try:
                self.ml_analyzer = MLAnalyzer()
            except Exception as e:
                print(f"   Failed to initialize ML: {e}")
                self.ml_analyzer = None
        else:
            self.ml_analyzer = None
    
        # Initialize LLM analyzer
        if LLM_AVAILABLE and LLMAnalyzer:
            try:
                self.llm_analyzer = LLMAnalyzer()
            except Exception as e:
                print(f"   Failed to initialize LLM: {e}")
                self.llm_analyzer = None
        else:
            self.llm_analyzer = None
    
        # Initialize parsers and rules
        self.parser = TerraformParser()
        self.rules = SecurityRules()
    
    def scan_file(self, filepath):
        """Scan a single file"""
        resources = self.parser.parse_file(filepath)
        return self._analyze_resources(resources)
    
    def scan_directory(self, directory):
        """Scan all .tf files in directory"""
        resources = self.parser.parse_directory(directory)
        return self._analyze_resources(resources)
    
    def _analyze_resources(self, resources: List[Dict]) -> Dict:
        """Analyze parsed resources for security issues"""
    
        issues = []
        stats = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
    
        for resource in resources:
            resource_type = resource.get('type', 'unknown')
            resource_name = resource.get('name', 'unknown')
        
            # Get rules - handle different SecurityRules implementations
            if hasattr(self.rules, 'items'):
                rules_dict = dict(self.rules.items())
            elif hasattr(self.rules, 'get_all_rules'):
                rules_dict = self.rules.get_all_rules()
            elif hasattr(self.rules, 'rules'):
                rules_dict = self.rules.rules
            else:
                print(f"⚠️  Warning: SecurityRules has no accessible rules")
                rules_dict = {}
        
            # Apply each rule
            for rule_name, rule_func in rules_dict.items():
                try:
                    finding = rule_func(resource)
                
                    if finding:
                        # Get ML risk score
                        ml_result = {}
                        if self.ml_analyzer:
                            try:
                                ml_result = self.ml_analyzer.analyze(resource)
                            except Exception as e:
                                print(f"⚠️  ML analysis failed: {e}")
                    
                        # Get LLM explanation
                        llm_result = {}
                        if self.llm_analyzer:
                            try:
                                llm_result = self.llm_analyzer.enhance_finding(
                                    resource, ml_result, finding
                                )
                            except Exception as e:
                                print(f"⚠️  LLM analysis failed: {e}")
                    
                        # Combine results
                        issue = {
                            **finding,
                            'resource_type': resource_type,
                            'resource_name': resource_name,
                            **ml_result,
                            **llm_result
                        }
                    
                        issues.append(issue)
                    
                        # Update stats
                        severity = finding.get('severity', 'MEDIUM')
                        stats[severity] = stats.get(severity, 0) + 1
                    
                except Exception as e:
                    print(f"⚠️  Error applying rule {rule_name}: {e}")
                    continue
    
        return {
            'issues': issues,
            'stats': stats,
            'total_resources': len(resources),
            'passed': len(resources) - len(issues)
        }
    
    def _default_ml_result(self):
        """Default ML result when ML unavailable"""
        return {
            'ml_risk_score': 0.5,
            'ml_confidence': 0.0,
            'ml_prediction': 'N/A',
            'triggered_features': []
        }
    
    def _check_rule(self, resource, rule):
        """Check if resource violates rule"""
        
        pattern = rule['pattern']

        if resource['type'] != pattern['resource_type']:
            return False

        for condition in pattern['conditions']:
            if not self._check_condition(resource, condition):
                return False
        
        return True
    
    def _check_condition(self, resource, condition):
        """Check individual condition"""
        
        prop_name = condition['property']
        props = resource.get('properties', {})

        if '.' in prop_name:
            value = self.parser.extract_property(resource, prop_name)
        else:
            value = props.get(prop_name)

        if 'absent' in condition:
            return (value is None) == condition['absent']

        if 'equals' in condition:
            return value == condition['equals']

        if 'contains' in condition:
            search_terms = condition['contains']
            if isinstance(search_terms, str):
                search_terms = [search_terms]
            
            if isinstance(value, str):
                return any(term in value.lower() for term in search_terms)
            elif isinstance(value, list):
                value_str = str(value).lower()
                return any(term in value_str for term in search_terms)
        
        if 'less_than' in condition:
            try:
                return int(value or 0) < condition['less_than']
            except:
                return False
        
        return False