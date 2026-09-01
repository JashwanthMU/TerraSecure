import os
import json
from typing import Dict, List, Any
from pathlib import Path
from scanner.parser import TerraformParser
from scanner.provider_detector import detect_provider
from rules import RULE_ENGINES


try:
    from ml.ml_analyzer import MLAnalyzer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("   ML analyzer not available")

# LLM Integration - Try Bedrock first
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
    """Analyzes Terraform resources for security issues across AWS, Azure, and GCP"""

    # The ML model (XGBoost, 50 engineered features) was trained on
    # AWS breach data only (Capital One, Uber, Tesla, MongoDB). Its
    # feature extractor assumes AWS resource shapes, so it is only
    # applied to resources detected as 'aws'. Azure/GCP findings are
    # rule-engine-only until provider-specific feature extractors and
    # models exist.
    ML_SUPPORTED_PROVIDERS = {"aws"}

    def __init__(self):
        """Initialize security analyzer with all components"""

        if ML_AVAILABLE:
            try:
                self.ml_analyzer = MLAnalyzer()
            except Exception as e:
                print(f"   Failed to initialize ML: {e}")
                self.ml_analyzer = None
        else:
            self.ml_analyzer = None

        if LLM_AVAILABLE and LLMAnalyzer:
            try:
                self.llm_analyzer = LLMAnalyzer()
            except Exception as e:
                print(f"   Failed to initialize LLM: {e}")
                self.llm_analyzer = None
        else:
            self.llm_analyzer = None

        self.parser = TerraformParser()

        # Multi-cloud rule engines, keyed by provider ('aws' | 'azure' | 'gcp').
        # Built once here instead of per-resource for performance.
        self.rule_engines = RULE_ENGINES
        self._rules_cache: Dict[str, Dict] = {}
        for provider, engine in self.rule_engines.items():
            self._rules_cache[provider] = self._extract_rules_dict(provider, engine)

    def _extract_rules_dict(self, provider: str, engine: Any) -> Dict:
        """Normalize a rule engine's rules into a flat {rule_name: rule_func} dict,
        regardless of whether it exposes items(), get_all_rules(), or .rules."""
        if hasattr(engine, 'items'):
            return dict(engine.items())
        elif hasattr(engine, 'get_all_rules'):
            return engine.get_all_rules()
        elif hasattr(engine, 'rules'):
            return engine.rules
        else:
            print(f"  Warning: {provider} rule engine has no accessible rules")
            return {}

    def scan_file(self, filepath, providers=None):
        """Scan a single file.

        providers: optional set/list like {'aws', 'azure'} to restrict
        which cloud rule engines run. None (default) = all detected clouds.
        """
        resources = self.parser.parse_file(filepath)
        return self._analyze_resources(resources, providers)

    def scan_directory(self, directory, providers=None):
        """Scan all .tf files in directory.

        providers: optional set/list like {'aws', 'azure'} to restrict
        which cloud rule engines run. None (default) = all detected clouds.
        """
        resources = self.parser.parse_directory(directory)
        return self._analyze_resources(resources, providers)

    def _analyze_resources(self, resources: List[Dict], providers=None) -> Dict:
        """Analyze parsed resources for security issues, routed per-resource
        to the correct cloud provider's rule engine."""

        provider_filter = set(providers) if providers else None

        issues = []
        stats = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        skipped_unknown = 0
        skipped_filtered = 0

        for resource in resources:
            resource_type = resource.get('type', 'unknown')
            resource_name = resource.get('name', 'unknown')

            provider = detect_provider(resource_type)
            if provider == 'unknown':
                # e.g. random_id, null_resource, local_file, data sources
                # from providers we don't have rule engines for. Don't run
                # these through the AWS rules by default — that produced
                # silent false negatives (rules never match, no signal
                # that the resource wasn't actually evaluated).
                skipped_unknown += 1
                continue

            if provider_filter is not None and provider not in provider_filter:
                # --cloud filter: skip engines the user didn't ask for,
                # rather than running them and discarding results.
                skipped_filtered += 1
                continue

            rules_dict = self._rules_cache.get(provider, {})
            if not rules_dict:
                continue

            for rule_name, rule_func in rules_dict.items():
                try:
                    finding = rule_func(resource)

                    if finding:
                        if self.ml_analyzer and provider in self.ML_SUPPORTED_PROVIDERS:
                            try:
                                ml_result = self.ml_analyzer.analyze(resource)
                            except Exception as e:
                                print(f"  ML analysis failed: {e}")
                                ml_result = self._default_ml_result()
                        else:
                            # Non-AWS finding, or ML unavailable entirely.
                            # Always attach the placeholder so every issue
                            # keeps the same schema (tests and formatters
                            # rely on ml_risk_score/ml_confidence always
                            # being present) — ml_prediction: 'N/A' is the
                            # signal that no real model ran, distinct from
                            # an actual computed score.
                            ml_result = self._default_ml_result()

                        # Get LLM explanation
                        llm_result = {}
                        if self.llm_analyzer:
                            try:
                                llm_result = self.llm_analyzer.enhance_finding(
                                    resource, ml_result, finding
                                )
                            except Exception as e:
                                print(f"  LLM analysis failed: {e}")

                        issue = {
                            **finding,
                            # Azure/GCP rule files already stamp their own
                            # 'cloud' key; this backstops AWS findings and
                            # any rule engine that doesn't set it.
                            'cloud': finding.get('cloud', provider),
                            'rule_id': rule_name,
                            'resource_type': resource_type,
                            'resource_name': resource_name,
                            **ml_result,
                            **llm_result
                        }

                        issues.append(issue)

                        severity = finding.get('severity', 'MEDIUM')
                        stats[severity] = stats.get(severity, 0) + 1

                except Exception as e:
                    print(f"  Error applying rule {rule_name} ({provider}): {e}")
                    continue

        cloud_breakdown: Dict[str, int] = {}
        for issue in issues:
            c = issue.get('cloud', 'unknown')
            cloud_breakdown[c] = cloud_breakdown.get(c, 0) + 1

        return {
            'issues': issues,
            'stats': stats,
            'total_resources': len(resources),
            'passed': len(resources) - len(issues),
            'skipped_unknown_provider': skipped_unknown,
            'skipped_filtered_provider': skipped_filtered,
            'cloud_breakdown': cloud_breakdown,
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