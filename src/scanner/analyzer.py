from scanner.parser import TerraformParser
from rules.security_rules import SecurityRules

# Try to import ML analyzer, but don't fail if it doesn't exist
try:
    from ml.ml_analyzer import MLAnalyzer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️  ML analyzer not available. Install: pip install xgboost scikit-learn joblib")

class SecurityAnalyzer:
    """Analyzes Terraform resources for security issues"""
    
    def __init__(self):
        self.parser = TerraformParser()
        self.rules = SecurityRules.get_all_rules()
        
        # Initialize ML analyzer if available
        if ML_AVAILABLE:
            try:
                self.ml_analyzer = MLAnalyzer()
            except Exception as e:
                print(f"⚠️  Could not initialize ML analyzer: {e}")
                self.ml_analyzer = None
        else:
            self.ml_analyzer = None
    
    def scan_file(self, filepath):
        """Scan a single file"""
        resources = self.parser.parse_file(filepath)
        return self._analyze_resources(resources)
    
    def scan_directory(self, directory):
        """Scan all .tf files in directory"""
        resources = self.parser.parse_directory(directory)
        return self._analyze_resources(resources)
    
    def _analyze_resources(self, resources):
        """
        Analyze list of resources against rules
        
        Returns:
            {
                'total_resources': int,
                'issues': [list of findings],
                'stats': {severity counts}
            }
        """
        findings = []
        stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for resource in resources:
            for rule_name, rule in self.rules.items():
                if self._check_rule(resource, rule):
                    
                    # Get ML analysis if available
                    if self.ml_analyzer:
                        try:
                            ml_result = self.ml_analyzer.analyze(resource)
                        except Exception as e:
                            print(f"⚠️  ML analysis failed: {e}")
                            ml_result = self._default_ml_result()
                    else:
                        ml_result = self._default_ml_result()
                    
                    finding = {
                        'rule': rule_name,
                        'severity': rule['severity'],
                        'resource_type': resource['type'],
                        'resource_name': resource['name'],
                        'file': resource['file'],
                        'message': rule['message'],
                        'fix': rule['fix'],
                        'ml_risk_score': ml_result.get('ml_risk_score', 0.5),
                        'ml_confidence': ml_result.get('ml_confidence', 0.0),
                        'ml_prediction': ml_result.get('ml_prediction', 'UNKNOWN'),
                        'triggered_features': ml_result.get('triggered_features', [])
                    }
                    findings.append(finding)
                    stats[rule['severity']] += 1
        
        return {
            'total_resources': len(resources),
            'issues': findings,
            'stats': stats,
            'passed': max(0, len(resources) - len(findings))
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
        
        # Check resource type matches
        if resource['type'] != pattern['resource_type']:
            return False
        
        # Check all conditions
        for condition in pattern['conditions']:
            if not self._check_condition(resource, condition):
                return False
        
        return True
    
    def _check_condition(self, resource, condition):
        """Check individual condition"""
        
        prop_name = condition['property']
        props = resource.get('properties', {})
        
        # Handle nested properties
        if '.' in prop_name:
            value = self.parser.extract_property(resource, prop_name)
        else:
            value = props.get(prop_name)
        
        # Check 'absent' condition
        if 'absent' in condition:
            return (value is None) == condition['absent']
        
        # Check 'equals' condition
        if 'equals' in condition:
            return value == condition['equals']
        
        # Check 'contains' condition
        if 'contains' in condition:
            search_terms = condition['contains']
            if isinstance(search_terms, str):
                search_terms = [search_terms]
            
            if isinstance(value, str):
                return any(term in value.lower() for term in search_terms)
            elif isinstance(value, list):
                value_str = str(value).lower()
                return any(term in value_str for term in search_terms)
        
        # Check 'less_than' condition
        if 'less_than' in condition:
            try:
                return int(value or 0) < condition['less_than']
            except:
                return False
        
        return False