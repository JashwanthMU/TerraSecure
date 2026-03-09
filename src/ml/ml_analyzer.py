import joblib
import os
import json
import sys
import numpy as np
from pathlib import Path
try:
    from ml.feature_extractor import SecurityFeatureExtractor
except (ModuleNotFoundError, ImportError):
    current_dir = Path(__file__).parent
    sys.path.insert(0, str(current_dir))
    from feature_extractor import SecurityFeatureExtractor

class MLAnalyzer:
    FEATURE_NAMES = [
        #Network
        'open_cidr_0_0_0_0', 'open_ssh_port_22', 'open_rdp_port_3389',
        'sg_all_ports_open', 'sg_egress_unrestricted', 'nacl_allow_all_traffic',
        'open_database_port_3306', 'open_database_port_5432',
        #IAM
        'iam_wildcard_action', 'iam_wildcard_resource', 'iam_inline_user_policy',
        'root_account_in_use', 'mfa_not_enabled', 'password_policy_weak',
        'unused_iam_credentials', 's3_bucket_policy_public',
        'cross_account_access_unrestricted', 'assume_role_no_external_id',
        'hardcoded_aws_credentials', 'secrets_in_environment_vars',
        #S3
        's3_public_acl', 's3_block_public_access_disabled', 's3_versioning_disabled',
        's3_encryption_disabled', 's3_lifecycle_policy_missing', 's3_mfa_delete_disabled',
        'snapshot_publicly_shared', 'backup_vault_unencrypted',
        #Database 
        'rds_publicly_accessible', 'rds_storage_unencrypted',
        'config_recorder_disabled', 'guardduty_not_enabled',
        # EC2 compute
        'ec2_public_ip_associated', 'ebs_unencrypted_volume',
        'lambda_no_vpc_config', 'lambda_env_vars_unencrypted',
        'ecr_image_scan_disabled', 'ecs_task_privilege_escalation',
        'api_gateway_no_waf', 'elb_http_listener_only',
        #Monitoring and compliance 
        'kms_key_rotation_disabled', 'cloudtrail_not_enabled',
        'cloudwatch_log_retention_missing', 'vpc_flow_logs_disabled',
        'route_to_igw_from_private', 'default_sg_in_use',
        'security_hub_not_enabled', 'access_logging_disabled',
        'alarm_missing_for_changes', 'sns_topic_unencrypted'
    ]
    
    def __init__(self):
        """Initialize ML analyzer with production model"""
        
        self.extractor = SecurityFeatureExtractor()
        self.model = None
        self.metadata = {}
        self.model_loaded = False

        self._load_production_model()
    
    def _find_model_file(self, filename):

        
        search_paths = [
            Path('models') / filename,
            Path(__file__).parent / '..' / '..' / 'models' / filename,
            Path(__file__).parent.parent.parent / 'models' / filename,
        ]
        
        for path in search_paths:
            if path.exists():
                return path
        
        return None
    
    def _load_production_model(self):

        prod_model_path = self._find_model_file('terrasecure_production_v1.0.pkl')
        
        if prod_model_path:
            try:
                self.model = joblib.load(prod_model_path)
                self.model_loaded = True
                

                metadata_path = self._find_model_file('model_metadata.json')
                if metadata_path:
                    with open(metadata_path) as f:
                        self.metadata = json.load(f)
                
                version = self.metadata.get('version', '1.0.0')
                accuracy = self.metadata.get('performance', {}).get('test_accuracy', 0)
                fp_rate = self.metadata.get('performance', {}).get('false_positive_rate', 0)
                
                print(f"  Production model v{version} loaded")
                print(f"   Accuracy: {accuracy*100:.2f}% | FP Rate: {fp_rate*100:.2f}%")
                
                return
                
            except Exception as e:
                print(f"  Failed to load production model: {e}")
        

        trained_model_path = self._find_model_file('xgboost_50features_model.pkl')
        
        if trained_model_path:
            try:
                self.model = joblib.load(trained_model_path)
                self.model_loaded = True
                print(" Legacy ML model loaded")
                return
                
            except Exception as e:
                print(f"  Failed to load trained model: {e}")
        

        print("  No ML model found")
        print("   Run: python scripts/build_production_model.py")
        print("   Falling back to rule-based detection only")
        
        self.model = None
        self.model_loaded = False
    
    def analyze(self, resource):
    
        if not self.model_loaded:
            return self._fallback_analysis()
        
        try:

            features_dict = self.extractor.extract_features(resource)

            features_array = np.array([[
                features_dict.get(feature, 0) 
                for feature in self.FEATURE_NAMES
            ]])
            

            prediction = self.model.predict(features_array)[0]
            probabilities = self.model.predict_proba(features_array)[0]

            risk_score = float(probabilities[1])
            confidence = float(max(probabilities))

            triggered = [
                feature for feature in self.FEATURE_NAMES
                if features_dict.get(feature, 0) == 1
            ]
            
            return {
                'ml_risk_score': round(risk_score, 3),
                'ml_confidence': round(confidence, 3),
                'ml_prediction': 'RISKY' if prediction == 1 else 'SAFE',
                'triggered_features': triggered,
                'model_version': self.metadata.get('version', 'unknown')
            }
        
        except Exception as e:
            print(f"  ML analysis error: {e}")
            return self._fallback_analysis()
    
    def _fallback_analysis(self):
        """Fallback when ML unavailable"""
        return {
            'ml_risk_score': 0.5,
            'ml_confidence': 0.0,
            'ml_prediction': 'UNKNOWN',
            'triggered_features': [],
            'model_version': 'none'
        }
    
    def get_model_info(self):
        """Get model information"""
        
        if not self.model_loaded:
            return {
                'status': 'not_loaded',
                'message': 'No ML model loaded. Using rule-based detection only.',
                'recommendation': 'Run: python scripts/build_production_model.py'
            }
        
        perf = self.metadata.get('performance', {})
        
        return {
            'status': 'loaded',
            'version': self.metadata.get('version', 'unknown'),
            'build_date': self.metadata.get('build_date', 'unknown'),
            'model_type': self.metadata.get('model_type', 'XGBoost'),
            'features': len(self.FEATURE_NAMES),
            'training_samples': self.metadata.get('training_samples', 0),
            'performance': {
                'accuracy': perf.get('test_accuracy', 0),
                'precision': perf.get('test_precision', 0),
                'recall': perf.get('test_recall', 0),
                'f1_score': perf.get('test_f1', 0),
                'false_positive_rate': perf.get('false_positive_rate', 0),
                'false_negative_rate': perf.get('false_negative_rate', 0)
            }
        }
    
    def is_ready(self):
        """Check if analyzer is ready"""
        return self.model_loaded

def main():
    """Test ML analyzer"""
    
    print("=" * 70)
    print("ML Analyzer Test")
    print("=" * 70)

    analyzer = MLAnalyzer()

    test_resource = {
        'type': 'aws_s3_bucket',
        'name': 'test_bucket',
        'properties': {
            'acl': 'public-read',
            'versioning': {'enabled': False},
            'server_side_encryption_configuration': None
        }
    }
    

    print("\n Analyzing test resource...")
    result = analyzer.analyze(test_resource)
    
    print("\n Results:")
    print(f"   Prediction:   {result['ml_prediction']}")
    print(f"   Risk Score:   {result['ml_risk_score']:.0%}")
    print(f"   Confidence:   {result['ml_confidence']:.0%}")
    print(f"   Features:     {len(result['triggered_features'])}")
    print(f"   Version:      {result['model_version']}")
    
    if result['triggered_features']:
        print(f"\n  Triggered Features:")
        for feature in result['triggered_features'][:10]:
            print(f"   - {feature}")

    print("\n Model Info:")
    info = analyzer.get_model_info()
    
    if info['status'] == 'loaded':
        print(f"   Status:        Loaded")
        print(f"   Version:      {info['version']}")
        print(f"   Type:         {info['model_type']}")
        print(f"   Features:     {info['features']}")
        print(f"   Samples:      {info['training_samples']}")
        print(f"\n   Performance:")
        perf = info['performance']
        print(f"   Accuracy:     {perf['accuracy']*100:.2f}%")
        print(f"   Precision:    {perf['precision']*100:.2f}%")
        print(f"   Recall:       {perf['recall']*100:.2f}%")
        print(f"   FP Rate:      {perf['false_positive_rate']*100:.2f}%")
        print(f"   FN Rate:      {perf['false_negative_rate']*100:.2f}%")
    else:
        print(f"   Status:        Not Loaded")
        print(f"   Message:      {info['message']}")
        print(f"   Fix:          {info['recommendation']}")
    
    print("\n" + "=" * 70)

if __name__ == '__main__':
    main()