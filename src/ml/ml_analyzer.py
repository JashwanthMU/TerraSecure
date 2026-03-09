import joblib
import os
import json
import numpy as np
from datetime import datetime
try:
    from ml.feature_extractor import SecurityFeatureExtractor
except ModuleNotFoundError:
    from feature_extractor import SecurityFeatureExtractor

class MLAnalyzer:
    """
    ML-powered security analysis with production model
    
    Features:
    - Pre-trained model (no training needed)
    - Fast predictions (<100ms)
    - Offline operation
    - Backward compatible
    """
    
    def __init__(self, force_retrain=False):
        """
        Initialize ML Analyzer
        
        Args:
            force_retrain: If True, requires training. If False, uses production model
        """
        self.extractor = SecurityFeatureExtractor()
        self.model = None
        self.metadata = {}

        self.feature_names = [
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
            
            #Compute  
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
        
   
        self._load_model(force_retrain)
    
    def _load_model(self, force_retrain=False):
        """
        Load ML model with fallback strategy:
        1. Try production model (pre-trained, recommended)
        2. Try trained model (from train_model.py)
        3. Fallback to rule-based only
        """
        
      
        production_model_path = 'models/terrasecure_production_v1.0.pkl'
        if os.path.exists(production_model_path) and not force_retrain:
            try:
                self.model = joblib.load(production_model_path)
                self.metadata = self._load_metadata('models/model_metadata.json')
                
                version = self.metadata.get('version', '1.0.0')
                accuracy = self.metadata.get('accuracy', 0)
                fp_rate = self.metadata.get('false_positive_rate', 0)
                
                print(f" Production model v{version} loaded")
                print(f" Accuracy: {accuracy:.2%} | FP Rate: {fp_rate:.2%}")
                return
            except Exception as e:
                print(f"  Could not load production model: {e}")
        
     
        trained_model_path = 'models/xgboost_50features_model.pkl'
        if os.path.exists(trained_model_path):
            try:
                self.model = joblib.load(trained_model_path)
                print(" 50-feature ML model loaded (trained)")
                return
            except Exception as e:
                print(f"  Could not load trained model: {e}")
        
        # No model available
        if force_retrain:
            raise FileNotFoundError(
                "No ML model found!\n"
                "Run: python scripts/build_production_model.py\n"
                "Or: python src/ml/train_model.py"
            )
        else:
            print("  ML model not found. Run: python scripts/build_production_model.py")
            print("   Continuing with rule-based detection only...")
            self.model = None
    
    def _load_metadata(self, path):
        """Load model metadata if available"""
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def analyze(self, resource):
        """
        Analyze resource with ML model
        
        Args:
            resource: Dict containing Terraform resource configuration
        
        Returns:
            {
                'ml_risk_score': float (0.0-1.0),  # Probability of being risky
                'ml_confidence': float (0.0-1.0),   # Model confidence
                'ml_prediction': str ('SAFE' or 'RISKY'),
                'triggered_features': list,         # Which features triggered
                'model_version': str                # Model version used
            }
        """
        
     
        if self.model is None:
            return self._fallback_analysis()
        
        try:
            
            features_dict = self.extractor.extract_features(resource)
            
            
            features_array = np.array([[
                features_dict.get(name, 0) for name in self.feature_names
            ]])
            
         
            prediction = self.model.predict(features_array)[0]
            probabilities = self.model.predict_proba(features_array)[0]
            
            
            risk_score = probabilities[1]  
            confidence = max(probabilities)  

            triggered = [
                name for name, val in features_dict.items() 
                if val == 1 and name in self.feature_names
            ]
            
            return {
                'ml_risk_score': round(float(risk_score), 3),
                'ml_confidence': round(float(confidence), 3),
                'ml_prediction': 'RISKY' if prediction == 1 else 'SAFE',
                'triggered_features': triggered,
                'model_version': self.metadata.get('version', 'unknown')
            }
        
        except Exception as e:
            print(f"  ML analysis failed: {e}")
            return self._fallback_analysis()
    
    def _fallback_analysis(self):
        """
        Fallback analysis when ML model unavailable
        Returns conservative estimates
        """
        return {
            'ml_risk_score': 0.5,
            'ml_confidence': 0.0,
            'ml_prediction': 'UNKNOWN',
            'triggered_features': [],
            'model_version': 'none'
        }
    
    def get_model_info(self):
        """
        Get information about loaded model
        
        Returns:
            Dict with model metadata
        """
        if self.model is None:
            return {
                'status': 'not_loaded',
                'message': 'No ML model loaded. Using rule-based detection only.'
            }
        
        return {
            'status': 'loaded',
            'version': self.metadata.get('version', 'unknown'),
            'accuracy': self.metadata.get('accuracy', 0),
            'false_positive_rate': self.metadata.get('false_positive_rate', 0),
            'false_negative_rate': self.metadata.get('false_negative_rate', 0),
            'build_date': self.metadata.get('build_date', 'unknown'),
            'training_samples': self.metadata.get('training_samples', 0),
            'features': len(self.feature_names)
        }
    
    def is_ready(self):
        """Check if ML analyzer is ready to use"""
        return self.model is not None
if __name__ == '__main__':
    print("Testing ML Analyzer...\n")
    
    try:
        analyzer = MLAnalyzer()

        test_resource = {
            'type': 'aws_s3_bucket',
            'name': 'test_bucket',
            'properties': {
                'acl': 'public-read',
                'versioning': {'enabled': False}
            }
        }
        
        result = analyzer.analyze(test_resource)
        
        print(" ML Analyzer Test Results:")
        print(f"   Prediction: {result['ml_prediction']}")
        print(f"   Risk Score: {result['ml_risk_score']:.0%}")
        print(f"   Confidence: {result['ml_confidence']:.0%}")
        print(f"   Triggered Features: {len(result['triggered_features'])}")
        print(f"   Model Version: {result['model_version']}")

        info = analyzer.get_model_info()
        if info['status'] == 'loaded':
            print(f"\n Model Info:")
            print(f"   Version: {info['version']}")
            print(f"   Accuracy: {info['accuracy']:.2%}")
            print(f"   FP Rate: {info['false_positive_rate']:.2%}")
            print(f"   Build Date: {info['build_date']}")
        
    except Exception as e:
        print(f" Error: {e}")
        print("\nTo fix, run:")
        print("  python scripts/build_production_model.py")