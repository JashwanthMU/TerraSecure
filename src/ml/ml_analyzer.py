import joblib
import os
import numpy as np
from ml.feature_extractor import SecurityFeatureExtractor

class MLAnalyzer:
    """ML-powered security analysis"""
    
    def __init__(self):
        self.extractor = SecurityFeatureExtractor()
        self.model = None
        
        self.feature_names = [
            'open_cidr_0_0_0_0', 'open_ssh_port_22', 'open_rdp_port_3389',
            'iam_wildcard_action', 'iam_wildcard_resource', 'iam_inline_user_policy',
            's3_public_acl', 's3_block_public_access_disabled', 's3_versioning_disabled',
            's3_encryption_disabled', 'rds_publicly_accessible', 'rds_storage_unencrypted',
            'ec2_public_ip_associated', 'ebs_unencrypted_volume', 'kms_key_rotation_disabled',
            'cloudtrail_not_enabled', 'cloudwatch_log_retention_missing', 'elb_http_listener_only',
            'lambda_no_vpc_config', 'hardcoded_aws_credentials',
            'sg_all_ports_open', 'sg_egress_unrestricted', 'nacl_allow_all_traffic',
            'vpc_flow_logs_disabled', 'route_to_igw_from_private', 'default_sg_in_use',
            'open_database_port_3306', 'open_database_port_5432', 'root_account_in_use',
            'mfa_not_enabled', 'password_policy_weak', 'unused_iam_credentials',
            's3_bucket_policy_public', 'cross_account_access_unrestricted', 'assume_role_no_external_id',
            's3_lifecycle_policy_missing', 's3_mfa_delete_disabled', 'snapshot_publicly_shared',
            'backup_vault_unencrypted', 'secrets_in_environment_vars', 'config_recorder_disabled',
            'guardduty_not_enabled', 'security_hub_not_enabled', 'access_logging_disabled',
            'alarm_missing_for_changes', 'sns_topic_unencrypted', 'ecr_image_scan_disabled',
            'ecs_task_privilege_escalation', 'api_gateway_no_waf', 'lambda_env_vars_unencrypted'
        ]
        self._load_model()
    
    def _load_model(self):
        """Load trained XGBoost model"""
        model_path = 'models/xgboost_50features_model.pkl'  
        
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                print("50-feature ML model loaded")
            except Exception as e:
                print(f"Could not load ML model: {e}")
                self.model = None
        else:
            print("ML model not found. Run: python src/ml/train_model.py")
            self.model = None
        
    def analyze(self, resource):
        """
        Analyze resource with ML model
        
        Returns:
            {
                'ml_risk_score': float (0.0-1.0),
                'ml_confidence': float (0.0-1.0),
                'ml_prediction': str ('SAFE' or 'RISKY'),
                'triggered_features': list
            }
        """
        
        if self.model is None:
            return self._fallback_analysis()

        features_dict = self.extractor.extract_features(resource)
        

        features_array = np.array([[features_dict[name] for name in self.feature_names]])
        

        prediction = self.model.predict(features_array)[0]
        probabilities = self.model.predict_proba(features_array)[0]
        
        risk_score = probabilities[1] 
        confidence = max(probabilities)
        

        triggered = [name for name, val in features_dict.items() if val == 1]
        
        return {
            'ml_risk_score': round(float(risk_score), 3),
            'ml_confidence': round(float(confidence), 3),
            'ml_prediction': 'RISKY' if prediction == 1 else 'SAFE',
            'triggered_features': triggered
        }
    
    def _fallback_analysis(self):
        """Fallback when ML model unavailable"""
        return {
            'ml_risk_score': 0.5,
            'ml_confidence': 0.0,
            'ml_prediction': 'UNKNOWN',
            'triggered_features': []
        }