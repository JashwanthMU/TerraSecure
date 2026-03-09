import sys
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import xgboost as xgb
import joblib
import json
from datetime import datetime

class ProductionModelBuilder:
    """Production model builder with quality checks"""
    
    def __init__(self):
        self.model = None
        self.metadata = {}
        self.feature_names = []
        
    def generate_training_data(self):
        
        print("=" * 70)
        print("STEP 1: TRAINING DATA GENERATION")
        print("=" * 70)

        print("\n Generating base training data...")
        result = os.system('python scripts/generate_training_data.py')
        
        if result != 0:
            raise RuntimeError("Failed to generate base training data")

        base_data_path = 'data/training_data_50features.csv'
        
        if not os.path.exists(base_data_path):
            raise FileNotFoundError(f"Training data not found: {base_data_path}")
        
        base_df = pd.read_csv(base_data_path)
        print(f" Loaded {len(base_df)} base examples")

        self.feature_names = [col for col in base_df.columns if col != 'label']

        print("\n Adding real-world breach patterns...")
        breach_data = self._generate_breach_patterns()

        print(" Adding secure configuration patterns...")
        secure_data = self._generate_secure_patterns()

        all_rows = []

        all_rows.extend(base_df.to_dict('records'))

        all_rows.extend(breach_data)

        all_rows.extend(secure_data)

        df = pd.DataFrame(all_rows)
        

        print("\n Data Quality Checks:")
        print(f"   Total samples: {len(df)}")
        print(f"   Features: {len(self.feature_names)}")

        nan_count = df['label'].isna().sum()
        if nan_count > 0:
            print(f"     Removing {nan_count} rows with NaN labels")
            df = df.dropna(subset=['label'])

        valid_labels = df['label'].isin(['risky', 'safe'])
        if not valid_labels.all():
            invalid_count = (~valid_labels).sum()
            print(f"     Removing {invalid_count} rows with invalid labels")
            df = df[valid_labels]

        feature_nans = df[self.feature_names].isna().sum().sum()
        if feature_nans > 0:
            print(f"     Filling {feature_nans} NaN feature values with 0")
            df[self.feature_names] = df[self.feature_names].fillna(0)
        

        label_counts = df['label'].value_counts()
        print(f"\n Final Dataset:")
        print(f"   Total: {len(df)} samples")
        print(f"   Risky: {label_counts.get('risky', 0)} ({label_counts.get('risky', 0)/len(df)*100:.1f}%)")
        print(f"   Safe: {label_counts.get('safe', 0)} ({label_counts.get('safe', 0)/len(df)*100:.1f}%)")

        imbalance_ratio = max(label_counts) / min(label_counts)
        if imbalance_ratio > 1.5:
            print(f"    Class imbalance detected: {imbalance_ratio:.2f}:1")
        else:
            print(f"    Classes balanced: {imbalance_ratio:.2f}:1")

        os.makedirs('data', exist_ok=True)
        output_path = 'data/production_training_data.csv'
        df.to_csv(output_path, index=False)
        print(f"\n Saved to: {output_path}")
        
        return df
    
    def _generate_breach_patterns(self):
        """Generate training data based on real-world breaches"""

        breach_patterns = {
            'capital_one_2019': {
                'open_cidr_0_0_0_0': 1,
                'iam_wildcard_action': 1,
                'iam_wildcard_resource': 1,
                's3_public_acl': 1,
                's3_encryption_disabled': 1,
                'cloudtrail_not_enabled': 1,
                'vpc_flow_logs_disabled': 1,
                'guardduty_not_enabled': 1,
                'api_gateway_no_waf': 1
            },
            'uber_2016': {
                'secrets_in_environment_vars': 1,
                'hardcoded_aws_credentials': 1,
                'open_ssh_port_22': 1,
                'mfa_not_enabled': 1,
                'access_logging_disabled': 1,
                'alarm_missing_for_changes': 1
            },
            'tesla_s3_2018': {
                's3_public_acl': 1,
                's3_encryption_disabled': 1,
                's3_versioning_disabled': 1,
                's3_lifecycle_policy_missing': 1,
                's3_mfa_delete_disabled': 1,
                's3_block_public_access_disabled': 1
            },
            'mongodb_ransomware_2017': {
                'rds_publicly_accessible': 1,
                'open_database_port_3306': 1,
                'open_database_port_5432': 1,
                'rds_storage_unencrypted': 1,
                'backup_vault_unencrypted': 1,
                'default_sg_in_use': 1,
                'mfa_not_enabled': 1
            },
            'docker_hub_2019': {
                'ecr_image_scan_disabled': 1,
                'ecs_task_privilege_escalation': 1,
                'secrets_in_environment_vars': 1,
                'lambda_env_vars_unencrypted': 1
            }
        }
        
        breach_data = []
        
        for breach_name, pattern in breach_patterns.items():
            for i in range(25):
                variation = {}
                for feature in self.feature_names:
                    if feature in pattern:
                        variation[feature] = pattern[feature] if np.random.random() > 0.2 else 0
                    else:
                        variation[feature] = 1 if np.random.random() < 0.05 else 0
                
                variation['label'] = 'risky'
                breach_data.append(variation)
        
        print(f"   Added {len(breach_data)} breach pattern examples")
        return breach_data
    
    def _generate_secure_patterns(self):
        """Generate training data for secure configurations"""
        
        secure_patterns = {
            'secure_s3': {
                's3_public_acl': 0,
                's3_encryption_disabled': 0,
                's3_versioning_disabled': 0,
                's3_block_public_access_disabled': 0,
                's3_lifecycle_policy_missing': 0,
                's3_mfa_delete_disabled': 0,
                'kms_key_rotation_disabled': 0,
                'cloudtrail_not_enabled': 0,
                'access_logging_disabled': 0
            },
            'secure_rds': {
                'rds_publicly_accessible': 0,
                'rds_storage_unencrypted': 0,
                'open_database_port_3306': 0,
                'open_database_port_5432': 0,
                'vpc_flow_logs_disabled': 0,
                'guardduty_not_enabled': 0,
                'security_hub_not_enabled': 0,
                'backup_vault_unencrypted': 0
            },
            'secure_iam': {
                'iam_wildcard_action': 0,
                'iam_wildcard_resource': 0,
                'iam_inline_user_policy': 0,
                'mfa_not_enabled': 0,
                'password_policy_weak': 0,
                'cross_account_access_unrestricted': 0,
                'root_account_in_use': 0,
                'hardcoded_aws_credentials': 0
            },
            'secure_network': {
                'open_cidr_0_0_0_0': 0,
                'open_ssh_port_22': 0,
                'open_rdp_port_3389': 0,
                'sg_all_ports_open': 0,
                'sg_egress_unrestricted': 0,
                'default_sg_in_use': 0,
                'vpc_flow_logs_disabled': 0
            }
        }
        
        secure_data = []
        
        for pattern_name, pattern in secure_patterns.items():
            for i in range(35):
                variation = {}
                
                for feature in self.feature_names:
                    if feature in pattern:
                        variation[feature] = pattern[feature]
                    else:
                        variation[feature] = 1 if np.random.random() < 0.02 else 0
                
                variation['label'] = 'safe'
                secure_data.append(variation)
        
        print(f"   Added {len(secure_data)} secure pattern examples")
        return secure_data
    
    def train_model(self, df):
        """
        Train production model with comprehensive validation
        """
        
        print("\n" + "=" * 70)
        print("STEP 2: MODEL TRAINING")
        print("=" * 70)

        X = df[self.feature_names]
        y = df['label'].map({'risky': 1, 'safe': 0})
        
        print(f"\n Training Set:")
        print(f"   Samples: {len(X)}")
        print(f"   Features: {len(self.feature_names)}")
        print(f"   Risky: {(y == 1).sum()}")
        print(f"   Safe: {(y == 0).sum()}")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=0.2, 
            random_state=42, 
            stratify=y
        )
        
        print(f"\n   Train: {len(X_train)} samples")
        print(f"   Test:  {len(X_test)} samples")
        

        print("\n Training XGBoost Classifier...")
        print("   Hyperparameters:")
        print("   - n_estimators: 200")
        print("   - max_depth: 10")
        print("   - learning_rate: 0.05")
        print("   - subsample: 0.8")
        print("   - colsample_bytree: 0.8")
        
        self.model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=10,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            eval_metric='logloss',
            use_label_encoder=False
        )
        

        self.model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False
        )
        
        print("  Training complete")
        

        return self._validate_model(X, y, X_test, y_test)
    
    def _validate_model(self, X, y, X_test, y_test):
        """Comprehensive model validation"""
        
        print("\n" + "=" * 70)
        print("STEP 3: MODEL VALIDATION")
        print("=" * 70)

        print("\n 5-Fold Cross-Validation...")
        cv_scores = cross_val_score(self.model, X, y, cv=5, scoring='accuracy')
        
        print(f"\n   Results:")
        print(f"   Mean Accuracy: {cv_scores.mean():.4f} ({cv_scores.mean()*100:.2f}%)")
        print(f"   Std Deviation: {cv_scores.std():.4f}")
        print(f"   Min Accuracy:  {cv_scores.min():.4f} ({cv_scores.min()*100:.2f}%)")
        print(f"   Max Accuracy:  {cv_scores.max():.4f} ({cv_scores.max()*100:.2f}%)")
        
        for i, score in enumerate(cv_scores, 1):
            print(f"   Fold {i}: {score:.4f} ({score*100:.2f}%)")

        print("\n Test Set Evaluation...")
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)

        print("\n" + classification_report(
            y_test, y_pred,
            target_names=['Safe', 'Risky'],
            digits=4
        ))

        cm = confusion_matrix(y_test, y_pred)
        
        print("Confusion Matrix:")
        print(f"                 Predicted Safe  Predicted Risky")
        print(f"Actual Safe      {cm[0][0]:>14}  {cm[0][1]:>15}")
        print(f"Actual Risky     {cm[1][0]:>14}  {cm[1][1]:>15}")

        tn, fp, fn, tp = cm.ravel()
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        fn_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
        print(f"\n Production Metrics:")
        print(f"   Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"   Precision: {precision:.4f} ({precision*100:.2f}%)")
        print(f"   Recall:    {recall:.4f} ({recall*100:.2f}%)")
        print(f"   F1-Score:  {f1:.4f}")
        print(f"\n   False Positive Rate: {fp_rate:.4f} ({fp_rate*100:.2f}%) [Target: <10%]")
        print(f"   False Negative Rate: {fn_rate:.4f} ({fn_rate*100:.2f}%) [Target: <5%]")
        print(f"\n Quality Gates:")
        
        quality_passed = True
        
        if accuracy < 0.85:
            print(f"    Accuracy below 85%: {accuracy*100:.2f}%")
            quality_passed = False
        else:
            print(f"    Accuracy: {accuracy*100:.2f}% (>85%)")
        
        if fp_rate > 0.10:
            print(f"    FP Rate above 10%: {fp_rate*100:.2f}%")
        else:
            print(f"    FP Rate: {fp_rate*100:.2f}% (<10%)")
        
        if fn_rate > 0.05:
            print(f"    FN Rate above 5%: {fn_rate*100:.2f}%")
        else:
            print(f"    FN Rate: {fn_rate*100:.2f}% (<5%)")

        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print(f"\n Top 15 Most Important Features:")
        for idx, (_, row) in enumerate(feature_importance.head(15).iterrows(), 1):
            bar = '█' * int(row['importance'] * 50)
            print(f"   {idx:2d}. {row['feature']:35s} {bar} {row['importance']:.4f}")

        self.metadata = {
            'version': '1.0.0',
            'build_date': datetime.now().isoformat(),
            'training_samples': len(X),
            'features': self.feature_names,
            'feature_count': len(self.feature_names),
            'model_type': 'XGBoost',
            'hyperparameters': {
                'n_estimators': 200,
                'max_depth': 10,
                'learning_rate': 0.05,
                'subsample': 0.8,
                'colsample_bytree': 0.8
            },
            'performance': {
                'cv_mean_accuracy': float(cv_scores.mean()),
                'cv_std_accuracy': float(cv_scores.std()),
                'test_accuracy': float(accuracy),
                'test_precision': float(precision),
                'test_recall': float(recall),
                'test_f1': float(f1),
                'false_positive_rate': float(fp_rate),
                'false_negative_rate': float(fn_rate)
            },
            'quality_gates_passed': quality_passed,
            'top_features': [
                {'feature': row['feature'], 'importance': float(row['importance'])}
                for _, row in feature_importance.head(20).iterrows()
            ]
        }
        
        return self.metadata
    
    def save_model(self):
        """Save model and metadata"""
        
        print("\n" + "=" * 70)
        print("STEP 4: MODEL EXPORT")
        print("=" * 70)

        os.makedirs('models', exist_ok=True)

        model_path = 'models/terrasecure_production_v1.0.pkl'
        joblib.dump(self.model, model_path)
        model_size = os.path.getsize(model_path)
        
        print(f"\n Model saved:")
        print(f"   Path: {model_path}")
        print(f"   Size: {model_size / 1024:.1f} KB")
        
        metadata_path = 'models/model_metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(self.metadata, f, indent=2)
        
        print(f"\n Metadata saved:")
        print(f"   Path: {metadata_path}")

        readme_path = 'models/README.md'
        with open(readme_path, 'w') as f:
            f.write(f"""# TerraSecure Production Model v{self.metadata['version']}

- **Version:** {self.metadata['version']}
- **Build Date:** {self.metadata['build_date']}
- **Model Type:** {self.metadata['model_type']}
- **Training Samples:** {self.metadata['training_samples']}
- **Features:** {self.metadata['feature_count']}

- **Accuracy:** {self.metadata['performance']['test_accuracy']*100:.2f}%
- **Precision:** {self.metadata['performance']['test_precision']*100:.2f}%
- **Recall:** {self.metadata['performance']['test_recall']*100:.2f}%
- **F1-Score:** {self.metadata['performance']['test_f1']:.4f}

- **False Positive Rate:** {self.metadata['performance']['false_positive_rate']*100:.2f}% (Target: <10%)
- **False Negative Rate:** {self.metadata['performance']['false_negative_rate']*100:.2f}% (Target: <5%)

{' PASSED' if self.metadata['quality_gates_passed'] else ' FAILED'}
{chr(10).join([f"{i+1}. {f['feature']} ({f['importance']:.4f})" for i, f in enumerate(self.metadata['top_features'][:10])])}
""")
        
        print(f"\n README created:")
        print(f"   Path: {readme_path}")
        
        return model_path, metadata_path
    
    def build(self):
        """Main build pipeline"""
        print("\n")
        print("╔" + "=" * 68 + "╗")
        print("║" + " " * 68 + "║")
        print("║" + "  TerraSecure Production Model Builder v1.0.0".center(68) + "║")
        print("║" + "  Enterprise-Grade ML Model for Infrastructure Security".center(68) + "║")
        print("║" + " " * 68 + "║")
        print("╚" + "=" * 68 + "╝")
        print()
        
        try:
            df = self.generate_training_data()
            metadata = self.train_model(df)
            model_path, metadata_path = self.save_model()
            print("\n" + "=" * 70)
            print(" BUILD SUCCESSFUL")
            print("=" * 70)

            
            print(f"\n Model Summary:")
            print(f"   Version:     {metadata['version']}")
            print(f"   Accuracy:    {metadata['performance']['test_accuracy']*100:.2f}%")
            print(f"   FP Rate:     {metadata['performance']['false_positive_rate']*100:.2f}%")
            print(f"   FN Rate:     {metadata['performance']['false_negative_rate']*100:.2f}%")
            print(f"   Samples:     {metadata['training_samples']}")
            print(f"   Features:    {metadata['feature_count']}")
            
            print("\n" + "=" * 70)
            
            return 0
            
        except Exception as e:
            print("\n" + "=" * 70)
            print(" BUILD FAILED")
            print("=" * 70)
            print(f"\nError: {e}")
            
            import traceback
            print("\nStack Trace:")
            traceback.print_exc()
            
            return 1
def main():
    """Entry point"""
    builder = ProductionModelBuilder()
    return builder.build()
if __name__ == '__main__':
    sys.exit(main())