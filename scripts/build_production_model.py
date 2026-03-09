import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import xgboost as xgb
import joblib
import json
from datetime import datetime

def generate_comprehensive_training_data():
    """Generate large, diverse training dataset"""
    print(" Generating comprehensive training dataset...")
    from generate_training_data import generate_training_data
    base_data = generate_training_data()
    additional_risky = []
    additional_safe = []
    breach_patterns = [
        #Capital one 
        {
            'open_cidr_0_0_0_0': 1, 'iam_wildcard_action': 1, 'iam_wildcard_resource': 1,
            's3_public_acl': 1, 's3_encryption_disabled': 1, 'cloudtrail_not_enabled': 1,
            'vpc_flow_logs_disabled': 1, 'guardduty_not_enabled': 1
        },
        #Uber 
        {
            'secrets_in_environment_vars': 1, 'open_ssh_port_22': 1, 
            'mfa_not_enabled': 1, 'access_logging_disabled': 1,
            'alarm_missing_for_changes': 1
        },
        #Tesla
        {
            's3_public_acl': 1, 's3_encryption_disabled': 1, 's3_versioning_disabled': 1,
            's3_lifecycle_policy_missing': 1, 's3_mfa_delete_disabled': 1
        },
        #MongoDB ransomware 
        {
            'rds_publicly_accessible': 1, 'open_database_port_3306': 1,
            'rds_storage_unencrypted': 1, 'backup_vault_unencrypted': 1,
            'default_sg_in_use': 1
        }
    ]

    for pattern in breach_patterns:
        for _ in range(20): 
            variation = pattern.copy()
            for key in variation:
                if np.random.random() < 0.2:  
                    variation[key] = 0
            for i in range(1, 51):
                feature_name = f'feature_{i}'
                if feature_name not in variation:
                    variation[feature_name] = 0
            variation['label'] = 'risky'
            additional_risky.append(variation)
    safe_patterns = [
        {
            's3_public_acl': 0, 's3_encryption_disabled': 0, 's3_versioning_disabled': 0,
            's3_block_public_access_disabled': 0, 's3_lifecycle_policy_missing': 0,
            'kms_key_rotation_disabled': 0, 'cloudtrail_not_enabled': 0
        },
        {
            'rds_publicly_accessible': 0, 'rds_storage_unencrypted': 0,
            'vpc_flow_logs_disabled': 0, 'guardduty_not_enabled': 0,
            'security_hub_not_enabled': 0
        },
        {
            'iam_wildcard_action': 0, 'iam_wildcard_resource': 0,
            'iam_inline_user_policy': 0, 'mfa_not_enabled': 0,
            'password_policy_weak': 0, 'cross_account_access_unrestricted': 0
        }
    ]
    for pattern in safe_patterns:
        for _ in range(30):  
            variation = pattern.copy()
            for i in range(1, 51):
                feature_name = f'feature_{i}'
                if feature_name not in variation:
                    variation[feature_name] = 0
            variation['label'] = 'safe'
            additional_safe.append(variation)
    all_data = base_data + additional_risky + additional_safe
    print(f" Generated {len(all_data)} training examples")
    print(f"   - Risky: {sum(1 for d in all_data if d['label'] == 'risky')}")
    print(f"   - Safe: {sum(1 for d in all_data if d['label'] == 'safe')}")
    return pd.DataFrame(all_data)

def train_production_model():
    """Train and validate production model"""
    
    print("\n" + "="*60)
    print("TerraSecure Production Model Training")
    print("="*60 + "\n")
    df = generate_comprehensive_training_data()
    df.to_csv('data/production_training_data.csv', index=False)
    print("\n Training data saved to: data/production_training_data.csv")

    X = df.drop('label', axis=1)
    y = df['label'].map({'risky': 1, 'safe': 0})

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\n Dataset Split:")
    print(f"   Training: {len(X_train)} samples")
    print(f"   Testing: {len(X_test)} samples")

    print("\n Training XGBoost model...")
    
    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=10,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='logloss'
    )
    
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False
    )

    print("\n Running 5-fold cross-validation...")
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
    
    print(f"\n Cross-Validation Results:")
    print(f"   Mean Accuracy: {cv_scores.mean():.2%}")
    print(f"   Std Deviation: {cv_scores.std():.2%}")
    print(f"   Individual Folds: {[f'{s:.2%}' for s in cv_scores]}")

    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    print("\n Test Set Performance:")
    print("\nClassification Report:")
    print(classification_report(
        y_test, y_pred, 
        target_names=['Safe', 'Risky'],
        digits=4
    ))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                Predicted Safe  Predicted Risky")
    print(f"Actual Safe     {cm[0][0]:>14}  {cm[0][1]:>15}")
    print(f"Actual Risky    {cm[1][0]:>14}  {cm[1][1]:>15}")

    fp_rate = cm[0][1] / (cm[0][0] + cm[0][1])
    fn_rate = cm[1][0] / (cm[1][0] + cm[1][1])
    
    print(f"\n Production Metrics:")
    print(f"   False Positive Rate: {fp_rate:.2%} (Target: <10%)")
    print(f"   False Negative Rate: {fn_rate:.2%} (Target: <5%)")
    
    if fp_rate > 0.10:
        print("\n  WARNING: False positive rate exceeds 10% threshold!")

    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\n🔝 Top 10 Most Important Features:")
    for idx, row in feature_importance.head(10).iterrows():
        print(f"   {row['feature']}: {row['importance']:.4f}")

    model_path = 'models/terrasecure_production_v1.0.pkl'
    joblib.dump(model, model_path)
    print(f"\n Model saved to: {model_path}")

    metadata = {
        'version': '1.0.0',
        'build_date': datetime.now().isoformat(),
        'training_samples': len(df),
        'features': X.columns.tolist(),
        'accuracy': float(cv_scores.mean()),
        'false_positive_rate': float(fp_rate),
        'false_negative_rate': float(fn_rate),
        'hyperparameters': {
            'n_estimators': 200,
            'max_depth': 10,
            'learning_rate': 0.05
        },
        'top_features': feature_importance.head(20).to_dict('records')
    }
    
    with open('models/model_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print("\n Production model build complete!")
    print(f"\nModel Info:")
    print(f"   Version: {metadata['version']}")
    print(f"   Accuracy: {metadata['accuracy']:.2%}")
    print(f"   FP Rate: {metadata['false_positive_rate']:.2%}")
    print(f"   Size: {os.path.getsize(model_path) / 1024:.1f} KB")
    
    return model, metadata

if __name__ == '__main__':
    import os
    os.makedirs('data', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    
    model, metadata = train_production_model()
    
    print("\n" + "="*60)
    print(" PRODUCTION MODEL READY FOR DISTRIBUTION")
    print("="*60)