import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os

def train_model():
    """Train XGBoost model on security features"""
    
    print("=" * 60)
    print("Training XGBoost Security Model")
    print("=" * 60)
    
    # Load data
    print("\n📊 Loading training data...")
    df = pd.read_csv('data/training_data.csv')
    
    print(f"   Total examples: {len(df)}")
    print(f"   Risky: {df['label'].sum()}")
    print(f"   Safe: {len(df) - df['label'].sum()}")
    
    # Split features and labels
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\n🔨 Training model...")
    print(f"   Training examples: {len(X_train)}")
    print(f"   Testing examples: {len(X_test)}")
    
    # Train XGBoost
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        eval_metric='logloss'
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\n📈 Evaluating model...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n✅ Model Performance:")
    print(f"   Accuracy: {accuracy:.2%}")
    print("\nDetailed Report:")
    print(classification_report(y_test, y_pred, target_names=['SAFE', 'RISKY']))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importance
    print("\n🔍 Top 10 Most Important Features:")
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for idx, row in feature_importance.head(10).iterrows():
        print(f"   {row['feature']}: {row['importance']:.3f}")
    
    # Save model
    os.makedirs('models', exist_ok=True)
    model_path = 'models/xgboost_security_model.pkl'
    joblib.dump(model, model_path)
    
    print(f"\n💾 Model saved: {model_path}")
    print("=" * 60)
    
    return model

if __name__ == '__main__':
    train_model()