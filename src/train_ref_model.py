import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os

def clean_and_prepare_data(filepath):
    print(f"Loading dataset from {filepath}...")
    df = pd.read_csv(filepath, low_memory=False)
    
    # 1. Clean column names (CIC datasets notoriously have leading spaces like ' Flow Duration')
    df.columns = df.columns.str.strip()
    
    # 2. Handle missing or infinite values (created by dividing by zero in network flows)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # 3. Verify the Label column exists
    if 'Label' not in df.columns:
        raise ValueError("Label column not found! Check your CSV columns output from the discovery script.")
        
    # 4. Map labels to binary classification: 0 for Benign, 1 for Malicious (DDoS/Slowloris)
    df['Label_Binary'] = df['Label'].apply(lambda x: 0 if 'BENIGN' in str(x).upper() else 1)
    
    # 5. Feature Selection: Isolate temporal and stateful features, dropping volumetric data and IP/Ports
    target_features = [
        'Flow Duration', 
        'Fwd IAT Mean', 
        'Bwd IAT Mean', 
        'Fwd PSH Flags',
        'Fwd Packets/s',
        'Bwd Packets/s'
    ]
    
    # Ensure our target features actually exist in this specific CSV
    available_features = [f for f in target_features if f in df.columns]
    
    X = df[available_features]
    y = df['Label_Binary']
    
    # 6. Export a clean subset for JASP statistical analysis
    jasp_df = X.copy()
    jasp_df['Label'] = y
    os.makedirs('../data/processed', exist_ok=True)
    jasp_df.to_csv('../data/processed/jasp_ready_data.csv', index=False)
    print("Exported clean dataset for JASP analysis to: data/processed/jasp_ready_data.csv")
    
    return X, y

def train_and_evaluate():
    # Update this filename to match the CSV in your data/raw folder
    csv_path = '../data/raw/cicddos2019_sample.csv' 
    
    X, y = clean_and_prepare_data(csv_path)
    print(f"\nFeatures mapped: {X.shape[1]} columns. Total usable rows: {X.shape[0]}")
    
    print("\nSplitting data (70% Training / 30% Testing)...")
    # 'stratify=y' ensures the 70/30 split maintains the exact ratio of Benign vs Malicious traffic
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    
    print("Training Random Forest Classifier (this might take a few moments)...")
    # n_jobs=-1 tells scikit-learn to use all available CPU cores for faster training
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)
    
    print("\nEvaluating Model on 30% Holdout Test Data...")
    predictions = rf_model.predict(X_test)
    
    print("\n" + "="*30)
    print("       MODEL RESULTS")
    print("="*30)
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    
    print("\nConfusion Matrix:")
    # Format: [[True Negatives, False Positives], [False Negatives, True Positives]]
    print(confusion_matrix(y_test, predictions))
    
    print("\nClassification Report:")
    print(classification_report(y_test, predictions))
    
    # 7. Serialize and Save the Model
    os.makedirs('../models', exist_ok=True)
    joblib.dump(rf_model, '../models/random_forest.pkl')
    print("\nSuccess! Model serialized and saved to: ../models/random_forest.pkl")

if __name__ == "__main__":
    train_and_evaluate()