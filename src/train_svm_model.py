import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os

def clean_and_prepare_data(filepath):
    print(f"Loading dataset from {filepath}...")
    df = pd.read_csv(filepath, low_memory=False)
    
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # Map labels: 0 for Benign, 1 for Malicious
    df['Label_Binary'] = df['Label'].apply(lambda x: 0 if 'BENIGN' in str(x).upper() else 1)
    
    # Isolate temporal features (Must match the RF script exactly)
    target_features = [
        'Flow Duration', 
        'Fwd IAT Mean', 
        'Bwd IAT Mean', 
        'Fwd PSH Flags',
        'Fwd Packets/s',
        'Bwd Packets/s'
    ]
    
    available_features = [f for f in target_features if f in df.columns]
    
    X = df[available_features]
    y = df['Label_Binary']
    
    return X, y

def train_and_evaluate_svm():
    csv_path = '../data/raw/cicddos2019_sample.csv' 
    
    X, y = clean_and_prepare_data(csv_path)
    
    # SVMs are highly computationally expensive. If your dataset is massive, 
    # we take a random sample to ensure it trains in a reasonable time.
    if X.shape[0] > 50000:
        print("\nDataset is large. Sub-sampling 50,000 rows for SVM efficiency...")
        X = X.sample(n=50000, random_state=42)
        y = y.loc[X.index]

    print("\nSplitting data (70% Training / 30% Testing)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    
    print("Applying StandardScaler...")
    scaler = StandardScaler()
    # Fit the scaler ONLY on the training data to prevent data leakage
    X_train_scaled = scaler.fit_transform(X_train)
    # Transform the test data using the fitted scaler
    X_test_scaled = scaler.transform(X_test)
    
    print("Training Support Vector Machine (RBF Kernel)...")
    # Using the Radial Basis Function (RBF) kernel as outlined in Chapter 3
    svm_model = SVC(kernel='rbf', random_state=42)
    svm_model.fit(X_train_scaled, y_train)
    
    print("\nEvaluating SVM Model on 30% Holdout Test Data...")
    predictions = svm_model.predict(X_test_scaled)
    
    print("\n" + "="*30)
    print("       SVM MODEL RESULTS")
    print("="*30)
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))
    
    print("\nClassification Report:")
    print(classification_report(y_test, predictions))
    
    # Serialize and Save BOTH the Model and the Scaler
    os.makedirs('../models', exist_ok=True)
    joblib.dump(svm_model, '../models/svm_model.pkl')
    joblib.dump(scaler, '../models/svm_scaler.pkl')
    print("\nSuccess! Model and Scaler serialized to the ../models/ directory.")

if __name__ == "__main__":
    train_and_evaluate_svm()