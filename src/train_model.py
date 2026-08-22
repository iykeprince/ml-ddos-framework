import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

def load_and_clean_data(csv_path):
    """Loads network features and drops null/infinite values."""
    print(f"Loading data from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    # Drop rows with missing or anomalous data
    df = df.dropna()
    
    # Assume 'Label' is 0 for Benign, 1 for Malicious
    X = df.drop(columns=['Label', 'Flow ID', 'Source IP', 'Destination IP', 'Timestamp'])
    y = df['Label']
    
    return X, y

def train_random_forest(X_train, y_train):
    """Trains the RF Classifier."""
    print("Training Random Forest model...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)
    return rf_model

def evaluate_model(model, X_test, y_test):
    """Prints evaluation metrics."""
    print("Evaluating model...")
    predictions = model.predict(X_test)
    
    print("\nAccuracy:", accuracy_score(y_test, predictions))
    print("\nConfusion Matrix:\n", confusion_matrix(y_test, predictions))
    print("\nClassification Report:\n", classification_report(y_test, predictions))

if __name__ == "__main__":
    # 1. Load Data
    # Note: Replace with your actual processed CSV path
    X, y = load_and_clean_data('../data/processed/network_traffic.csv')
    
    # 2. Split Data (70/30)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.30, random_state=42)
    
    # 3. Train
    rf_model = train_random_forest(X_train, y_train)
    
    # 4. Evaluate
    evaluate_model(rf_model, X_test, y_test)
    
    # 5. Serialize and Save for the Live Daemon
    joblib.dump(rf_model, '../models/random_forest.pkl')
    print("Model saved to ../models/random_forest.pkl")