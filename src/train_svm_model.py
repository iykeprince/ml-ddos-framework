import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    roc_auc_score, ConfusionMatrixDisplay
)
import matplotlib.pyplot as plt
import joblib
import os

# Must match train_rf_model.py and live_daemon.py exactly (same columns, same order)
FEATURE_COLUMNS = [
    'Flow Duration',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'Fwd IAT Std',
    'Bwd IAT Std',
    'SYN Flag Count',
    'ACK Flag Count'
]


def load_and_clean_data(csv_path):
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()

    if 'Label' not in df.columns:
        raise ValueError(f"'Label' column not found. Columns present: {list(df.columns)}")

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            f"Missing expected feature columns: {missing}. "
            f"Columns present: {list(df.columns)}"
        )

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=FEATURE_COLUMNS + ['Label'], inplace=True)

    X = df[FEATURE_COLUMNS]
    y = df['Label'].astype(int)
    return X, y


def train_and_evaluate_svm():
    csv_path = './data/processed/cleaned_narrow_flows.csv'

    X, y = load_and_clean_data(csv_path)
    print(f"Rows: {X.shape[0]} | Benign: {(y == 0).sum()} | Malicious: {(y == 1).sum()}")

    # SVM training time scales super-linearly with sample count - subsample if huge.
    if X.shape[0] > 50000:
        print("\nDataset is large. Sub-sampling 50,000 rows for SVM efficiency...")
        X = X.sample(n=50000, random_state=42)
        y = y.loc[X.index]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )

    print("Applying StandardScaler (fit on training data only, to avoid leakage)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("Training SVM (kernel=rbf)...")
    # probability=True is required so predict_proba works later for AUC
    # and for the live daemon's confidence-threshold mitigation logic.
    svm_model = SVC(kernel='rbf', C=1, gamma='scale', random_state=42, probability=True)
    svm_model.fit(X_train_scaled, y_train)

    predictions = svm_model.predict(X_test_scaled)
    probs = svm_model.predict_proba(X_test_scaled)[:, 1]

    print("\n" + "=" * 30)
    print("       SVM MODEL RESULTS")
    print("=" * 30)
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(f"AUC:      {roc_auc_score(y_test, probs):.4f}")

    cm = confusion_matrix(y_test, predictions)
    print("\nConfusion Matrix (rows=actual, cols=predicted):\n", cm)
    print("\nClassification Report:\n", classification_report(y_test, predictions))

    # --- Save confusion matrix figure for Figure 4.3 ---
    os.makedirs('./figures', exist_ok=True)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Benign', 'Malicious'])
    disp.plot(cmap='Oranges')
    plt.title('SVM Confusion Matrix (30% Holdout)')
    plt.savefig('./figures/svm_confusion_matrix.png', dpi=200, bbox_inches='tight')
    print("Saved confusion matrix to ./figures/svm_confusion_matrix.png")

    # --- Save model AND scaler (daemon needs both) ---
    os.makedirs('./models', exist_ok=True)
    joblib.dump(svm_model, './models/svm_model.pkl')
    joblib.dump(scaler, './models/svm_scaler.pkl')
    print("\nSuccess! Model and Scaler saved to ./models/")


if __name__ == "__main__":
    train_and_evaluate_svm()