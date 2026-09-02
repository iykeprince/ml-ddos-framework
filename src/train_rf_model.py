import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    roc_auc_score, ConfusionMatrixDisplay
)
import matplotlib.pyplot as plt
import joblib
import os

# Must match live_daemon.py's FEATURE_COLUMNS exactly (same order) and the
# columns present in cleaned_narrow_flows.csv (already JASP-validated).
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
    y = df['Label'].astype(int)  # already 0=benign, 1=malicious from label_flows.py
    return X, y


def train_and_evaluate():
    # Point this at your actual generated dataset
    csv_path = './data/processed/cleaned_narrow_flows.csv'

    X, y = load_and_clean_data(csv_path)
    print(f"Rows: {X.shape[0]} | Benign: {(y == 0).sum()} | Malicious: {(y == 1).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )

    # Table 3.1 search grid
    param_grid = {
        'n_estimators': [50, 100, 200, 300],
        'max_depth': [10, 20, 30, None],
        'min_samples_split': [2, 5, 10],
        'max_features': ['sqrt', 'log2']
    }

    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)

    print("Running GridSearchCV (10-fold, scoring=F1)... this can take a while.")
    grid = GridSearchCV(
        RandomForestClassifier(random_state=42, n_jobs=-1, criterion='gini'),
        param_grid,
        cv=cv,
        scoring='f1',
        n_jobs=-1,
        verbose=1
    )
    grid.fit(X_train, y_train)

    print(f"\nBest params: {grid.best_params_}")
    print(f"Best mean CV F1 score: {grid.best_score_:.4f}")

    rf_model = grid.best_estimator_

    predictions = rf_model.predict(X_test)
    probs = rf_model.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 30)
    print("       MODEL RESULTS")
    print("=" * 30)
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(f"AUC:      {roc_auc_score(y_test, probs):.4f}")

    cm = confusion_matrix(y_test, predictions)
    print("\nConfusion Matrix (rows=actual, cols=predicted):\n", cm)
    print("\nClassification Report:\n", classification_report(y_test, predictions))

    # --- Save confusion matrix figure for Figure 4.2 ---
    os.makedirs('./figures', exist_ok=True)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Benign', 'Malicious'])
    disp.plot(cmap='Blues')
    plt.title('Random Forest Confusion Matrix (30% Holdout)')
    plt.savefig('./figures/rf_confusion_matrix.png', dpi=200, bbox_inches='tight')
    print("Saved confusion matrix to ./figures/rf_confusion_matrix.png")

    # --- Feature importance, for your Feature Importance / Interpretability section ---
    importances = pd.Series(
        rf_model.feature_importances_, index=FEATURE_COLUMNS
    ).sort_values(ascending=False)
    print("\nFeature Importances (Gini):\n", importances)

    # --- Save model ---
    os.makedirs('./models', exist_ok=True)
    joblib.dump(rf_model, './models/random_forest.pkl')
    print("\nSuccess! Model saved to: ./models/random_forest.pkl")


if __name__ == "__main__":
    train_and_evaluate()