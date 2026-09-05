import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
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

    # Force every feature + Label column to numeric. This catches stray
    # duplicated header rows (e.g. from a shell `cat file1.csv file2.csv`
    # concatenation instead of pandas.concat) or any other non-numeric
    # garbage row - anything that can't be coerced becomes NaN and is
    # dropped below, instead of crashing GridSearchCV mid-run.
    before_rows = len(df)
    for col in FEATURE_COLUMNS + ['Label']:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=FEATURE_COLUMNS + ['Label'], inplace=True)

    dropped = before_rows - len(df)
    if dropped > 0:
        print(f"[!] Dropped {dropped} row(s) with non-numeric or missing values "
              f"(check for a duplicated/embedded header row if this number is unexpectedly high).")

    X = df[FEATURE_COLUMNS]
    y = df['Label'].astype(int)  # already 0=benign, 1=malicious from label_flows.py
    return X, y


def train_and_evaluate():
    # Point this at your actual generated dataset, not the public CICDDoS2019 sample
    csv_path = './data/processed/windowed_flows_labeled.csv'

    X, y = load_and_clean_data(csv_path)
    print(f"Rows: {X.shape[0]} | Benign: {(y == 0).sum()} | Malicious: {(y == 1).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )

    # Regularized, fixed hyperparameters (no GridSearchCV) - deliberately
    # conservative given the small dataset (7,624 rows, 386-sample minority
    # class): shallow trees, small forest, high leaf/split minimums, and
    # class_weight='balanced' to counter the ~19:1 malicious:benign ratio.
    print("Training Random Forest with fixed, regularized hyperparameters...")
    rf_model = RandomForestClassifier(
        n_estimators=50,
        max_depth=5,
        min_samples_split=10,
        min_samples_leaf=8,
        max_features='sqrt',
        criterion='gini',
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    # 10-fold stratified CV score on the training set, for reference only
    # (no hyperparameter search happening here - this just reports how
    # stable this fixed configuration is across folds).
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    cv_scores = cross_val_score(rf_model, X_train, y_train, cv=cv, scoring='f1', n_jobs=-1)
    print(f"10-fold CV F1 scores: {cv_scores}")
    print(f"Mean CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

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