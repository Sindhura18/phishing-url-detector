"""
model.py
--------
Handles training, evaluation, and persistence of the phishing detection model.

Why Random Forest?
- Works well with mixed feature types (binary flags + numeric counts)
- Provides feature importance — we can explain WHY a URL is flagged
- Resistant to overfitting compared to a single Decision Tree
- Fast prediction — ideal for real-time URL classification
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "rf_model.pkl")


def load_dataset(filepath: str) -> tuple[pd.DataFrame, pd.Series]:
    """
    Loads the UCI Phishing Websites Dataset from a CSV file.

    Dataset labels:
        1  → Phishing
       -1  → Legitimate

    We rename -1 → 0 for easier binary classification.

    Args:
        filepath: Path to the CSV file

    Returns:
        X: Feature DataFrame (30 columns)
        y: Label Series (0 = legitimate, 1 = phishing)
    """
    df = pd.read_csv(filepath)

    # The last column 'Result' is the label
    X = df.drop(columns=["Result"])
    y = df["Result"]

    # Convert -1 (legitimate) → 0 for standard binary classification
    y = y.map({-1: 0, 1: 1})

    print(f"Dataset loaded: {len(df)} samples, {X.shape[1]} features")
    print(f"Class distribution:\n  Phishing  : {(y==1).sum()}")
    print(f"  Legitimate: {(y==0).sum()}")

    return X, y


def train_model(X: pd.DataFrame, y: pd.Series) -> RandomForestClassifier:
    """
    Trains a Random Forest classifier on the phishing dataset.

    Key hyperparameters explained:
    - n_estimators=100: Use 100 decision trees and average their predictions
      (reduces variance, prevents overfitting)
    - max_depth=None: Trees can grow as deep as needed
      (dataset is clean, so this doesn't overfit badly)
    - random_state=42: Ensures reproducible results

    Args:
        X: Feature matrix
        y: Labels (0=legitimate, 1=phishing)

    Returns:
        Trained RandomForestClassifier
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
        # stratify=y ensures both train and test sets
        # have the same phishing/legitimate ratio
    )

    print("\nTraining Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1  # Use all CPU cores for faster training
    )
    model.fit(X_train, y_train)

    # Evaluate on held-out test set
    evaluate_model(model, X_test, y_test)

    # Cross-validation: more reliable estimate of real performance
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="f1")
    print(f"\n5-Fold Cross-Validation F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    return model


def evaluate_model(model: RandomForestClassifier, X_test: pd.DataFrame, y_test: pd.Series):
    """
    Prints full evaluation metrics on the test set.

    Why F1-score matters more than accuracy here:
    - If 90% of URLs were legitimate, a dumb model that always says
      "legitimate" would get 90% accuracy but catch ZERO phishing.
    - F1-score balances precision and recall, so we measure how well
      we actually detect phishing.
    - Recall (sensitivity) is most critical: missing a phishing URL
      (false negative) is far more dangerous than a false alarm.
    """
    y_pred = model.predict(X_test)

    print("\n" + "=" * 50)
    print("MODEL EVALUATION")
    print("=" * 50)
    print(f"\nAccuracy : {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  True Negatives  (Legit → Legit)   : {cm[0][0]}")
    print(f"  False Positives (Legit → Phishing) : {cm[0][1]}")
    print(f"  False Negatives (Phish → Legit)    : {cm[1][0]}  ← most dangerous")
    print(f"  True Positives  (Phish → Phishing) : {cm[1][1]}")


def get_feature_importance(model: RandomForestClassifier, feature_names: list) -> pd.DataFrame:
    """
    Returns a sorted DataFrame of feature importances.
    Useful for explaining which URL characteristics matter most.

    In interviews: "I used feature_importances_ from Random Forest
    to identify that IP address usage, URL length, and domain age
    were the strongest indicators of phishing."
    """
    importance_df = pd.DataFrame({
        "feature": feature_names,
        "importance": model.feature_importances_
    }).sort_values("importance", ascending=False).reset_index(drop=True)

    print("\nTop 10 Most Important Features:")
    print(importance_df.head(10).to_string(index=False))

    return importance_df


def save_model(model: RandomForestClassifier, path: str = MODEL_PATH):
    """Saves trained model to disk using pickle."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(model, f)
    print(f"\nModel saved to: {path}")


def load_model(path: str = MODEL_PATH) -> RandomForestClassifier:
    """Loads a previously trained model from disk."""
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"No trained model found at {path}. "
            "Please run train.py first."
        )
    with open(path, "rb") as f:
        model = pickle.load(f)
    return model


def predict(model: RandomForestClassifier, features: dict) -> dict:
    """
    Makes a prediction for a single URL given its extracted features.

    Args:
        model: Trained RandomForestClassifier
        features: Dictionary from extract_features(url)

    Returns:
        Dictionary with:
          - label: "Phishing" or "Legitimate"
          - confidence: probability score (0-100%)
    """
    feature_vector = np.array(list(features.values())).reshape(1, -1)

    prediction = model.predict(feature_vector)[0]
    probability = model.predict_proba(feature_vector)[0]

    # predict_proba returns [prob_legit, prob_phishing]
    confidence = probability[1] if prediction == 1 else probability[0]

    return {
        "label": "Phishing" if prediction == 1 else "Legitimate",
        "confidence": round(confidence * 100, 2),
        "is_phishing": bool(prediction == 1)
    }
