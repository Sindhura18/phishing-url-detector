"""
train.py
--------
One-click script to train and save the phishing detection model.

Usage:
    python train.py

Steps:
    1. Downloads/loads the UCI Phishing Websites Dataset
    2. Trains a Random Forest classifier
    3. Evaluates on a held-out test set
    4. Saves the model to models/rf_model.pkl

After running this, launch the Streamlit app:
    streamlit run app.py
"""

import os
import sys
import urllib.request

# ── Dataset Configuration ────────────────────────────────────────────────────
# The UCI Phishing Websites Dataset is publicly available.
# We download it automatically if not already present.
DATASET_URL = (
    "https://raw.githubusercontent.com/dsrscientist/"
    "dataset1/master/phishing.csv"
)
DATASET_PATH = os.path.join("data", "phishing.csv")

# ── Imports ──────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from src.model import load_dataset, train_model, get_feature_importance, save_model


def download_dataset():
    """Downloads the UCI phishing dataset if not already present."""
    if os.path.exists(DATASET_PATH):
        print(f"Dataset already exists at {DATASET_PATH}")
        return

    print("Downloading UCI Phishing Websites Dataset...")
    os.makedirs("data", exist_ok=True)
    try:
        urllib.request.urlretrieve(DATASET_URL, DATASET_PATH)
        print(f"Dataset downloaded to {DATASET_PATH}")
    except Exception as e:
        print(f"\nCould not auto-download dataset: {e}")
        print("\nPlease download the dataset manually:")
        print("1. Go to: https://archive.ics.uci.edu/ml/datasets/phishing+websites")
        print("2. Download 'Training Dataset.arff'")
        print("3. Convert to CSV and save as 'data/phishing.csv'")
        print(
            "\nOr use this Kaggle version: "
            "https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector"
        )
        sys.exit(1)


def main():
    print("=" * 60)
    print("  PHISHING URL DETECTION — MODEL TRAINING")
    print("=" * 60)

    # Step 1: Get the dataset
    download_dataset()

    # Step 2: Load and inspect dataset
    X, y = load_dataset(DATASET_PATH)

    # Step 3: Train Random Forest
    model = train_model(X, y)

    # Step 4: Show which features matter most
    get_feature_importance(model, list(X.columns))

    # Step 5: Save model for use in the Streamlit app
    save_model(model)

    print("\n" + "=" * 60)
    print("  Training complete!")
    print("  Run: streamlit run app.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
