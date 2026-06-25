"""
train.py
--------
One-click script to train and save the hybrid phishing detection models.

Usage:
    python train.py
"""

import os
import sys
import urllib.request
import pickle
import random
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# ── Dataset Configuration ────────────────────────────────────────────────────
DATASET_PATH = os.path.join("data", "phishing.csv")

sys.path.insert(0, os.path.dirname(__file__))
from src.model import load_dataset, train_model, get_feature_importance, save_model, TEXT_MODEL_PATH, VECTORIZER_PATH


def generate_synthetic_urls(n_samples=5000):
    """
    Synthesizes a realistic dataset of raw URL strings for training the TF-IDF model.
    This guarantees offline portability and prevents remote download failures.
    """
    legit_domains = [
        "google.com", "yahoo.com", "apple.com", "netflix.com", "github.com",
        "wikipedia.org", "amazon.com", "microsoft.com", "bankofamerica.com",
        "paypal.com", "chase.com", "wellsfargo.com", "facebook.com", "linkedin.com",
        "twitter.com", "youtube.com", "instagram.com", "reddit.com", "nytimes.com",
        "cnn.com", "zoom.us", "dropbox.com", "slack.com", "spotify.com"
    ]
    
    phishing_domains = [
        "paypal-secure-verify.com", "login-paypal.com", "verify-apple-id.com",
        "netflix-update-billing.com", "secure-bank-login.com", "amazon-security-alert.com",
        "chase-security-verification.com", "wellsfargo-verify-account.com",
        "microsoft-security-team.com", "login-netflix-update.com", "signin-paypal-secure.com",
        "google-security-login.com", "facebook-verify-profile.com", "instagram-login-verify.com",
        "secure-dropbox-update.com", "apple-id-security-confirm.com", "bankofamerica-alert-verify.com"
    ]
    
    paths = [
        "", "/", "/login", "/signin", "/verify", "/account", "/update", "/billing",
        "/secure", "/reset-password", "/confirm-identity", "/auth", "/dashboard"
    ]
    
    subpaths = [
        "", "/confirm", "/status", "/login.php", "/signin.html", "/auth.jsp", "/verify-account"
    ]
    
    queries = [
        "", "?session=12893892", "?q=search&lang=en", "?login=true&id=829",
        "?security_check=1", "?uid=8298192&token=928", "?redirect=secure"
    ]

    data = []
    
    # Generate Legitimate URLs (Label = 0)
    for _ in range(n_samples // 2):
        domain = random.choice(legit_domains)
        # 20% chance of www prefix
        prefix = "https://www." if random.random() > 0.8 else "https://"
        path = random.choice(paths)
        sub = random.choice(subpaths) if path else ""
        query = random.choice(queries) if (path or sub) else ""
        url = f"{prefix}{domain}{path}{sub}{query}"
        data.append({"url": url, "label": 0})
        
    # Generate Phishing URLs (Label = 1)
    for _ in range(n_samples // 2):
        domain = random.choice(phishing_domains)
        # Phishing URLs often use insecure HTTP, raw IPs, or complex subdomains
        if random.random() > 0.7:
            # IP based
            ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            prefix = "http://"
            url = f"{prefix}{ip}/login@paypal-secure-verify.com/account/update"
        else:
            prefix = "http://" if random.random() > 0.4 else "https://"
            subdomain = "secure-login." if random.random() > 0.5 else ""
            path = random.choice(paths)
            if not path or path == "/":
                path = "/login"  # Force phishing keyword path
            sub = random.choice(subpaths)
            query = random.choice(queries)
            url = f"{prefix}{subdomain}{domain}{path}{sub}{query}"
        data.append({"url": url, "label": 1})
        
    df = pd.DataFrame(data)
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


def train_text_model(df):
    """Trains a TF-IDF Vectorizer + Logistic Regression model on raw URL texts."""
    print("\nTraining TF-IDF + Logistic Regression text classifier...")
    X_train, X_test, y_train, y_test = train_test_split(
        df["url"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )
    
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    model = LogisticRegression(random_state=42)
    model.fit(X_train_tfidf, y_train)
    
    y_pred = model.predict(X_test_tfidf)
    acc = accuracy_score(y_test, y_pred)
    print(f"Text Model Accuracy: {acc:.4f}")
    print("\nText Model Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    
    # Save text model and vectorizer
    os.makedirs(os.path.dirname(TEXT_MODEL_PATH), exist_ok=True)
    with open(TEXT_MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(VECTORIZER_PATH, "wb") as f:
        pickle.dump(vectorizer, f)
    print(f"Text model saved to: {TEXT_MODEL_PATH}")
    print(f"Vectorizer saved to: {VECTORIZER_PATH}")


def main():
    print("=" * 60)
    print("  PHISHING URL DETECTION — HYBRID MODEL ENSEMBLE TRAINING")
    print("=" * 60)

    # Step 1: Check dataset
    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: Dataset not found at {DATASET_PATH}. Please place phishing.csv in the data/ folder.")
        sys.exit(1)

    # Step 2: Train Feature-based Random Forest Model
    X, y = load_dataset(DATASET_PATH)
    rf_model = train_model(X, y)
    get_feature_importance(rf_model, list(X.columns))
    save_model(rf_model)

    # Step 3: Train Text-based TF-IDF Model
    df_text = generate_synthetic_urls(5000)
    train_text_model(df_text)

    print("\n" + "=" * 60)
    print("  Training complete for both models!")
    print("  Run: streamlit run app.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
