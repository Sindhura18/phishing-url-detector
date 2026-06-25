"""
app.py
------
Streamlit web app for real-time phishing URL detection.

Run with:
    streamlit run app.py

The app:
1. Takes a URL input from the user
2. Extracts 10 URL-based features
3. Passes features to trained Random Forest model
4. Displays prediction with confidence score and feature breakdown
"""

import streamlit as st
import pandas as pd
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from src.features import extract_features
from src.model import load_model, predict

# ── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🔐",
    layout="centered"
)

# ── Header ───────────────────────────────────────────────────────────────────
st.title("🔐 Phishing URL Detector")
st.markdown(
    "Detects whether a URL is **phishing** or **legitimate** using "
    "Machine Learning (Random Forest) trained on the UCI Phishing Websites Dataset."
)
st.markdown("---")

# ── Load Model ───────────────────────────────────────────────────────────────
@st.cache_resource  # Cache so model loads only once
def get_model():
    try:
        return load_model()
    except FileNotFoundError:
        return None

model = get_model()

if model is None:
    st.error(
        "⚠️ No trained model found. "
        "Please run `python train.py` first to train and save the model."
    )
    st.stop()

# ── URL Input ─────────────────────────────────────────────────────────────────
st.subheader("Enter a URL to analyse")

url_input = st.text_input(
    label="URL",
    placeholder="e.g. https://paypal.com/login or http://192.168.1.1/verify@secure.com",
    label_visibility="collapsed"
)

# ── Example URLs ─────────────────────────────────────────────────────────────
st.markdown("**Try these examples:**")
col1, col2 = st.columns(2)

with col1:
    if st.button("🟢 Legitimate example"):
        url_input = "https://www.google.com/search?q=python"

with col2:
    if st.button("🔴 Phishing example"):
        url_input = "http://192.168.1.1/login@paypal-secure-verify.com/account/update"

# ── Analysis ──────────────────────────────────────────────────────────────────
if url_input:
    st.markdown("---")

    # Extract features
    features = extract_features(url_input)

    # Get prediction
    result = predict(model, features)

    # ── Result Banner ──────────────────────────────────────────────────────
    if result["is_phishing"]:
        st.error(
            f"⚠️ **PHISHING DETECTED**  \n"
            f"Confidence: **{result['confidence']}%**"
        )
    else:
        st.success(
            f"✅ **URL appears LEGITIMATE**  \n"
            f"Confidence: **{result['confidence']}%**"
        )

    # ── Confidence Gauge ──────────────────────────────────────────────────
    st.progress(result["confidence"] / 100)
    st.caption(
        "⚠️ Note: This model analyses URL structure only. "
        "Always exercise caution with unknown links."
    )

    # ── Feature Breakdown ─────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("🔍 Feature Analysis")
    st.markdown("Here's what the model found in this URL:")

    FEATURE_DESCRIPTIONS = {
        "has_ip_address":          ("IP in URL (instead of domain name)", "Suspicious"),
        "has_at_symbol":           ("'@' symbol in URL", "Suspicious"),
        "url_length":              ("URL length (characters)", "Long = suspicious"),
        "has_https":               ("Uses HTTPS (secure)", "Good if present"),
        "has_double_slash":        ("Double slash redirect (//)", "Suspicious"),
        "dot_count":               ("Number of dots (subdomains)", "Many = suspicious"),
        "has_hyphen_in_domain":    ("Hyphen (-) in domain name", "Suspicious"),
        "url_depth":               ("URL depth (/ segments)", "Deep = suspicious"),
        "uses_shortening_service": ("Uses URL shortening service", "Suspicious"),
        "has_suspicious_keywords": ("Contains phishing keywords", "Suspicious"),
    }

    rows = []
    for key, value in features.items():
        description, note = FEATURE_DESCRIPTIONS.get(key, (key, ""))
        rows.append({
            "Feature": description,
            "Value": value,
            "Note": note,
        })

    feature_df = pd.DataFrame(rows)
    st.dataframe(feature_df, use_container_width=True, hide_index=True)

    # ── URL Parsed ────────────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("🔗 URL Details")
    import urllib.parse
    parsed = urllib.parse.urlparse(url_input)
    st.code(
        f"Protocol : {parsed.scheme}\n"
        f"Domain   : {parsed.netloc}\n"
        f"Path     : {parsed.path}\n"
        f"Query    : {parsed.query}"
    )

# ── Footer ───────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "Built with **Python**, **scikit-learn**, and **Streamlit**  \n"
    "Dataset: [UCI Phishing Websites Dataset](https://archive.ics.uci.edu/ml/datasets/phishing+websites)  \n"
    "Model: Random Forest Classifier — ~96% accuracy on UCI benchmark"
)
