import sys
import os
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.api import app, API_KEY

client = TestClient(app)


def test_health_endpoint():
    """Tests the Health check endpoint returns 200 and indicates healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert "models_loaded" in response.json()


def test_scan_endpoint_missing_api_key():
    """Tests that accessing the scan endpoint without an API key header raises a 422 validation error."""
    response = client.post("/api/v1/scan", json={"url": "https://google.com"})
    # FastAPI returns 422 Unprocessable Entity when required header 'x-api-key' is missing
    assert response.status_code == 422


def test_scan_endpoint_invalid_api_key():
    """Tests that accessing the scan endpoint with an invalid API key raises a 401 Unauthorized error."""
    headers = {"X-API-Key": "invalid-token-123"}
    response = client.post("/api/v1/scan", json={"url": "https://google.com"}, headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API key."


def test_scan_endpoint_valid_url_legitimate():
    """Tests scanning a legitimate URL with a valid API Key."""
    headers = {"X-API-Key": API_KEY}
    response = client.post("/api/v1/scan", json={"url": "https://google.com"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    
    # Assert return structure
    assert data["url"] == "https://google.com"
    assert "threat_intel" in data
    assert "models" in data
    assert "explainability" in data
    
    # Assert threat details
    assert data["threat_intel"]["domain"] == "google.com"
    assert data["threat_intel"]["severity"] in ["Low", "Medium", "High", "Critical"]
    
    # Assert ensemble predictions are present
    assert "random_forest" in data["models"]
    assert "tfidf_text" in data["models"]
    assert data["models"]["random_forest"]["is_phishing"] is False


def test_scan_endpoint_valid_url_phishing():
    """Tests scanning a clearly phishing URL with a valid API Key."""
    headers = {"X-API-Key": API_KEY}
    phish_url = "http://paypal-secure-verify.com/account/update"
    response = client.post("/api/v1/scan", json={"url": phish_url}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    
    # Assert model classifications
    assert data["models"]["random_forest"]["is_phishing"] is True
    assert data["threat_intel"]["is_blacklisted"] is True
    assert data["threat_intel"]["severity"] == "Critical"


def test_scan_email_endpoint_missing_api_key():
    """Tests that accessing the email scan endpoint without an API key raises 422."""
    response = client.post("/api/v1/scan-email", json={"email_text": "Hello"})
    assert response.status_code == 422


def test_scan_email_endpoint_invalid_api_key():
    """Tests that accessing the email scan endpoint with an invalid API key raises 401."""
    headers = {"X-API-Key": "invalid-token-123"}
    response = client.post("/api/v1/scan-email", json={"email_text": "Hello"}, headers=headers)
    assert response.status_code == 401


def test_scan_email_legitimate():
    """Tests scanning a clean, authentic email with SPF and DKIM pass headers."""
    headers = {"X-API-Key": API_KEY}
    email_text = (
        "From: service@google.com\n"
        "Return-Path: service@google.com\n"
        "Received-SPF: pass\n"
        "DKIM-Signature: pass\n"
        "DMARC: pass\n\n"
        "Hello user, this is a legitimate message from Google."
    )
    response = client.post("/api/v1/scan-email", json={"email_text": email_text}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["overall_severity"] == "Safe"
    assert data["email_summary"]["spoof_detected"] is False
    assert len(data["email_summary"]["extracted_urls"]) == 0
    assert len(data["incident_playbook"]) == 1
    assert data["incident_playbook"][0]["action"] == "No Action Required"


def test_scan_email_malicious_spoofed_and_link():
    """Tests scanning a highly malicious spoofed email containing a threat URL."""
    headers = {"X-API-Key": API_KEY}
    email_text = (
        "From: billing@paypal.com\n"
        "Return-Path: hacker@evil-direct.com\n"
        "Received-SPF: fail\n"
        "DMARC: fail\n\n"
        "URGENT: Your account is suspended. Verify immediately at http://paypal-secure-verify.com/login"
    )
    response = client.post("/api/v1/scan-email", json={"email_text": email_text}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["overall_severity"] == "Malicious"
    assert data["email_summary"]["spoof_detected"] is True
    assert "http://paypal-secure-verify.com/login" in data["email_summary"]["extracted_urls"]
    assert len(data["url_scan_results"]) > 0
    assert data["url_scan_results"][0]["is_malicious"] is True
    
    actions = [action["action"] for action in data["incident_playbook"]]
    assert "Quarantine Email" in actions
    assert "Block Sender Domain" in actions
    assert "Block Malicious URLs" in actions
    assert "Revoke User Sessions" in actions

