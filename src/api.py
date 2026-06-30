import os
import sys
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from src.features import extract_cybersecurity_report
from src.model import load_model, load_text_model, predict, predict_text, explain_prediction

# Default secure API Key (in real production, load this from environment variables)
API_KEY = os.getenv("API_KEY", "phish-detector-token-2026")

# Setup Rate Limiting
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="Phishing URL Detector Security API",
    description="Microservice API for live URL phishing analysis, security lookups, and ML model predictions.",
    version="1.0.0"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load Models at Startup
try:
    rf_model = load_model()
    text_model, vectorizer = load_text_model()
    print("AI Models successfully loaded.")
except Exception as e:
    print(f"WARNING: Could not load models: {e}. Please ensure train.py has been run.")
    rf_model, text_model, vectorizer = None, None, None


class ScanRequest(BaseModel):
    url: str


class ScanResponse(BaseModel):
    url: str
    threat_intel: dict
    models: dict
    explainability: dict


class EmailScanRequest(BaseModel):
    email_text: str


class EmailScanResponse(BaseModel):
    email_summary: dict
    url_scan_results: list
    incident_playbook: list
    overall_severity: str


# Security dependency
def verify_api_key(x_api_key: str = Header(..., description="API Access Token")):
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key."
        )


@app.get("/health")
def health():
    """Simple API health check endpoint."""
    return {
        "status": "healthy",
        "models_loaded": rf_model is not None and text_model is not None
    }


import re

def parse_email_threats(email_text: str) -> dict:
    """Parses raw email text to extract From, Return-Path, SPF, DKIM, DMARC status and URLs."""
    from_match = re.search(r'(?i)^From:\s*(.*)', email_text, re.MULTILINE)
    return_path_match = re.search(r'(?i)^Return-Path:\s*(.*)', email_text, re.MULTILINE)
    
    spf_match = re.search(r'(?i)(?:Received-SPF|SPF):\s*(pass|fail|softfail|neutral|none)', email_text)
    dkim_match = re.search(r'(?i)(?:DKIM-Signature|DKIM):\s*(pass|fail|invalid|none)', email_text)
    dmarc_match = re.search(r'(?i)DMARC:\s*(pass|fail|none)', email_text)
    
    from_header = from_match.group(1).strip() if from_match else ""
    return_path = return_path_match.group(1).strip() if return_path_match else ""
    
    spf_status = spf_match.group(1).upper() if spf_match else "NONE"
    dkim_status = dkim_match.group(1).upper() if dkim_match else "NONE"
    dmarc_status = dmarc_match.group(1).upper() if dmarc_match else "NONE"

    
    def get_domain_from_email(email_str: str) -> str:
        match = re.search(r'[\w\.-]+@([\w\.-]+)', email_str)
        return match.group(1).lower() if match else ""
        
    from_domain = get_domain_from_email(from_header)
    return_path_domain = get_domain_from_email(return_path)
    
    spoof_detected = False
    spoof_reasons = []
    
    if from_domain and return_path_domain and from_domain != return_path_domain:
        spoof_detected = True
        spoof_reasons.append(f"Sender Address Mismatch: 'From' domain ({from_domain}) does not match 'Return-Path' domain ({return_path_domain}).")
        
    if spf_status in ["FAIL", "SOFTFAIL"]:
        spoof_detected = True
        spoof_reasons.append(f"SPF authentication failed ({spf_status.lower()}).")
        
    if dkim_status in ["FAIL", "INVALID"]:
        spoof_detected = True
        spoof_reasons.append("DKIM cryptographic signature check failed.")
        
    if dmarc_status == "FAIL":
        spoof_detected = True
        spoof_reasons.append("DMARC domain alignment policy failed.")
        
    # Extract all URLs
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, email_text)
    cleaned_urls = []
    for u in urls:
        u_clean = u.strip().rstrip(".,;:")
        if u_clean not in cleaned_urls:
            cleaned_urls.append(u_clean)
            
    body_reasons = []
    urgent_keywords = ["urgent", "action required", "suspend", "unauthorized", "verify", "password reset", "billing update", "immediate", "security alert"]
    for kw in urgent_keywords:
        if kw in email_text.lower():
            body_reasons.append(f"Urgent keyword detected: '{kw}'")
            
    overall_severity = "Safe"
    if spoof_detected or len(cleaned_urls) > 0 or body_reasons:
        overall_severity = "Suspicious"
        
    return {
        "from_header": from_header,
        "from_domain": from_domain,
        "return_path": return_path,
        "return_path_domain": return_path_domain,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "spoof_detected": spoof_detected,
        "spoof_reasons": spoof_reasons,
        "body_reasons": body_reasons,
        "extracted_urls": cleaned_urls,
        "overall_severity": overall_severity
    }


@app.post("/api/v1/scan-email", response_model=EmailScanResponse)
@limiter.limit("15/minute")
def scan_email(payload: EmailScanRequest, request: Request, x_api_key: str = Header(...)):
    """
    Parses and scans email text:
    - Verifies SPF/DKIM/DMARC headers
    - Detects sender address spoofing
    - Scans all extracted links via URL models and threat intelligence
    - Compiles a custom SOC incident response playbook
    """
    verify_api_key(x_api_key)
    
    email_text = payload.email_text
    email_summary = parse_email_threats(email_text)
    
    url_scan_results = []
    has_malicious_url = False
    
    if rf_model is None or text_model is None:
        raise HTTPException(
            status_code=503,
            detail="AI models are not loaded. Run train.py first."
        )
        
    for url in email_summary["extracted_urls"]:
        url_std = url
        if not url_std.startswith(("http://", "https://")):
            url_std = "http://" + url_std
            
        threat_intel = extract_cybersecurity_report(url_std)
        rf_pred = predict(rf_model, url_std)
        text_pred = predict_text(text_model, vectorizer, url_std)
        
        is_malicious = (threat_intel["severity"] == "Critical") or (rf_pred["label"] == "Phishing") or (text_pred["label"] == "Phishing")
        if is_malicious:
            has_malicious_url = True
            
        url_scan_results.append({
            "url": url,
            "severity": threat_intel["severity"],
            "reasons": threat_intel["reasons"],
            "rf_pred": rf_pred["label"],
            "text_pred": text_pred["label"],
            "is_malicious": is_malicious
        })

        
    overall_severity = email_summary["overall_severity"]
    if has_malicious_url:
        overall_severity = "Malicious"
        
    # Generate incident playbook
    playbook = []
    from_domain = email_summary["from_domain"]
    return_path_domain = email_summary["return_path_domain"]
    block_domain = return_path_domain if return_path_domain else from_domain
    
    if overall_severity == "Malicious":
        playbook.extend([
            {"action": "Quarantine Email", "description": "Execute global purge search-and-destroy command across all user mailboxes to delete this message.", "status": "Recommended"},
            {"action": "Block Sender Domain", "description": f"Add the sender domain '{block_domain if block_domain else 'unknown'}' to the email gateway blocklist.", "status": "Recommended"},
            {"action": "Block Malicious URLs", "description": "Propagate the detected malicious URL(s) to corporate proxy and DNS firewall blocklists.", "status": "Recommended"},
            {"action": "Revoke User Sessions", "description": "Force-revoke active login sessions and OAuth tokens for any users who opened or clicked links in this email.", "status": "Immediate Action"},
            {"action": "Mandatory Password Reset", "description": "Trigger automated credential resets for affected recipients.", "status": "Immediate Action"}
        ])
    elif overall_severity == "Suspicious":
        playbook.extend([
            {"action": "Quarantine Email", "description": "Move the email to user junk/quarantine folders while investigation is pending.", "status": "Recommended"},
            {"action": "Alert Recipients", "description": "Deliver a warning banner to the recipient inbox warning against interacting with links.", "status": "Completed"},
            {"action": "Analyze Headers further", "description": "Check mail server logs to trace the originating IP of the message and verify sender legitimacy.", "status": "Investigation Required"}
        ])
    else:
        playbook.append({
            "action": "No Action Required",
            "description": "Email authenticated successfully and contains no suspicious threat signatures.",
            "status": "Info"
        })
        
    return {
        "email_summary": email_summary,
        "url_scan_results": url_scan_results,
        "incident_playbook": playbook,
        "overall_severity": overall_severity
    }



@app.post("/api/v1/scan", response_model=ScanResponse)
@limiter.limit("15/minute")
def scan_url(payload: ScanRequest, request: Request, x_api_key: str = Header(...)):
    """
    Scans a single URL.
    - Validates API key authentication
    - Applies IP-based rate limiting (15 scans per minute)
    - Performs DNS and WHOIS threat intelligence scans
    - Evaluates the URL using both structural Random Forest and text TF-IDF models
    - Computes local feature attribution (XAI) for explanation
    """
    # 1. Verify API Key
    verify_api_key(x_api_key)
    
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
        
    # Standardize URL protocol if missing (for feature extractors)
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    if rf_model is None or text_model is None:
        raise HTTPException(
            status_code=503,
            detail="AI models are not loaded. Run train.py first."
        )

    # 2. Extract Cybersecurity Report (DNS, WHOIS, Entropy, Blocklist)
    threat_intel = extract_cybersecurity_report(url)
    
    # 3. Model Predictions (Model Ensemble)
    rf_pred = predict(rf_model, url)
    text_pred = predict_text(text_model, vectorizer, url)
    
    # 4. Explainable AI (XAI)
    explainability = explain_prediction(rf_model, url)

    return {
        "url": url,
        "threat_intel": threat_intel,
        "models": {
            "random_forest": rf_pred,
            "tfidf_text": text_pred
        },
        "explainability": explainability
    }
