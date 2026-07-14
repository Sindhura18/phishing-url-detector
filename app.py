import streamlit as st
import pandas as pd
import requests
import os
import time
import json

# Configuration
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
API_KEY = os.getenv("API_KEY")

# Require API_KEY env var if connecting to a remote FastAPI backend
if not API_KEY and BACKEND_URL.lower() != "local":
    raise ValueError("CRITICAL: The 'API_KEY' environment variable must be set when connecting to a remote backend service.")

# Try to import local modules for offline/standalone backup mode
try:
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from src.features import extract_cybersecurity_report
    from src.model import load_model, load_text_model, predict, predict_text, explain_prediction
    from src.api import parse_email_threats
    LOCAL_MODE_AVAILABLE = True
except Exception as e:
    LOCAL_MODE_AVAILABLE = False

@st.cache_resource
def get_local_models():
    if not LOCAL_MODE_AVAILABLE:
        return None, None, None
    try:
        rf = load_model()
        text_m, vec = load_text_model()
        return rf, text_m, vec
    except Exception as e:
        return None, None, None

# ── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatIntel Phishing Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS for Premium Cybersecurity Aesthetics ─────────────────────────
st.markdown(
    """
    <style>
    .metric-card {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 10px;
        padding: 15px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        text-align: center;
    }
    .badge-critical {
        background-color: #ff4b4b;
        color: white;
        padding: 5px 10px;
        border-radius: 5px;
        font-weight: bold;
    }
    .badge-high {
        background-color: #ffa500;
        color: white;
        padding: 5px 10px;
        border-radius: 5px;
        font-weight: bold;
    }
    .badge-medium {
        background-color: #ffe600;
        color: black;
        padding: 5px 10px;
        border-radius: 5px;
        font-weight: bold;
    }
    .badge-low {
        background-color: #00cc66;
        color: white;
        padding: 5px 10px;
        border-radius: 5px;
        font-weight: bold;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ── Session State Initialisation ─────────────────────────────────────────────
if "total_scans" not in st.session_state:
    st.session_state.total_scans = 0
if "threats_detected" not in st.session_state:
    st.session_state.threats_detected = 0
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "average_response" not in st.session_state:
    st.session_state.average_response = 0.0
if "last_scanned_url" not in st.session_state:
    st.session_state.last_scanned_url = ""
if "last_url_result" not in st.session_state:
    st.session_state.last_url_result = None
if "last_email_result" not in st.session_state:
    st.session_state.last_email_result = None

# Callbacks to safely update widget session states and perform scans
def set_url_input(url_val: str):
    st.session_state.url_scanner_input = url_val

def set_email_input(email_val: str):
    st.session_state.email_text_input_area = email_val

def run_url_scan(url_val: str):
    url_val = url_val.strip()
    if not url_val:
        st.session_state.last_url_result = None
        st.session_state.last_scanned_url = ""
        return
        
    start_time = time.time()
    result = None
    used_local_fallback = False
    
    # Standardize URL protocol if missing
    url_std = url_val
    if not url_std.startswith(("http://", "https://")):
        url_std = "http://" + url_std

    if BACKEND_URL.lower() != "local":
        try:
            headers = {"X-API-Key": API_KEY}
            payload = {"url": url_std}
            response = requests.post(f"{BACKEND_URL}/api/v1/scan", json=payload, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
            else:
                used_local_fallback = True
        except Exception:
            used_local_fallback = True

    if BACKEND_URL.lower() == "local" or used_local_fallback:
        if LOCAL_MODE_AVAILABLE:
            rf_m, text_m, vec = get_local_models()
            if rf_m is not None and text_m is not None:
                try:
                    threat_intel = extract_cybersecurity_report(url_std)
                    rf_pred = predict(rf_m, url_std)
                    text_pred = predict_text(text_m, vec, url_std)
                    explainability = explain_prediction(rf_m, url_std)
                    
                    result = {
                        "url": url_std,
                        "threat_intel": threat_intel,
                        "models": {
                            "random_forest": rf_pred,
                            "tfidf_text": text_pred
                        },
                        "explainability": explainability
                    }
                except Exception as e:
                    st.session_state.last_url_result = {"error": f"Failed running local classification fallback: {e}"}
                    return
            else:
                st.session_state.last_url_result = {"error": "Local AI models could not be loaded. Please ensure models are trained."}
                return
        else:
            st.session_state.last_url_result = {"error": "Could not connect to backend and local mode is unavailable."}
            return

    if result:
        # Override/upgrade severity if AI models detect phishing
        is_rf_phish = result["models"]["random_forest"]["is_phishing"]
        is_text_phish = result["models"]["tfidf_text"]["is_phishing"]
        is_phishing = is_rf_phish or is_text_phish
        
        if is_phishing:
            if is_rf_phish and is_text_phish:
                result["threat_intel"]["severity"] = "Critical"
                result["threat_intel"]["reasons"].append("AI Model Ensemble consensus: both classifiers flagged the URL as phishing.")
            else:
                result["threat_intel"]["severity"] = "High"
                if is_rf_phish:
                    result["threat_intel"]["reasons"].append("Structural AI Model (Random Forest) flagged the URL structure as phishing.")
                if is_text_phish:
                    result["threat_intel"]["reasons"].append("Textual AI Model (Logistic Regression) flagged the URL text as phishing.")
        
        # Update Session States
        st.session_state.total_scans += 1
        if is_phishing:
            st.session_state.threats_detected += 1
            
        elapsed = time.time() - start_time
        st.session_state.average_response = (
            (st.session_state.average_response * (st.session_state.total_scans - 1)) + elapsed
        ) / st.session_state.total_scans
        
        # Add to history
        st.session_state.scan_history.insert(0, {
            "url": url_val,
            "severity": result["threat_intel"]["severity"],
            "is_phishing": is_phishing,
            "time": time.strftime("%H:%M:%S")
        })
        
        st.session_state.last_url_result = result
        st.session_state.last_scanned_url = url_val

def trigger_example_url_scan(url_val: str):
    set_url_input(url_val)
    run_url_scan(url_val)

def trigger_text_input_scan():
    url_val = st.session_state.get("url_scanner_input", "")
    run_url_scan(url_val)

def run_email_scan():
    email_text = st.session_state.get("email_text_input_area", "").strip()
    if not email_text:
        return
        
    start_time = time.time()
    email_result = None
    used_local_fallback = False
    
    if BACKEND_URL.lower() != "local":
        try:
            headers = {"X-API-Key": API_KEY}
            payload = {"email_text": email_text}
            response = requests.post(f"{BACKEND_URL}/api/v1/scan-email", json=payload, headers=headers, timeout=12)
            
            if response.status_code == 200:
                email_result = response.json()
            else:
                used_local_fallback = True
        except Exception:
            used_local_fallback = True

    if BACKEND_URL.lower() == "local" or used_local_fallback:
        if LOCAL_MODE_AVAILABLE:
            rf_m, text_m, vec = get_local_models()
            if rf_m is not None and text_m is not None:
                try:
                    email_summary = parse_email_threats(email_text)
                    url_scan_results = []
                    has_malicious_url = False
                    
                    for url in email_summary["extracted_urls"]:
                        url_std = url
                        if not url_std.startswith(("http://", "https://")):
                            url_std = "http://" + url_std
                            
                        threat_intel = extract_cybersecurity_report(url_std)
                        rf_pred = predict(rf_m, url_std)
                        text_pred = predict_text(text_m, vec, url_std)
                        
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
                        
                    email_result = {
                        "email_summary": email_summary,
                        "url_scan_results": url_scan_results,
                        "incident_playbook": playbook,
                        "overall_severity": overall_severity
                    }
                except Exception as e:
                    st.session_state.email_scan_error = f"Failed running local email analysis fallback: {e}"
                    return
            else:
                st.session_state.email_scan_error = "Local AI models could not be loaded. Please ensure models are trained."
                return
        else:
            st.session_state.email_scan_error = "Could not connect to backend and local mode is unavailable."
            return

    if email_result:
        st.session_state.last_email_result = email_result
        st.session_state.total_scans += 1
        if email_result["overall_severity"] in ["Suspicious", "Malicious"]:
            st.session_state.threats_detected += 1
            
        elapsed = time.time() - start_time
        st.session_state.average_response = (
            (st.session_state.average_response * (st.session_state.total_scans - 1)) + elapsed
        ) / st.session_state.total_scans
        if "email_scan_error" in st.session_state:
            del st.session_state.email_scan_error


# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ ThreatIntel Security")
    st.markdown("### Control Center")
    if BACKEND_URL.lower() == "local":
        st.success("🔒 Local Scanner Active")
    else:
        st.info(f"Connected to: `{BACKEND_URL}`")
    
    st.markdown("---")
    st.markdown("### Session Statistics")
    
    # Render sidebar KPI stats
    st.metric("Total Scanned", st.session_state.total_scans)
    st.metric("Threats Flagged", st.session_state.threats_detected)
    if st.session_state.total_scans > 0:
        ratio = (st.session_state.threats_detected / st.session_state.total_scans) * 100
        st.metric("Threat Ratio", f"{ratio:.1f}%")
        st.metric("Avg Response Time", f"{st.session_state.average_response:.3f}s")
    else:
        st.metric("Threat Ratio", "0.0%")
        st.metric("Avg Response Time", "0.000s")
        
    if st.button("Clear Session History"):
        st.session_state.total_scans = 0
        st.session_state.threats_detected = 0
        st.session_state.scan_history = []
        st.session_state.average_response = 0.0
        st.session_state.last_scanned_url = ""
        st.session_state.last_url_result = None
        st.session_state.last_email_result = None
        st.rerun()

# ── Main Header ──────────────────────────────────────────────────────────────
st.title("🔐 Enterprise Phishing URL Intel & Detection Platform")
st.markdown(
    "A production-grade cybersec AI model ensemble utilizing lexical analysis, "
    "DNS records, live WHOIS lookups, and a feature contribution breakdown."
)
st.markdown("---")

# ── Backend Health Check ─────────────────────────────────────────────────────
backend_healthy = False
if BACKEND_URL.lower() == "local":
    backend_healthy = True
else:
    try:
        health_resp = requests.get(f"{BACKEND_URL}/health", timeout=3)
        if health_resp.status_code == 200 and health_resp.json().get("status") == "healthy":
            backend_healthy = True
    except Exception:
        backend_healthy = False

if not backend_healthy:
    st.error(
        f"⚠️ **Cannot connect to the Security API Backend at {BACKEND_URL}**  \n"
        "Please ensure the FastAPI service is running:  \n"
        "`uvicorn src.api:app --reload --port 8000`"
    )
    st.stop()

# ── Tabs Configuration ───────────────────────────────────────────────────────
tab_url, tab_email = st.tabs(["🔍 URL Threat Scanner", "✉️ Email Incident Hub"])

with tab_url:
    st.subheader("🔍 URL Threat Scanner")
    url_input = st.text_input(
        "Enter a URL to analyze",
        placeholder="e.g. http://192.168.1.1/login@paypal-secure-verify.com/account/update",
        label_visibility="collapsed",
        key="url_scanner_input",
        on_change=trigger_text_input_scan
    )

    # Example buttons
    st.markdown("**Example Templates:**")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.button(
            "🟢 Legitimate (Google Search)",
            key="btn_legit",
            on_click=trigger_example_url_scan,
            args=("https://www.google.com/search?q=python+tutorial",)
        )
    with col2:
        st.button(
            "🔴 Critical Threat (IP-based Phish)",
            key="btn_phish",
            on_click=trigger_example_url_scan,
            args=("http://192.168.1.1/login@paypal-secure-verify.com/account/update",)
        )
    with col3:
        st.button(
            "🟡 High Risk (New/Untrusted Domain)",
            key="btn_risk",
            on_click=trigger_example_url_scan,
            args=("http://secure-netflix-update-billing.com/signin.html",)
        )

    # Get input from state if updated by button
    current_url = st.session_state.get("url_scanner_input", "").strip()

    # Render results if available
    if "last_url_result" in st.session_state and st.session_state.last_url_result is not None:
        result = st.session_state.last_url_result
        if "error" in result:
            st.error(result["error"])
        else:
            is_rf_phish = result["models"]["random_forest"]["is_phishing"]
            is_text_phish = result["models"]["tfidf_text"]["is_phishing"]
            is_phishing = is_rf_phish or is_text_phish
            
            # ── Render Scanning Results Dashboard ──────────────────────────────────
            severity = result["threat_intel"]["severity"]
            
            col_left, col_right = st.columns([2, 1])
            
            with col_left:
                if severity == "Critical":
                    st.markdown(f"### Threat Status: <span class='badge-critical'>⚠️ CRITICAL THREAT DETECTED</span>", unsafe_allow_html=True)
                elif severity == "High":
                    st.markdown(f"### Threat Status: <span class='badge-high'>⚠️ HIGH RISK WARNING</span>", unsafe_allow_html=True)
                elif severity == "Medium":
                    st.markdown(f"### Threat Status: <span class='badge-medium'>⚠️ SUSPICIOUS ACTIVITY</span>", unsafe_allow_html=True)
                else:
                    st.markdown(f"### Threat Status: <span class='badge-low'>✅ SECURE / NO SUSPICIOUS THREATS FOUND</span>", unsafe_allow_html=True)
                    
                st.markdown(f"**URL Scanned**: `{current_url}`")
                
                # Reasons list
                if result["threat_intel"]["reasons"]:
                    st.markdown("#### Threat Intelligence Findings:")
                    for reason in result["threat_intel"]["reasons"]:
                        st.markdown(f"- {reason}")
                else:
                    st.markdown("- No heuristic abnormalities detected in URL structure.")

            with col_right:
                st.markdown("#### Report Actions")
                report_json = json.dumps(result, indent=2)
                st.download_button(
                    label="📥 Download Threat Report (JSON)",
                    data=report_json,
                    file_name="threat_scan_report.json",
                    mime="application/json",
                    key="dl_report_url"
                )
                
            st.markdown("---")

            # ── Model Ensemble & Feature Contribution Breakdown ─────────────────────
            col_ens_l, col_ens_r = st.columns([1, 1])
            
            with col_ens_l:
                st.subheader("🤖 AI Model Ensemble Results")
                st.markdown("Two independent AI classifiers analyzed this URL:")
                
                # Model 1: Random Forest
                rf_res = result["models"]["random_forest"]
                st.markdown(f"**1. Random Forest (Structural Features)**")
                if rf_res["is_phishing"]:
                    st.error(f"🔴 Flagged as: **Phishing** | Confidence: **{rf_res['confidence']}%**")
                else:
                    st.success(f"🟢 Flagged as: **Legitimate** | Confidence: **{rf_res['confidence']}%**")
                    
                # Model 2: TF-IDF Text classifier
                text_res = result["models"]["tfidf_text"]
                st.markdown(f"**2. Logistic Regression (URL String Text Analysis)**")
                if text_res["is_phishing"]:
                    st.error(f"🔴 Flagged as: **Phishing** | Confidence: **{text_res['confidence']}%**")
                else:
                    st.success(f"🟢 Flagged as: **Legitimate** | Confidence: **{text_res['confidence']}%**")
                    
            with col_ens_r:
                st.subheader("🔍 Feature Contribution Breakdown")
                st.markdown("Attribution of features to the Random Forest decision (positive values push towards phishing):")
                
                contribs = result["explainability"]
                feature_mapping = {
                    "having_IPhaving_IP_Address": "IP in Domain",
                    "URLURL_Length": "URL Length Score",
                    "Shortining_Service": "Shortener Used",
                    "having_At_Symbol": "Has '@' Symbol",
                    "double_slash_redirecting": "Double Slash Redirect",
                    "Prefix_Suffix": "Hyphen in Domain",
                    "having_Sub_Domain": "Subdomain Count",
                    "SSLfinal_State": "SSL Final State (HTTPS)"
                }
                contrib_data = [
                    {"Feature": feature_mapping.get(k, k), "Weight": v}
                    for k, v in contribs.items()
                ]
                contrib_df = pd.DataFrame(contrib_data).set_index("Feature")
                st.bar_chart(contrib_df)

            st.markdown("---")

            # ── Live OSINT & Network Lookups ─────────────────────────────────────────
            st.subheader("🌐 Real-Time OSINT & Network Metadata")
            
            col_lookup1, col_lookup2, col_lookup3 = st.columns(3)
            
            with col_lookup1:
                st.markdown("#### 📡 DNS Records Validation")
                dns_info = result["threat_intel"]["dns"]
                if dns_info["has_dns_records"]:
                    st.success("✅ DNS Records Exist")
                    st.code(
                        f"A record  : {dns_info['A_record'] or 'None'}\n"
                        f"MX record : {dns_info['MX_record'] or 'None'}"
                    )
                else:
                    st.error("❌ No Active DNS Records Found")
                    st.caption("Often indicates dynamically generated temporary landing pages.")
                    
            with col_lookup2:
                st.markdown("#### ⏳ WHOIS Domain Lifecycle")
                whois_info = result["threat_intel"]["whois"]
                if whois_info["creation_date"]:
                    st.info(f"Creation Date: `{whois_info['creation_date']}`")
                    if whois_info["age_days"]:
                        st.markdown(f"Age: **{whois_info['age_days']} days** (~{whois_info['age_days']//365} years)")
                    if whois_info["is_new_domain"]:
                        st.warning("⚠️ Registered under 6 months ago")
                else:
                    st.warning("⚠️ No WHOIS lifecycle records returned")
                    st.caption("Common for unregistered, dynamic, or highly private phishing domains.")
                    
            with col_lookup3:
                st.markdown("#### 📊 Domain Name Entropy")
                entropy = result["threat_intel"]["entropy"]
                st.markdown(f"Shannon Entropy Score: **{entropy}**")
                st.progress(min(entropy / 8.0, 1.0))
                if entropy > 4.2:
                    st.error("🚨 Highly Random Domain Name")
                    st.caption("Random strings are signature indicators of DGA algorithms.")
                else:
                    st.success("✅ Standard Domain Complexity")

    # ── Scan History Dashboard ───────────────────────────────────────────────────
    if st.session_state.scan_history:
        st.markdown("---")
        st.subheader("📜 Session Threat Log")
        history_df = pd.DataFrame(st.session_state.scan_history)
        st.dataframe(history_df, use_container_width=True, hide_index=True)


with tab_email:
    st.subheader("✉️ Email Threat Header & Body Analyzer")
    st.markdown(
        "Analyze email source text (headers + body) to detect spoofed identities, "
        "mismatched sender envelopes, authentication failures, and suspicious text patterns. "
        "Includes URL verification and automated incident remediation playbooks."
    )
    
    # Session state for email text
    if "email_text_input_area" not in st.session_state:
        st.session_state.email_text_input_area = ""
        
    email_text_val = st.text_area(
        "Paste Raw Email Headers and Body",
        height=200,
        placeholder="From: billing@paypal.com\nReturn-Path: attacker@evil-direct.com\nReceived-SPF: fail\n...\n\nURGENT: Please verify your credentials at http://paypal-secure-verify.com/login",
        key="email_text_input_area"
    )

    
    # Template loader
    st.button(
        "📋 Load Spoofed Email Template",
        on_click=set_email_input,
        args=(
            "From: security@paypal.com\n"
            "Return-Path: spam-delivery@malicious-domain.xyz\n"
            "Received-SPF: fail\n"
            "DKIM-Signature: fail\n"
            "DMARC: fail\n"
            "Subject: URGENT: Billing Information Correction Required\n\n"
            "Dear Customer, we detected unauthorized access to your account. "
            "Please verify your credentials immediately within 24 hours to prevent permanent suspension.\n"
            "Update link: http://paypal-secure-verify.com/update-credentials",
        )
    )


    # Trigger action button with callback
    if "email_scan_error" in st.session_state and st.session_state.email_scan_error:
        st.error(st.session_state.email_scan_error)
        
    st.button(
        "Analyze Email Message",
        type="primary",
        key="btn_scan_email",
        on_click=run_email_scan,
        disabled=not email_text_val.strip()
    )
                
    # Render results if available
    if "last_email_result" in st.session_state and st.session_state.last_email_result is not None:
        res = st.session_state.last_email_result
        summary = res["email_summary"]
        severity = res["overall_severity"]
        
        st.markdown("---")
        
        # Severity Indicator Banner
        if severity == "Malicious":
            st.markdown(f"### Incident Threat Severity: <span class='badge-critical'>🚨 MALICIOUS - ACTIVE THREAT</span>", unsafe_allow_html=True)
        elif severity == "Suspicious":
            st.markdown(f"### Incident Threat Severity: <span class='badge-high'>⚠️ SUSPICIOUS INDICATORS DETECTED</span>", unsafe_allow_html=True)
        else:
            st.markdown(f"### Incident Threat Severity: <span class='badge-low'>✅ SAFE / AUTHENTICATED</span>", unsafe_allow_html=True)
            
        # Layout Grid
        col_sum_l, col_sum_r = st.columns([1, 1])
        
        with col_sum_l:
            st.markdown("#### 📨 Sender Authentication Audit")
            st.markdown(f"**From Address:** `{summary['from_header'] or 'None'}`")
            st.markdown(f"**Return-Path:** `{summary['return_path'] or 'None'}`")
            
            # Check for spoofing mismatch
            if summary["spoof_detected"]:
                st.warning("⚠️ **Envelop/Header Discrepancy Found**")
                for reason in summary["spoof_reasons"]:
                    st.markdown(f"- {reason}")
            else:
                st.success("✅ Sender envelop alignment validated successfully.")
                
        with col_sum_r:
            st.markdown("#### 🔒 Cryptographic Security Signatures")
            spf = summary["spf_status"]
            dkim = summary["dkim_status"]
            dmarc = summary["dmarc_status"]
            
            def render_status(status_str):
                if status_str == "PASS":
                    return f"<span style='color:#00cc66; font-weight:bold;'>PASS</span>"
                elif status_str in ["FAIL", "INVALID"]:
                    return f"<span style='color:#ff4b4b; font-weight:bold;'>FAIL</span>"
                else:
                    return f"<span style='color:#ffa500; font-weight:bold;'>{status_str}</span>"
                    
            st.markdown(f"- **SPF Record Check:** {render_status(spf)}", unsafe_allow_html=True)
            st.markdown(f"- **DKIM Signature Check:** {render_status(dkim)}", unsafe_allow_html=True)
            st.markdown(f"- **DMARC Alignment Check:** {render_status(dmarc)}", unsafe_allow_html=True)
            
        st.markdown("---")
        
        # Extracted URLs table
        st.markdown("#### 🔗 Embedded Hyperlinks Analysis")
        if res["url_scan_results"]:
            url_data = []
            for scan in res["url_scan_results"]:
                url_data.append({
                    "URL": scan["url"],
                    "Ensemble RF": scan["rf_pred"],
                    "Ensemble TF-IDF": scan["text_pred"],
                    "OSINT Threat Severity": scan["severity"],
                    "Decision": "🛑 Phishing" if scan["is_malicious"] else "🟢 Safe"
                })
            st.dataframe(pd.DataFrame(url_data), use_container_width=True, hide_index=True)
        else:
            st.info("No hyperlinks extracted from email body text.")
            
        # Incident Response Playbook
        st.markdown("---")
        st.markdown("#### 🛡️ Automated Security Incident Response Playbook")
        st.markdown("Recommended remediation protocols for SOC analysts:")
        
        playbook_data = []
        for item in res["incident_playbook"]:
            playbook_data.append({
                "Security Action": item["action"],
                "Remediation Instructions": item["description"],
                "Deployment Priority": item["status"]
            })
        st.table(pd.DataFrame(playbook_data))
        
        # Download Incident Report
        report_json = json.dumps(res, indent=2)
        st.download_button(
            label="📥 Download SOC Incident Report (JSON)",
            data=report_json,
            file_name="email_incident_report.json",
            mime="application/json",
            key="dl_report_email"
        )

