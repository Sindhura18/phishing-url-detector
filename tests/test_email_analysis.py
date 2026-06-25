import os
import sys
import subprocess
import time
import pytest
import requests
from playwright.sync_api import Page, expect

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.pages.dashboard_page import DashboardPage
from tests.pages.email_analyzer_page import EmailAnalyzerPage


# Configure test environment parameters
os.environ["BACKEND_URL"] = "http://127.0.0.1:8009"
SCREENSHOTS_DIR = os.path.join("tests", "screenshots")

@pytest.fixture(scope="module", autouse=True)
def run_services():
    """
    Spins up the FastAPI backend and Streamlit frontend as background processes,
    waiting for them to be healthy before running E2E tests, and terminating
    them after testing completes.
    """
    # Create screenshots directory
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

    # Create backend environment with network mocking enabled
    env_backend = os.environ.copy()
    env_backend["MOCK_NETWORK"] = "true"
    env_backend["BACKEND_URL"] = "http://127.0.0.1:8009"

    # 1. Start FastAPI Backend on port 8009
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "src.api:app", "--host", "127.0.0.1", "--port", "8009"],
        env=env_backend,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # 2. Start Streamlit Frontend on port 8509 (headless mode)
    env = os.environ.copy()
    env["BACKEND_URL"] = "http://127.0.0.1:8009"
    frontend_proc = subprocess.Popen(
        [
            sys.executable, "-m", "streamlit", "run", "app.py",
            "--server.port", "8509",
            "--server.headless", "true",
            "--browser.gatherUsageStats", "false"
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Wait up to 10 seconds for services to start up and check health
    for _ in range(10):
        try:
            resp = requests.get("http://127.0.0.1:8009/health", timeout=1)
            if resp.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(1)

    yield

    # Clean up background processes
    backend_proc.terminate()
    frontend_proc.terminate()
    backend_proc.wait()
    frontend_proc.wait()


def test_url_impersonation_detection_flow(page: Page):
    """
    Verifies that scanning a brand-impersonation URL displays critical severity and brand alerts.
    Utilizes DashboardPage POM.
    """
    dashboard = DashboardPage(page)
    dashboard.navigate("http://127.0.0.1:8509")
    
    # Assert main heading is visible
    expect(page.get_by_text("Enterprise Phishing URL Intel & Detection Platform")).to_be_visible()
    
    # Scan a simulated brand impersonation URL
    target_url = "http://paypal-security-check.com/login"
    dashboard.scan_url(target_url)
    
    # Wait for results and verify CRITICAL status is loaded
    status_text = dashboard.get_threat_status()
    assert "CRITICAL THREAT DETECTED" in status_text or "HIGH RISK WARNING" in status_text
    
    # Verify the brand spoofing indicator exists in findings
    expect(page.get_by_text("Brand impersonation detected: attempts to spoof official 'paypal'")).to_be_visible()
    
    # Save a screenshot of the scan result
    page.screenshot(path=os.path.join(SCREENSHOTS_DIR, "url_impersonation_test.png"))


def test_email_header_spoofing_analysis_flow(page: Page):
    """
    Inputs a spoofed email template and asserts SPF/DKIM/DMARC status and incident playbook details.
    Utilizes EmailAnalyzerPage POM.
    """
    email_page = EmailAnalyzerPage(page)
    
    # Navigate and switch to email tab
    page.goto("http://127.0.0.1:8509")
    email_page.navigate_tab()
    
    # Paste the email text directly
    email_text = (
        "From: billing@paypal.com\n"
        "Return-Path: hacker@evil-direct.com\n"
        "Received-SPF: fail\n"
        "DKIM-Signature: fail\n"
        "DMARC: fail\n\n"
        "URGENT: Your account is suspended. Verify immediately at http://paypal-security-check.com/login"
    )
    email_page.paste_email_content(email_text)
    
    # Run the email threat verification scan
    email_page.click_analyze()

    
    # Verify malicious threat indicators are flagged
    severity = email_page.get_incident_severity()
    assert "MALICIOUS" in severity
    
    # Assert header authentication breakdowns are displayed
    expect(page.get_by_text("SPF Record Check: FAIL")).to_be_visible()
    expect(page.get_by_text("DKIM Signature Check: FAIL")).to_be_visible()
    expect(page.get_by_text("DMARC Alignment Check: FAIL")).to_be_visible()
    
    # Assert that incident response actions are recommended to SOC
    expect(page.get_by_text("Quarantine Email").first).to_be_visible()
    expect(page.get_by_text("Block Sender Domain").first).to_be_visible()
    expect(page.get_by_text("Block Malicious URLs").first).to_be_visible()
    expect(page.get_by_text("Revoke User Sessions").first).to_be_visible()

    
    # Save a screenshot of the email incident response portal
    page.screenshot(path=os.path.join(SCREENSHOTS_DIR, "email_spoofing_test.png"))

