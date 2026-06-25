import os
import sys
import subprocess
import time
import pytest
import requests
from playwright.sync_api import Page, expect

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.pages.dashboard_page import DashboardPage

# Ensure path resolution works correctly
os.environ["BACKEND_URL"] = "http://127.0.0.1:8009"

@pytest.fixture(scope="module", autouse=True)
def run_services():
    """
    Spins up the FastAPI backend and Streamlit frontend as background processes,
    waiting for them to be healthy before running E2E tests, and terminating
    them after testing completes.
    """
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


def test_streamlit_app_loads(page: Page):
    """Verifies that the Streamlit application loads successfully and displays the main heading."""
    page.goto("http://127.0.0.1:8509")
    # Wait for the main heading to render
    page.wait_for_selector("h1")
    expect(page.get_by_text("Enterprise Phishing URL Intel & Detection Platform")).to_be_visible()


def test_legitimate_url_scan(page: Page):
    """Enters a legitimate URL and asserts that the safe results are displayed."""
    dashboard = DashboardPage(page)
    dashboard.navigate("http://127.0.0.1:8509")
    
    # Enter and scan URL
    dashboard.scan_url("https://www.google.com/search?q=python+tutorial")
    
    # Wait for processing and assert success text
    status_text = dashboard.get_threat_status()
    assert "SECURE / NO SUSPICIOUS THREATS FOUND" in status_text
    expect(page.get_by_text("AI Model Ensemble Results")).to_be_visible()


def test_phishing_url_scan(page: Page):
    """Enters a phishing URL and asserts that critical threat results are displayed."""
    dashboard = DashboardPage(page)
    dashboard.navigate("http://127.0.0.1:8509")

    # Enter and scan URL
    dashboard.scan_url("http://paypal-secure-verify.com/account/update")

    # Wait for processing and assert critical threat warnings
    status_text = dashboard.get_threat_status()
    assert "CRITICAL THREAT DETECTED" in status_text

    # Assert model analysis displays the red flags
    expect(page.get_by_text("Domain matches a known threat signature in the blocklist.")).to_be_visible()


