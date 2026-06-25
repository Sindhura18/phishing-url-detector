from playwright.sync_api import Page

class DashboardPage:
    """Page Object representing the URL Threat Scanner tab in the Streamlit UI."""
    def __init__(self, page: Page):
        self.page = page
        
    def navigate(self, url: str = "http://127.0.0.1:8501"):
        """Navigates to the portal and switches to the URL scanner tab."""
        self.page.goto(url)
        self.page.get_by_role("tab", name="🔍 URL Threat Scanner").click()

        
    def scan_url(self, target_url: str):
        """Inputs a target URL and submits it for scanning."""
        input_el = self.page.get_by_placeholder("e.g. http://192.168.1.1/login@paypal-secure-verify.com/account/update")
        input_el.fill(target_url)
        input_el.press("Enter")
        
    def click_example_legitimate(self):
        """Clicks the button to run the legitimate template search query."""
        self.page.get_by_role("button", name="🟢 Legitimate (Google Search)").click()
        
    def click_example_phishing(self):
        """Clicks the button to run the critical IP-based phishing query."""
        self.page.get_by_role("button", name="🔴 Critical Threat (IP-based Phish)").click()
        
    def click_example_risk(self):
        """Clicks the button to run the high risk new domain query."""
        self.page.get_by_role("button", name="🟡 High Risk (New/Untrusted Domain)").click()

    def get_threat_status(self, timeout_ms: int = 15000) -> str:
        """Waits for and returns the threat severity text."""
        status_el = self.page.locator("text=Threat Status:")
        status_el.wait_for(state="visible", timeout=timeout_ms)
        return status_el.text_content()
