from playwright.sync_api import Page

class EmailAnalyzerPage:
    """Page Object representing the Email Incident Hub tab in the Streamlit UI."""
    def __init__(self, page: Page):
        self.page = page
        
    def navigate_tab(self):
        """Clicks the Email Incident Hub tab trigger to view the pane."""
        self.page.get_by_role("tab", name="✉️ Email Incident Hub").click()

        
    def paste_email_content(self, text: str):
        """Pastes raw email content (headers + body) into the scan text area."""
        textarea = self.page.get_by_placeholder("From: billing@paypal.com\nReturn-Path: attacker@evil-direct.com\nReceived-SPF: fail\n...")
        textarea.fill(text)
        textarea.press("Control+Enter")

        
    def click_load_template(self):
        """Clicks the button to load the preconfigured spoofed email template."""
        self.page.get_by_role("button", name="📋 Load Spoofed Email Template").click()
        
    def click_analyze(self):
        """Clicks the submission button to analyze the pasted email."""
        self.page.get_by_role("button", name="Analyze Email Message").click()
        
    def get_incident_severity(self, timeout_ms: int = 15000) -> str:
        """Waits for and returns the incident severity banner text."""
        status_el = self.page.locator("text=Incident Threat Severity:")
        status_el.wait_for(state="visible", timeout=timeout_ms)
        return status_el.text_content()
        
    def get_playbook_action_visible(self, action_name: str) -> bool:
        """Checks if a specific SOC playbook action action exists in the page layout."""
        return self.page.locator(f"text={action_name}").is_visible()
