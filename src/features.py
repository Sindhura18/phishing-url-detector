"""
features.py
-----------
Extracts URL-based lexical and structural features for phishing detection.

Each feature captures a known indicator of phishing behavior:
- Phishing sites often use IP addresses instead of domain names
- They use special characters like '@' to confuse users
- They avoid HTTPS or use suspicious SSL setups
- They tend to have very long URLs to hide the real domain

These 10 features are extracted purely from the URL string,
requiring no external API calls — making prediction instant.
"""

import re
import urllib.parse


# Known URL-shortening services used to hide the real destination
SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "buff.ly", "shorte.st", "is.gd", "tr.im", "tiny.cc"
}


def has_ip_address(url: str) -> int:
    """
    Returns 1 if URL uses an IP address instead of a domain name.
    Phishing sites frequently use raw IPs to avoid traceable domain registration.

    Example: http://192.168.1.1/login → 1
             https://paypal.com/login → 0
    """
    ip_pattern = r"(https?://)?(\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(ip_pattern, url) else 0


def has_at_symbol(url: str) -> int:
    """
    Returns 1 if '@' is present in the URL.
    Browsers ignore everything before '@', so attackers exploit this:
    http://legitimate.com@phishing.com → user lands on phishing.com
    """
    return 1 if "@" in url else 0


def url_length(url: str) -> int:
    """
    Returns the total length of the URL.
    Phishing URLs tend to be very long to hide the malicious domain.
    Research shows URLs > 75 chars are suspicious.
    """
    return len(url)


def has_https(url: str) -> int:
    """
    Returns 1 if URL uses HTTPS (secure), 0 if HTTP (insecure).
    Legitimate sites almost always use HTTPS.
    Note: phishing sites can also have HTTPS, but absence is a red flag.
    """
    return 1 if url.startswith("https") else 0


def has_double_slash_redirect(url: str) -> int:
    """
    Returns 1 if '//' appears after the protocol part.
    Example: http://legitimate.com//redirect?to=evil.com
    The '//' tricks the browser into redirecting unexpectedly.
    """
    # Remove the 'http://' or 'https://' prefix before checking
    stripped = re.sub(r"https?://", "", url)
    return 1 if "//" in stripped else 0


def count_dots(url: str) -> int:
    """
    Returns the number of dots in the URL.
    More dots usually means more subdomains, a common phishing tactic:
    paypal.secure-login.phishing.com has many dots but is not PayPal.
    """
    return url.count(".")


def has_hyphen_in_domain(url: str) -> int:
    """
    Returns 1 if the domain contains a hyphen (-).
    Attackers use hyphens to mimic trusted brands:
    e.g., pay-pal-login.com, amazon-secure.com
    """
    try:
        domain = urllib.parse.urlparse(url).netloc
        return 1 if "-" in domain else 0
    except Exception:
        return 0


def url_depth(url: str) -> int:
    """
    Returns the number of path segments (depth) in the URL.
    Phishing URLs often have deep paths to appear legitimate:
    http://evil.com/secure/login/account/verify/confirm
    """
    try:
        path = urllib.parse.urlparse(url).path
        # Count non-empty path segments
        depth = len([p for p in path.split("/") if p])
        return depth
    except Exception:
        return 0


def uses_shortening_service(url: str) -> int:
    """
    Returns 1 if the URL uses a known URL-shortening service.
    Attackers use shorteners to hide the real phishing destination.
    """
    try:
        domain = urllib.parse.urlparse(url).netloc.lower()
        # Remove 'www.' prefix if present
        domain = domain.replace("www.", "")
        return 1 if domain in SHORTENING_SERVICES else 0
    except Exception:
        return 0


def has_suspicious_keywords(url: str) -> int:
    """
    Returns 1 if the URL contains common phishing keywords.
    Attackers use trust-inducing words like 'secure', 'verify', 'login'
    to make phishing URLs look official.
    """
    SUSPICIOUS_WORDS = [
        "secure", "login", "signin", "verify", "update",
        "confirm", "account", "banking", "password", "credential"
    ]
    url_lower = url.lower()
    return 1 if any(word in url_lower for word in SUSPICIOUS_WORDS) else 0


def extract_features(url: str) -> dict:
    """
    Master function: extracts all 10 features from a raw URL string.
    Returns a dictionary of {feature_name: value}.

    Usage:
        features = extract_features("http://192.168.1.1/login@paypal.com")
        # → {'has_ip_address': 1, 'has_at_symbol': 1, ...}
    """
    return {
        "has_ip_address":          has_ip_address(url),
        "has_at_symbol":           has_at_symbol(url),
        "url_length":              url_length(url),
        "has_https":               has_https(url),
        "has_double_slash":        has_double_slash_redirect(url),
        "dot_count":               count_dots(url),
        "has_hyphen_in_domain":    has_hyphen_in_domain(url),
        "url_depth":               url_depth(url),
        "uses_shortening_service": uses_shortening_service(url),
        "has_suspicious_keywords": has_suspicious_keywords(url),
    }

def extract_features_for_model(url: str) -> dict:
    """
    Extracts and maps URL features to match the exact schema and value range
    (-1, 0, 1) of the UCI Phishing Websites dataset columns used by the model.
    """
    # 1. IP Address (1 = Phishing, -1 = Legitimate)
    ip_addr = 1 if has_ip_address(url) else -1

    # 2. URL Length (<54 -> -1, 54-75 -> 0, >75 -> 1)
    length = len(url)
    if length < 54:
        url_len = -1
    elif length <= 75:
        url_len = 0
    else:
        url_len = 1

    # 3. Shortening Service (-1 = Phishing/Shortener used, 1 = Legitimate/No shortener)
    short = -1 if uses_shortening_service(url) else 1
    return {
        "having_IPhaving_IP_Address": ip_addr,
        "URLURL_Length": url_len,
        "Shortining_Service": short
    }
