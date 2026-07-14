"""
features.py
-----------
Extracts URL-based features for phishing detection.

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
import math
import datetime
import os
import socket
import dns.resolver
import whois

# Prevent live socket lookups (WHOIS, DNS) from hanging indefinitely
socket.setdefaulttimeout(3.0)


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

    # 4. At Symbol (1 = Phishing, -1 = Legitimate)
    at_sym = 1 if has_at_symbol(url) else -1

    # 5. Double Slash Redirect (-1 = Phishing/Redirect present, 1 = Legitimate/No redirect)
    double_slash = -1 if has_double_slash_redirect(url) else 1

    # 6. Prefix Suffix / Hyphen in Domain (1 = Phishing, -1 = Legitimate)
    prefix_suffix = 1 if has_hyphen_in_domain(url) else -1

    # 7. Sub Domain Dots (excluding www) (dots<=1 -> -1, dots==2 -> 0, dots>2 -> 1)
    try:
        domain = urllib.parse.urlparse(url).netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        dots = domain.count(".")
        if dots <= 1:
            sub_domain = -1
        elif dots == 2:
            sub_domain = 0
        else:
            sub_domain = 1
    except Exception:
        sub_domain = -1

    # 8. SSL Final State (In the dataset, -1 = Legitimate/HTTPS, 1 = Phishing/HTTP)
    ssl_state = -1 if has_https(url) else 1

    return {
        "having_IPhaving_IP_Address": ip_addr,
        "URLURL_Length": url_len,
        "Shortining_Service": short,
        "having_At_Symbol": at_sym,
        "double_slash_redirecting": double_slash,
        "Prefix_Suffix": prefix_suffix,
        "having_Sub_Domain": sub_domain,
        "SSLfinal_State": ssl_state
    }


def calculate_entropy(text: str) -> float:
    """
    Calculates the Shannon entropy of a string.
    High entropy indicates random/DGA-like domain names.
    """
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def check_dns_records(domain: str) -> dict:
    """
    Verifies if a domain has valid A or MX DNS records.
    """
    res = {"has_dns_records": False, "A_record": None, "MX_record": None}
    if not domain:
        return res
        
    if os.getenv("MOCK_NETWORK") == "true":
        return {"has_dns_records": True, "A_record": "192.168.1.1", "MX_record": "mail.domain.com"}

    try:
        a_records = dns.resolver.resolve(domain, 'A')
        res["A_record"] = str(a_records[0])
        res["has_dns_records"] = True
    except Exception:
        res["A_record"] = None

    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        res["MX_record"] = str(mx_records[0].exchange)
        res["has_dns_records"] = True
    except Exception:
        res["MX_record"] = None

    return res


def check_domain_age(domain: str) -> dict:
    """
    Queries WHOIS for domain creation date and calculates age in days.
    Only queries the primary registered domain to prevent subdomain lookups from hanging.
    """
    res = {
        "creation_date": None,
        "expiration_date": None,
        "age_days": None,
        "is_new_domain": False
    }
    if not domain:
        return res
        
    if os.getenv("MOCK_NETWORK") == "true":
        return {
            "creation_date": "2020-01-01",
            "expiration_date": "2030-01-01",
            "age_days": 2000,
            "is_new_domain": False
        }
        
    # Heuristic to extract registered domain (e.g. www.google.com -> google.com)
    domain_parts = domain.lower().split('.')
    if len(domain_parts) > 2:
        tlds = {"com", "net", "org", "edu", "gov", "mil", "co", "uk", "in", "us", "info", "biz", "xyz"}
        if domain_parts[-2] in tlds and len(domain_parts) >= 3:
            registered_domain = ".".join(domain_parts[-3:])
        else:
            registered_domain = ".".join(domain_parts[-2:])
    else:
        registered_domain = domain

    try:
        # Query WHOIS with registered root domain
        w = whois.whois(registered_domain)
        creation = w.creation_date

        expiration = w.expiration_date

        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiration, list):
            expiration = expiration[0]

        if isinstance(creation, datetime.datetime):
            res["creation_date"] = creation.strftime("%Y-%m-%d")
            age = (datetime.datetime.now() - creation).days
            res["age_days"] = age
            res["is_new_domain"] = age < 180

        if isinstance(expiration, datetime.datetime):
            res["expiration_date"] = expiration.strftime("%Y-%m-%d")
    except Exception:
        pass
    return res


LOCAL_BLOCKLIST = {
    "paypal-secure-verify.com",
    "login-paypal.com",
    "verify-apple-id.com",
    "netflix-update-billing.com",
    "secure-bank-login.com",
    "amazon-security-alert.com"
}


def check_local_blocklist(domain: str) -> bool:
    """Checks if the domain is present in our local phishing blocklist."""
    if not domain:
        return False
    domain_clean = domain.lower().replace("www.", "")
    return domain_clean in LOCAL_BLOCKLIST or any(blocked in domain_clean for blocked in LOCAL_BLOCKLIST)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_homoglyph(domain: str) -> bool:
    """
    Detects if the domain uses non-ASCII characters or an IDN prefix (xn--)
    suggesting a Unicode homoglyph lookalike spoofing attempt.
    """
    if not domain:
        return False
    domain_lower = domain.lower()
    if domain_lower.startswith("xn--"):
        return True
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        return True
    return False


def detect_brand_impersonation(domain: str) -> dict:
    """
    Checks if the domain primary label typosquats or subdomains mimic major web brands.
    """
    res = {"is_impersonation": False, "target_brand": None}
    if not domain:
        return res

    domain_clean = domain.lower().replace("www.", "")
    parts = domain_clean.split('.')
    if len(parts) < 2:
        return res

    # Simple common TLD set to identify the primary brand token
    tlds = {"com", "net", "org", "edu", "gov", "mil", "co", "uk", "in", "us", "info", "biz", "xyz"}
    primary = parts[-2]
    if primary in tlds and len(parts) >= 3:
        primary = parts[-3]

    target_brands = [
        "google", "microsoft", "paypal", "amazon", "netflix", "apple",
        "facebook", "yahoo", "linkedin", "twitter", "instagram", "github"
    ]

    # 1. Look for brand name embedded inappropriately in subdomains
    for brand in target_brands:
        if brand in parts[:-2]:
            res["is_impersonation"] = True
            res["target_brand"] = brand
            return res

        if brand in primary and primary != brand:
            # If it's a hyphenated part, e.g. "secure-paypal"
            if "-" in primary:
                subparts = primary.split("-")
                if brand in subparts:
                    res["is_impersonation"] = True
                    res["target_brand"] = brand
                    return res
            else:
                # If not hyphenated, check if it's concatenated with common phishing words or qualifiers
                qualifiers = {
                    "login", "verify", "secure", "signin", "update", "support", "account", "bank", 
                    "billing", "service", "portal", "my", "get", "try", "go", "the", "app", "web", 
                    "online", "pay", "shop", "store", "official", "alert", "security", "help", "client"
                }
                for qual in qualifiers:
                    if primary == f"{brand}{qual}" or primary == f"{qual}{brand}":
                        res["is_impersonation"] = True
                        res["target_brand"] = brand
                        return res

    # 2. Calculate edit distance for typosquatting checks (distance 1 or 2)
    for brand in target_brands:
        if primary != brand:
            dist = levenshtein_distance(primary, brand)
            if dist in [1, 2] and len(primary) >= 4:
                res["is_impersonation"] = True
                res["target_brand"] = brand
                return res

    return res


def extract_cybersecurity_report(url: str) -> dict:
    """
    Master threat intelligence function.
    Returns real-time DNS status, domain age, entropy, local blocklist check,
    brand impersonation alerts, and homoglyph checks.
    """
    try:
        domain = urllib.parse.urlparse(url).netloc.split(":")[0]
    except Exception:
        domain = ""

    entropy = calculate_entropy(domain)
    dns_info = check_dns_records(domain)
    whois_info = check_domain_age(domain)
    is_blacklisted = check_local_blocklist(domain)
    impersonation_info = detect_brand_impersonation(domain)
    is_homoglyph = detect_homoglyph(domain)

    # Compute a quick heuristics-based "Severity" rating
    severity = "Low"
    reasons = []
    if is_blacklisted:
        severity = "Critical"
        reasons.append("Domain matches a known threat signature in the blocklist.")
    elif impersonation_info["is_impersonation"]:
        severity = "Critical"
        reasons.append(f"Brand impersonation detected: attempts to spoof official '{impersonation_info['target_brand']}' domain.")
    elif is_homoglyph:
        severity = "Critical"
        reasons.append("Unicode homoglyph attack detected (uses IDN punycode or mixed scripts).")
    else:
        if whois_info["is_new_domain"]:
            severity = "High"
            reasons.append("Domain is newly registered (under 6 months old).")
        if not dns_info["has_dns_records"] and domain:
            severity = "High"
            reasons.append("Domain has no valid DNS A or MX records.")
        if entropy > 4.2:
            severity = "Medium"
            reasons.append(f"High domain character entropy ({entropy}), suggesting dynamic generation.")

    return {
        "domain": domain,
        "entropy": entropy,
        "dns": dns_info,
        "whois": whois_info,
        "is_blacklisted": is_blacklisted,
        "is_homoglyph": is_homoglyph,
        "impersonation": impersonation_info,
        "severity": severity,
        "reasons": reasons
    }


