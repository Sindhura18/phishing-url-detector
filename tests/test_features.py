"""
test_features.py
----------------
Unit tests for all URL feature extraction functions.

Run with:
    pytest tests/ -v

These tests verify that each feature function behaves correctly
on both phishing and legitimate URL examples.
This is where SDET skills shine — testing the ML feature pipeline.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.features import (
    has_ip_address,
    has_at_symbol,
    url_length,
    has_https,
    has_double_slash_redirect,
    count_dots,
    has_hyphen_in_domain,
    url_depth,
    uses_shortening_service,
    has_suspicious_keywords,
    extract_features,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

PHISHING_URL    = "http://192.168.1.1/login@paypal-secure-verify.com//account/update/confirm"
LEGITIMATE_URL  = "https://www.google.com/search?q=python+tutorial"
SHORTENER_URL   = "https://bit.ly/3xYz"
EMPTY_URL       = ""


# ── has_ip_address ───────────────────────────────────────────────────────────

class TestHasIpAddress:
    def test_detects_ip_in_url(self):
        assert has_ip_address("http://192.168.1.1/login") == 1

    def test_returns_zero_for_domain_url(self):
        assert has_ip_address("https://paypal.com/login") == 0

    def test_returns_zero_for_clean_url(self):
        assert has_ip_address(LEGITIMATE_URL) == 0

    def test_detects_ip_without_http(self):
        assert has_ip_address("192.168.0.1/page") == 1


# ── has_at_symbol ─────────────────────────────────────────────────────────────

class TestHasAtSymbol:
    def test_detects_at_symbol(self):
        assert has_at_symbol("http://legit.com@evil.com") == 1

    def test_no_at_symbol_in_clean_url(self):
        assert has_at_symbol(LEGITIMATE_URL) == 0

    def test_at_in_phishing_url(self):
        assert has_at_symbol(PHISHING_URL) == 1

    def test_empty_url(self):
        assert has_at_symbol(EMPTY_URL) == 0


# ── url_length ────────────────────────────────────────────────────────────────

class TestUrlLength:
    def test_returns_correct_length(self):
        url = "https://abc.com"
        assert url_length(url) == len(url)

    def test_long_phishing_url(self):
        assert url_length(PHISHING_URL) > 50

    def test_empty_url_returns_zero(self):
        assert url_length(EMPTY_URL) == 0

    def test_short_url(self):
        assert url_length("http://a.io") == 11


# ── has_https ─────────────────────────────────────────────────────────────────

class TestHasHttps:
    def test_https_url_returns_one(self):
        assert has_https("https://example.com") == 1

    def test_http_url_returns_zero(self):
        assert has_https("http://example.com") == 0

    def test_legitimate_url_has_https(self):
        assert has_https(LEGITIMATE_URL) == 1

    def test_phishing_url_lacks_https(self):
        assert has_https(PHISHING_URL) == 0


# ── has_double_slash_redirect ─────────────────────────────────────────────────

class TestHasDoubleSlashRedirect:
    def test_detects_double_slash_in_path(self):
        assert has_double_slash_redirect("http://example.com//redirect") == 1

    def test_no_double_slash_in_clean_url(self):
        assert has_double_slash_redirect(LEGITIMATE_URL) == 0

    def test_protocol_slashes_not_counted(self):
        # The http:// should not trigger a false positive
        assert has_double_slash_redirect("http://clean.com/page") == 0


# ── count_dots ────────────────────────────────────────────────────────────────

class TestCountDots:
    def test_counts_single_dot(self):
        assert count_dots("http://example.com") == 1

    def test_counts_multiple_dots(self):
        # login.secure.paypal.phishing.com → 4 dots
        assert count_dots("http://login.secure.paypal.phishing.com") == 4

    def test_empty_url_zero_dots(self):
        assert count_dots(EMPTY_URL) == 0


# ── has_hyphen_in_domain ──────────────────────────────────────────────────────

class TestHasHyphenInDomain:
    def test_detects_hyphen_in_domain(self):
        assert has_hyphen_in_domain("http://pay-pal-login.com") == 1

    def test_no_hyphen_in_clean_domain(self):
        assert has_hyphen_in_domain("https://google.com") == 0

    def test_hyphen_in_path_not_counted(self):
        # Hyphen in path only — should NOT trigger
        assert has_hyphen_in_domain("https://google.com/my-page") == 0


# ── url_depth ─────────────────────────────────────────────────────────────────

class TestUrlDepth:
    def test_shallow_url_has_low_depth(self):
        assert url_depth("https://google.com") == 0

    def test_deep_url_has_high_depth(self):
        assert url_depth("http://evil.com/a/b/c/d/e") == 5

    def test_single_path_segment(self):
        assert url_depth("https://github.com/Sindhura18") == 1


# ── uses_shortening_service ───────────────────────────────────────────────────

class TestUsesShorteningService:
    def test_detects_bitly(self):
        assert uses_shortening_service("https://bit.ly/3xYz") == 1

    def test_detects_tinyurl(self):
        assert uses_shortening_service("https://tinyurl.com/abc") == 1

    def test_legitimate_url_not_shortened(self):
        assert uses_shortening_service(LEGITIMATE_URL) == 0

    def test_unknown_shortener_not_detected(self):
        # We only check against known services
        assert uses_shortening_service("https://newshortener.io/abc") == 0


# ── has_suspicious_keywords ───────────────────────────────────────────────────

class TestHasSuspiciousKeywords:
    def test_detects_login_keyword(self):
        assert has_suspicious_keywords("http://evil.com/login") == 1

    def test_detects_verify_keyword(self):
        assert has_suspicious_keywords("http://evil.com/verify/account") == 1

    def test_clean_url_no_keywords(self):
        assert has_suspicious_keywords("https://github.com/Sindhura18") == 0

    def test_case_insensitive(self):
        assert has_suspicious_keywords("http://evil.com/SECURE") == 1


# ── extract_features ──────────────────────────────────────────────────────────

class TestExtractFeatures:
    def test_returns_dict_with_10_keys(self):
        result = extract_features(LEGITIMATE_URL)
        assert isinstance(result, dict)
        assert len(result) == 10

    def test_phishing_url_has_multiple_red_flags(self):
        result = extract_features(PHISHING_URL)
        # A clearly phishing URL should trigger multiple warning flags
        red_flags = sum([
            result["has_ip_address"],
            result["has_at_symbol"],
            result["has_double_slash"],
        ])
        assert red_flags >= 2

    def test_legitimate_url_has_https(self):
        result = extract_features(LEGITIMATE_URL)
        assert result["has_https"] == 1

    def test_all_values_are_numeric(self):
        result = extract_features(LEGITIMATE_URL)
        for key, val in result.items():
            assert isinstance(val, (int, float)), f"{key} should be numeric"

    def test_empty_url_does_not_crash(self):
        # Should not raise any exception
        result = extract_features(EMPTY_URL)
        assert isinstance(result, dict)
