
import re
import ipaddress
from urllib.parse import urlparse


def analyze_url(url):
    """
    Extract security-related features from a URL.
    Does not visit or open the website.
    """

    url = url.strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if parsed.scheme not in ("http", "https") or not hostname:
        raise ValueError("Please enter a valid HTTP or HTTPS URL.")

    # Check whether hostname is an IP address
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    features = {}

    # Basic URL features
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["digit_count"] = sum(c.isdigit() for c in url)
    features["at_symbol"] = int("@" in url)
    features["https"] = int(parsed.scheme == "https")

    # IP address detection
    features["uses_ip_address"] = int(is_ip)

    # Subdomain calculation
    if is_ip:
        features["subdomain_count"] = 0
    else:
        features["subdomain_count"] = max(
            0, len(hostname.split(".")) - 2
        )

    # Suspicious words
    suspicious_words = [
        "login", "verify", "update", "secure",
        "account", "banking", "password",
        "signin", "confirm", "wallet"
    ]

    features["suspicious_word_count"] = sum(
        word in url.lower() for word in suspicious_words
    )

    # Special indicators
    features["has_punycode"] = int(
        "xn--" in hostname.lower()
    )

    features["has_double_slash_in_path"] = int(
        "//" in parsed.path or "//" in parsed.query
    )

    features["query_parameter_count"] = (
        len(parsed.query.split("&")) if parsed.query else 0
    )

    return features


def assess_url_risk(features):
    """Calculate a simple rule-based URL risk score."""

    risk_score = 0
    risk_factors = []

    if features["at_symbol"] == 1:
        risk_score += 2
        risk_factors.append("URL contains @ symbol")

    if features["uses_ip_address"] == 1:
        risk_score += 2
        risk_factors.append("URL uses an IP address")

    if features["has_punycode"] == 1:
        risk_score += 2
        risk_factors.append("URL contains punycode")

    if features["https"] == 0:
        risk_score += 1
        risk_factors.append("URL does not use HTTPS")

    if features["suspicious_word_count"] >= 2:
        risk_score += 2
        risk_factors.append("Multiple suspicious words found")
    elif features["suspicious_word_count"] == 1:
        risk_score += 1
        risk_factors.append("Suspicious word found")

    if features["url_length"] > 75:
        risk_score += 1
        risk_factors.append("Unusually long URL")

    if features["subdomain_count"] >= 3:
        risk_score += 1
        risk_factors.append("Multiple subdomains found")

    if features["has_double_slash_in_path"] == 1:
        risk_score += 1
        risk_factors.append("Unusual double slash found")

    if risk_score >= 6:
        risk_level = "High Risk"
    elif risk_score >= 3:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors
    }
