"""URL preprocessing and feature extraction.

`normalize` and `extract_features` are copied unchanged from the Assignment 2
data-processing notebook, so the model receives at prediction time exactly
the 16 features it was trained on. Do not edit these two functions without
retraining the model.
"""
import re
from urllib.parse import unquote, urlparse

FEATURES = [
    "url_length", "host_length", "path_length", "n_hyphens", "n_dots",
    "n_digits", "n_slashes", "n_subdomains", "has_ip", "has_at",
    "has_port", "suspicious_words", "digit_ratio", "suspicious_tlds",
    "companies_in_sub", "tld_length",
]

suspicious_words = [
    "verify", "account", "login", "update", "secure", "banking", "confirm",
    "password", "security", "signin", "support", "service", "auth", "authenticate",
    "winner", "prize", "websrc",
]

suspicious_tlds = {"tk", "ml", "ga", "xyz", "top", "icu", "sbs", "cfd", "zip", "move"}

companies = ["amazon", "paypal", "microsoft", "apple", "twitter", "facebook", "google", "netflix", "bank"]


def normalize(url):
    """A2 notebook: decode percent-encoding, lowercase scheme/host, add a default scheme."""
    if not isinstance(url, str):
        return ""
    url = url.strip()
    try:
        url = unquote(url)
    except Exception:
        pass
    if "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        return f"{scheme}://{host}{path}" + (f"?{query}" if query else "")
    except ValueError:
        return ""


def extract_features(url):
    """A2 notebook: 16 lexical features from a normalised URL."""
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path
    url_lower = url.lower()
    host_no_port = host.split(":")[0]

    has_ip = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host_no_port)))

    parts = host_no_port.split(".")
    tld = parts[-1] if len(parts) > 1 else ""

    companies_in_sub = int(any(c in ".".join(parts[:-2]) for c in companies) and len(parts) > 2)

    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "n_hyphens": url.count("-"),
        "n_dots": url.count("."),
        "n_digits": sum(c.isdigit() for c in url),
        "n_slashes": url.count("/"),
        "n_subdomains": max(0, host_no_port.count(".") - 1),
        "has_ip": has_ip,
        "has_at": int("@" in url),
        "has_port": int(":" in host),
        "suspicious_words": sum(w in url_lower for w in suspicious_words),
        "digit_ratio": sum(c.isdigit() for c in url) / max(len(url), 1),
        "suspicious_tlds": int(tld in suspicious_tlds),
        "companies_in_sub": companies_in_sub,
        "tld_length": len(tld),
    }


def to_vector(url):
    """Normalise a raw URL and return (normalised_url, feature row in FEATURES order)."""
    clean = normalize(url)
    feats = extract_features(clean)
    return clean, [feats[f] for f in FEATURES]
