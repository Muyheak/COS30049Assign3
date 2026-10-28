from urllib.parse import urlparse
import re

suspicious_words = [
    "verify", "account", "login", "update", "secure", "banking", "confirm", 
    "password", "security", "signin", "support", "service", "auth", "authenticate",
    "winner", "prize", "websrc"
]

suspicious_tlds = {
    "tk", "ml", "ga", "xyz", "top", "icu", "sbs", "cfd", "zip", "move"
}

companies = ["amazon", "paypal", "microsoft", "apple", "twitter", "facebook", "google", "netflix", "bank"]

def extract_features(url):
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path
    url_lower = url.lower()
    host_no_port = host.split(":")[0]

    has_ip = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host_no_port)))

    parts = host_no_port.split(".")
    tld = parts[-1] if len(parts) > 1 else ""

    companies_in_sub = int(any(c in ".".join(parts[:-2]) for c in companies) and len(parts) > 2)

    return [
        len(url),
        len(host),
        len(path),
        url.count("-"),
        url.count("."),
        sum(c.isdigit() for c in url),
        url.count("/"),
        max(0, host_no_port.count(".") - 1),
        has_ip,
        int("@" in url),
        int(":" in host),
        sum(w in url_lower for w in suspicious_words),
        sum(c.isdigit() for c in url) / max(len(url), 1),
        int(tld in suspicious_tlds),
        companies_in_sub,
        len(tld)
    ]