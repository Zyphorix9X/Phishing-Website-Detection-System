import re
import math
import ipaddress
from urllib.parse import urlparse
import tldextract


SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account", "bank",
    "confirm", "password", "signin", "wallet", "free", "bonus",
    "gift", "support", "limited", "urgent", "security", "alert",
    "billing", "invoice", "recover", "unlock", "suspended"
]


BRAND_KEYWORDS = [
    "paypal", "facebook", "google", "microsoft", "apple",
    "amazon", "netflix", "linkedin", "instagram", "bank",
    "whatsapp", "binance", "coinbase"
]


SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly"
]


def safe_parse(url: str):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return urlparse(url)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0

    probabilities = [
        text.count(char) / len(text)
        for char in set(text)
    ]

    return -sum(p * math.log2(p) for p in probabilities)


def has_ip_address(domain: str) -> int:
    try:
        ipaddress.ip_address(domain)
        return 1
    except ValueError:
        return 0


def count_digits(text: str) -> int:
    return sum(char.isdigit() for char in text)


def count_letters(text: str) -> int:
    return sum(char.isalpha() for char in text)


def count_special_chars(text: str) -> int:
    return len(re.findall(r"[^a-zA-Z0-9]", text))


def extract_url_features(url: str) -> dict:
    parsed = safe_parse(url)
    extracted = tldextract.extract(url)

    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    subdomain = extracted.subdomain.lower()
    suffix = extracted.suffix.lower()

    url_lower = url.lower()

    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "path_length": len(path),
        "query_length": len(query),

        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_question_marks": url.count("?"),
        "num_equal_signs": url.count("="),
        "num_at_symbols": url.count("@"),
        "num_percent": url.count("%"),
        "num_ampersand": url.count("&"),

        "num_digits": count_digits(url),
        "num_letters": count_letters(url),
        "num_special_chars": count_special_chars(url),

        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_http": 1 if parsed.scheme == "http" else 0,
        "has_ip_address": has_ip_address(domain),

        "subdomain_length": len(subdomain),
        "tld_length": len(suffix),
        "subdomain_count": len(subdomain.split(".")) if subdomain else 0,

        "suspicious_word_count": sum(
            1 for word in SUSPICIOUS_WORDS if word in url_lower
        ),

        "brand_keyword_count": sum(
            1 for word in BRAND_KEYWORDS if word in url_lower
        ),

        "contains_double_slash_redirect": 1 if "//" in path else 0,
        "contains_percent_encoding": 1 if "%" in url else 0,
        "contains_shortener_hint": 1 if any(short in domain for short in SHORTENERS) else 0,

        "url_entropy": round(shannon_entropy(url_lower), 4),
        "domain_entropy": round(shannon_entropy(domain), 4),

        "digit_ratio": round(count_digits(url) / max(len(url), 1), 4),
        "special_char_ratio": round(count_special_chars(url) / max(len(url), 1), 4),
    }

    return features


def explain_url_risk(url: str, phishing_probability: float, extra_context=None) -> list:
    features = extract_url_features(url)
    reasons = []

    if extra_context is None:
        extra_context = {}

    if features["has_https"] == 0:
        reasons.append("URL does not use HTTPS.")

    if features["url_length"] > 75:
        reasons.append("URL is unusually long.")

    if features["num_hyphens"] >= 3:
        reasons.append("URL contains many hyphens, which is common in phishing domains.")

    if features["num_digits"] >= 5:
        reasons.append("URL contains many digits.")

    if features["has_ip_address"] == 1:
        reasons.append("URL uses an IP address instead of a normal domain name.")

    if features["suspicious_word_count"] >= 2:
        reasons.append("URL contains multiple suspicious words such as login, verify, secure, update, or account.")

    if features["brand_keyword_count"] >= 1 and features["suspicious_word_count"] >= 1:
        reasons.append("URL combines a brand-like keyword with security or login wording.")

    if features["contains_percent_encoding"] == 1:
        reasons.append("URL contains encoded characters, which can hide malicious patterns.")

    if features["contains_shortener_hint"] == 1:
        reasons.append("URL uses or resembles a URL shortener.")

    if features["url_entropy"] > 4.2:
        reasons.append("URL has high randomness/entropy, which can indicate generated malicious URLs.")

    if extra_context.get("is_blacklisted"):
        reasons.append("Domain was found in the local phishing blacklist.")

    domain_age_days = extra_context.get("domain_age_days", -1)

    if domain_age_days != -1 and domain_age_days < 30:
        reasons.append("Domain appears very new based on WHOIS information.")

    if phishing_probability >= 0.90:
        reasons.append("Machine learning model gives a very high phishing probability.")
    elif phishing_probability >= 0.70:
        reasons.append("Machine learning model gives a high phishing probability.")
    elif phishing_probability >= 0.50:
        reasons.append("Machine learning model gives a medium phishing probability.")

    if not reasons:
        reasons.append("No strong phishing indicators found, but manual verification is still recommended.")

    return reasons