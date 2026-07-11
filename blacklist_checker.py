from urllib.parse import urlparse
import tldextract

from config import BLACKLIST_PATH


def normalize_domain(url: str) -> str:
    extracted = tldextract.extract(url)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return urlparse(url).netloc.lower()


def load_blacklist() -> set:
    try:
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as file:
            return {
                line.strip().lower()
                for line in file
                if line.strip() and not line.startswith("#")
            }
    except FileNotFoundError:
        return set()


def check_blacklist(url: str) -> dict:
    domain = normalize_domain(url)
    blacklist = load_blacklist()

    is_blacklisted = domain in blacklist

    return {
        "domain": domain,
        "is_blacklisted": is_blacklisted
    }
