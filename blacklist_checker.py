from urllib.parse import urlparse
import os
import tldextract

from config import BLACKLIST_PATH

_extract = tldextract.TLDExtract(suffix_list_urls=())


def normalize_domain(url: str) -> str:
    extracted = _extract(url)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return (urlparse(url).hostname or "").lower()


def load_blacklist() -> set:
    try:
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as file:
            return {
                line.strip().lower()
                for line in file
                if line.strip() and not line.lstrip().startswith("#")
            }
    except FileNotFoundError:
        return set()


def check_blacklist(url: str) -> dict:
    domain = normalize_domain(url)
    try:
        if not os.path.isfile(BLACKLIST_PATH):
            raise OSError("Local blacklist file is unavailable")
        blacklist = load_blacklist()
        is_blacklisted = domain in blacklist
        status = "confirmed_match" if is_blacklisted else "no_match"
    except OSError:
        is_blacklisted = False
        status = "unavailable"

    return {
        "domain": domain,
        "is_blacklisted": is_blacklisted,
        "status": status,
        "source": "local_blacklist",
    }
