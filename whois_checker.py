from datetime import datetime, timezone
import tldextract

try:
    import whois
except ImportError:
    whois = None


def extract_domain(url: str) -> str:
    extracted = tldextract.extract(url)

    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return extracted.domain


def normalize_whois_date(value):
    if isinstance(value, list):
        value = value[0] if value else None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    return None


def get_domain_age_days(url: str) -> dict:
    domain = extract_domain(url)

    if whois is None:
        return {
            "domain": domain,
            "domain_age_days": -1,
            "whois_available": False,
            "error": "python-whois is not installed"
        }

    try:
        data = whois.whois(domain)
        creation_date = normalize_whois_date(data.creation_date)

        if creation_date is None:
            return {
                "domain": domain,
                "domain_age_days": -1,
                "whois_available": False,
                "error": "Creation date not available"
            }

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days

        return {
            "domain": domain,
            "domain_age_days": age_days,
            "whois_available": True,
            "error": None
        }

    except Exception as e:
        return {
            "domain": domain,
            "domain_age_days": -1,
            "whois_available": False,
            "error": str(e)
        }