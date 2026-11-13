from __future__ import annotations

import ipaddress
import json
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests
import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=())
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()
_CACHE_SECONDS = 6 * 60 * 60


def registered_domain(url_or_host: str) -> str:
    host = urlsplit(url_or_host).hostname or url_or_host
    try:
        return ipaddress.ip_address(host.strip("[]")).compressed
    except ValueError:
        parsed = _extract(host)
        return f"{parsed.domain}.{parsed.suffix}" if parsed.domain and parsed.suffix else host.lower()


def get_domain_intelligence(url_or_host: str, enabled: bool = True) -> dict:
    domain = registered_domain(url_or_host)
    result = {
        "domain": domain,
        "registration_date": None,
        "expiration_date": None,
        "domain_age_days": None,
        "registrar": None,
        "lookup_status": "unavailable",
    }
    if not enabled:
        result["lookup_status"] = "not_performed"
        return result
    try:
        ipaddress.ip_address(domain)
        result["lookup_status"] = "not_applicable"
        return result
    except ValueError:
        pass
    if "." not in domain or domain.lower() in {"localhost", "invalid"}:
        result["lookup_status"] = "not_applicable"
        return result

    now_epoch = datetime.now(timezone.utc).timestamp()
    with _lock:
        cached = _cache.get(domain)
        if cached and cached[0] > now_epoch:
            return dict(cached[1])
    try:
        # This contacts a fixed RDAP service, never the submitted website.
        response = _request_rdap(domain)
        if response.status_code != 200:
            response.close()
            result["lookup_status"] = "unavailable"
        else:
            content = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                content.extend(chunk)
                if len(content) > 1_000_000:
                    raise ValueError("RDAP response exceeds size limit")
            response.close()
            payload = json.loads(content.decode("utf-8"))
            events = payload.get("events", [])
            for event in events:
                action = (event.get("eventAction") or "").lower()
                date = _parse_date(event.get("eventDate"))
                if action in {"registration", "registered"} and date:
                    result["registration_date"] = date.isoformat()
                    result["domain_age_days"] = max(0, (datetime.now(timezone.utc) - date).days)
                elif action in {"expiration", "expiry"} and date:
                    result["expiration_date"] = date.isoformat()
            for entity in payload.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        result["registrar"] = next((item[3] for item in vcard[1] if len(item) > 3 and item[0] == "fn"), None)
                    if result["registrar"]:
                        break
            result["lookup_status"] = "available" if result["registration_date"] or result["registrar"] else "unavailable"
    except (requests.RequestException, ValueError, TypeError, KeyError, IndexError):
        result["lookup_status"] = "unavailable"
    with _lock:
        _cache[domain] = (now_epoch + _CACHE_SECONDS, dict(result))
    return result


def _request_rdap(domain: str):
    last_error = None
    for attempt in range(2):
        try:
            response = requests.get(
                f"https://rdap.org/domain/{domain}",
                timeout=(2, 3),
                allow_redirects=False,
                stream=True,
                headers={"Accept": "application/rdap+json, application/json"},
            )
            if response.status_code >= 500 and attempt == 0:
                response.close()
                time.sleep(0.2)
                continue
            return response
        except requests.RequestException as exc:
            last_error = exc
            if attempt == 0:
                time.sleep(0.2)
    if last_error:
        raise last_error
    raise requests.RequestException("RDAP service is unavailable")


def _parse_date(value: str | None):
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None
