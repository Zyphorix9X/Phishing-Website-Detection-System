from __future__ import annotations

import threading
import time
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

from blacklist_checker import check_blacklist

_openphish_cache: tuple[float, set[str], str] | None = None
_phishtank_cache: dict[str, tuple[float, dict]] = {}
_cache_lock = threading.Lock()


def check_threat_intelligence(url: str, phishtank_api_key: str = "", openphish_feed_url: str = "") -> list[dict]:
    local = check_blacklist(url)
    findings = [{
        "provider": "Local blacklist",
        "status": local["status"],
        "matched": bool(local["is_blacklisted"]),
        "checked_at": _timestamp(),
        "evidence": {"domain": local["domain"], "source": local["source"]},
    }]
    if openphish_feed_url:
        findings.append(_check_openphish(url, openphish_feed_url))
    else:
        findings.append({"provider": "OpenPhish", "status": "not_configured", "matched": False, "checked_at": None, "feed_updated_at": None, "evidence": {}})
    if phishtank_api_key:
        findings.append(_check_phishtank(url, phishtank_api_key))
    else:
        findings.append({"provider": "PhishTank", "status": "not_configured", "matched": False, "checked_at": None, "evidence": {}})
    return findings


def _check_openphish(url: str, feed_url: str) -> dict:
    try:
        parsed = urlsplit(feed_url)
        port = parsed.port
    except ValueError:
        parsed = None
        port = None
    if parsed is None or parsed.scheme != "https" or parsed.hostname != "openphish.com" or port not in (None, 443) or parsed.path != "/feed.txt" or parsed.query or parsed.fragment or parsed.username or parsed.password:
        return {"provider": "OpenPhish", "status": "unavailable", "matched": False, "checked_at": _timestamp(), "feed_updated_at": None, "evidence": {"reason": "Unsupported feed URL"}}
    global _openphish_cache
    now = time.time()
    with _cache_lock:
        cached = _openphish_cache
    if not cached or cached[0] <= now:
        response = None
        try:
            response = requests.get(feed_url, timeout=(2, 4), allow_redirects=False, stream=True)
            response.raise_for_status()
            items = set()
            size = 0
            for line in response.iter_lines(chunk_size=8192, decode_unicode=True):
                if isinstance(line, bytes):
                    line = line.decode("utf-8", "replace")
                size += len(line or "")
                if size > 20_000_000:
                    raise ValueError("Feed exceeds configured size limit")
                if line and line.strip().startswith("http"):
                    items.add(line.strip().lower())
            if len(items) > 2_000_000:
                raise ValueError("Feed exceeds configured size limit")
            cached = (now + 900, items, _timestamp())
            with _cache_lock:
                _openphish_cache = cached
        except (requests.RequestException, ValueError):
            return {"provider": "OpenPhish", "status": "unavailable", "matched": False, "checked_at": _timestamp(), "feed_updated_at": None, "evidence": {}}
        finally:
            if response is not None:
                response.close()
    normalized = url.rstrip("/").lower()
    matched = normalized in cached[1] or url.lower() in cached[1]
    return {
        "provider": "OpenPhish community feed",
        "status": "confirmed_match" if matched else "no_match",
        "matched": matched,
        "checked_at": _timestamp(),
        "feed_updated_at": cached[2],
        "evidence": {"feed": "OpenPhish community feed"},
    }


def _check_phishtank(url: str, api_key: str) -> dict:
    cache_key = hashlib.sha256(f"{api_key}:{url}".encode("utf-8")).hexdigest()
    now = time.time()
    with _cache_lock:
        cached = _phishtank_cache.get(cache_key)
        if cached and cached[0] > now:
            return dict(cached[1])
    try:
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json", "app_key": api_key},
            timeout=(2, 4),
            allow_redirects=False,
            headers={"User-Agent": "PhishingDetectionResearch/1.0"},
        )
        response.raise_for_status()
        payload = response.json().get("results", {})
        matched = bool(payload.get("in_database") and payload.get("valid"))
        result = {
            "provider": "PhishTank",
            "status": "confirmed_match" if matched else "no_match",
            "matched": matched,
            "checked_at": _timestamp(),
            "evidence": {"in_database": bool(payload.get("in_database")), "valid": bool(payload.get("valid"))},
        }
        with _cache_lock:
            _phishtank_cache[cache_key] = (now + 900, dict(result))
        return result
    except (requests.RequestException, ValueError, TypeError):
        return {"provider": "PhishTank", "status": "unavailable", "matched": False, "checked_at": _timestamp(), "evidence": {}}


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
