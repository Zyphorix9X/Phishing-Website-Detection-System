from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


MAX_URL_LENGTH = 2048
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


class URLValidationError(ValueError):
    pass


def normalize_url(value: str) -> str:
    if not isinstance(value, str):
        raise URLValidationError("Enter a URL as text.")
    raw = value.strip()
    if not raw:
        raise URLValidationError("Enter a URL to analyze.")
    if len(raw) > MAX_URL_LENGTH:
        raise URLValidationError(f"URLs must be {MAX_URL_LENGTH} characters or fewer.")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw) or "\\" in raw:
        raise URLValidationError("The URL contains unsupported control characters.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise URLValidationError("Only HTTP and HTTPS URLs are supported.")
        if not parsed.hostname:
            raise URLValidationError("Enter a URL with a valid domain or IP address.")
        if parsed.username is not None or parsed.password is not None:
            raise URLValidationError("URLs containing embedded usernames or passwords are not supported.")
        port = parsed.port
    except ValueError as exc:
        if isinstance(exc, URLValidationError):
            raise
        raise URLValidationError("Enter a URL with a valid host and port.") from exc

    host = parsed.hostname.rstrip(".")
    if not host or len(host) > 253:
        raise URLValidationError("Enter a valid domain name.")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        normalized_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        try:
            normalized_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise URLValidationError("The internationalized domain name is not valid.") from exc
        labels = normalized_host.split(".")
        if len(labels) < 2 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise URLValidationError("Enter a fully qualified domain name, such as example.com.")
        if labels[-1].isdigit():
            raise URLValidationError("The top-level domain must contain letters.")

    netloc = normalized_host
    if port is not None:
        netloc = f"{netloc}:{port}"
    # Keep an empty path empty: the preserved character model was trained on
    # URLs in their source spelling, and adding '/' changes its learned n-grams.
    path = parsed.path
    normalized = urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
    if len(normalized) > MAX_URL_LENGTH:
        raise URLValidationError(f"URLs must be {MAX_URL_LENGTH} characters or fewer.")
    return normalized
