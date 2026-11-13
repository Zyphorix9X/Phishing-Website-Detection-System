"""Explain URL observations without mistaking ordinary query IDs for hostile hosts.

These rules do not fetch pages or establish that a URL is safe.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from feature_extractor import BRAND_KEYWORDS, SHORTENERS, SUSPICIOUS_WORDS


def assess_url_indicators(url: str, *, confirmed_match: bool = False, domain_age_days: int | None = None) -> dict:
    parsed = urlsplit(url)
    host = (parsed.hostname or '').lower().rstrip('.')
    tokens = set(re.findall(r'[a-z0-9]+', host))
    keywords = tokens.intersection(SUSPICIOUS_WORDS)
    brands = tokens.intersection(BRAND_KEYWORDS)
    items = []

    def add(code, description, points=0, severity='info', review=False):
        items.append({'code': code, 'description': description, 'points': points, 'severity': severity, 'requires_review': review})

    if confirmed_match:
        add('confirmed_match', 'A configured threat source reported a confirmed match.', 40, 'high', True)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        add('ip_host', 'The destination uses an IP address rather than a domain name; verify the intended destination.', 18, 'medium', True)
    if parsed.scheme != 'https':
        add('http', 'The URL uses HTTP. Transport encryption is absent; this alone does not establish phishing.', 5, 'low')
    if any(host == short or host.endswith('.' + short) for short in SHORTENERS):
        add('shortener', 'The hostname belongs to a known URL shortener. Its final destination has not been inspected.', 5, 'medium', True)
    if brands and keywords:
        add('brand_host', 'The hostname combines a brand-like token with account or security wording; verify ownership independently.', 21, 'medium', True)
    elif len(keywords) >= 3:
        add('keyword_host', 'The hostname contains several account or security tokens; verify the intended destination.', 15, 'medium', True)
    if host.count('-') >= 3:
        add('host_hyphens', 'The hostname contains several hyphens. This is a weak structural indicator.', 4, 'low')
    if sum(char.isdigit() for char in host) >= 5:
        add('host_digits', 'The hostname contains several digits. This is a weak structural indicator.', 3, 'low')
    if domain_age_days is not None and domain_age_days < 90:
        add('recent_domain', f'Registration data reports a domain age of {domain_age_days} days; age alone does not establish intent.', 10 if domain_age_days < 30 else 5, 'low')
    if len(url) > 100:
        add('long_url', 'The URL is long. Length alone is common in application and course links and adds no indicator points.')
    if parsed.query:
        add('query_parameters', 'Query parameters are present. Identifiers, digits, and hyphens in parameter values are not treated as suspicious hostname patterns.')
    if '%' in parsed.path or '%' in parsed.query:
        add('encoding', 'Encoded URL components are present. Encoding alone is not evidence of phishing.')
    if not items:
        add('no_scored_indicators', 'No scored URL indicators were observed. URL structure alone cannot verify safety.')
    return {'items': items, 'score': min(100, sum(item['points'] for item in items)),
            'requires_review': any(item['requires_review'] for item in items),
            'hostname_keyword_count': len(keywords)}
