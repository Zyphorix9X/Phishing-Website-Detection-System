from feature_extractor import extract_url_features
import pytest


def test_extract_url_features_has_required_keys():
    url = "http://paypal-login-security-alert.com/verify"
    features = extract_url_features(url)

    assert "url_length" in features
    assert "has_https" in features
    assert "suspicious_word_count" in features
    assert "brand_keyword_count" in features


def test_http_url_is_not_https():
    url = "http://example.com"
    features = extract_url_features(url)

    assert features["has_https"] == 0
    assert features["has_http"] == 1


def test_suspicious_words_detected():
    url = "http://secure-login-update-account.com"
    features = extract_url_features(url)

    assert features["suspicious_word_count"] >= 2


@pytest.mark.parametrize('url,expected', [
    ('https://www.microsoft.com', 0),
    ('https://bit.ly.attacker.invalid', 0),
    ('https://notbit.ly', 0),
    ('https://t.co/path', 1),
    ('https://bit.ly:443/path', 1),
])
def test_shortener_matching_uses_hostname_boundaries(url, expected):
    assert extract_url_features(url)['contains_shortener_hint'] == expected


@pytest.mark.parametrize('url', ['http://192.0.2.1:8080/', 'https://[2001:db8::1]:443/'])
def test_ip_detection_handles_ports_and_ipv6(url):
    assert extract_url_features(url)['has_ip_address'] == 1
