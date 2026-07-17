from feature_extractor import extract_url_features


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