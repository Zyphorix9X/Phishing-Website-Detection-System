from feature_extractor import explain_url_risk


def test_explanation_returns_list():
    reasons = explain_url_risk(
        "http://paypal-login-security-alert.com/verify",
        0.95,
        {"is_blacklisted": True, "domain_age_days": 10}
    )

    assert isinstance(reasons, list)
    assert len(reasons) > 0