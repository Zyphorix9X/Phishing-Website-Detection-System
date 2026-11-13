import pytest

from url_indicators import assess_url_indicators


@pytest.mark.parametrize('hostname', ['www.netacad.com', 'learning.example.org'])
def test_long_course_query_identifiers_are_not_host_phishing_indicators(hostname):
    url = f'https://{hostname}/launch?id=aaaaaaaa-1234-4567-8901-aaaaaaaaaaaa&tab=curriculum&view=bbbbbbbb-2345-4567-8901-bbbbbbbbbbbb'
    assessment = assess_url_indicators(url)
    assert assessment['score'] == 0
    assert assessment['requires_review'] is False
    assert {item['code'] for item in assessment['items']} == {'long_url', 'query_parameters'}


def test_regular_login_path_does_not_impersonate_a_brand_in_the_hostname():
    assessment = assess_url_indicators('https://accounts.example.org/login?service=google&next=account')
    assert assessment['score'] == 0
    assert assessment['requires_review'] is False


def test_suspicious_hostname_retains_review_and_explains_its_points():
    assessment = assess_url_indicators('https://paypal-login-security-alert.invalid/verify')
    assert assessment['score'] == 25
    assert assessment['requires_review'] is True
    assert {item['code']: item['points'] for item in assessment['items']} == {'brand_host': 21, 'host_hyphens': 4}


def test_missing_registration_data_adds_no_points():
    assert assess_url_indicators('https://example.org', domain_age_days=None)['score'] == 0


def test_url_encoding_is_an_observation_not_an_automatic_risk_score():
    assessment = assess_url_indicators('https://example.org/course%20name?item=abc%2D123')
    assert assessment['score'] == 0
    assert assessment['requires_review'] is False


def test_confirmed_threat_match_is_attributed_explicitly():
    assessment = assess_url_indicators('https://example.org', confirmed_match=True)
    assert assessment['score'] == 40
    assert assessment['items'][0]['code'] == 'confirmed_match'
