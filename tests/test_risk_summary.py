import pytest

from risk_summary import summarize_risk


def test_research_percentage_uses_observed_indicators_and_excludes_raw_model_score():
    summary = summarize_risk({
        'prediction': 'UNVERIFIED', 'model_deployment_status': 'research_only',
        'model_status': 'available', 'risk_score': 95.8,
        'ml_phishing_probability': 0.958, 'url_indicator_score': 0,
    })
    assert summary['risk_percentage'] == 0
    assert summary['risk_percentage_display'] == '0%'
    assert summary['risk_percentage_calibrated'] is False
    assert summary['risk_percentage_basis'] == 'completed_rule_checks'
    assert summary['risk_headline'] == 'No scored risk indicators found'


def test_validated_model_uses_combined_heuristic_index_and_still_disclaims_probability():
    summary = summarize_risk({
        'model_deployment_status': 'validated', 'model_status': 'available',
        'risk_score': 58.5, 'url_indicator_score': 5,
    })
    assert summary['risk_percentage_display'] == '58.5%'
    assert summary['risk_percentage_basis'] == 'validated_model_and_indicators'
    assert 'not the probability' in summary['risk_percentage_explanation']


def test_unvalidated_historical_score_does_not_become_a_new_percentage():
    summary = summarize_risk({'risk_score': 4, 'ml_phishing_probability': .958})
    assert summary['risk_percentage'] is None
    assert summary['risk_percentage_display'] == '—'


@pytest.mark.parametrize('raw,expected', [(-5, 0), (120, 100), (25, 25), (float('nan'), None), (float('inf'), None), ('bad', None), (True, None)])
def test_percentage_is_finite_bounded_and_valid_for_the_display_meter(raw, expected):
    assert summarize_risk({'url_indicator_score': raw})['risk_percentage'] == expected


def test_threat_match_remains_prominent_even_when_index_is_not_a_probability():
    summary = summarize_risk({'prediction': 'PHISHING', 'url_indicator_score': 40})
    assert summary['risk_percentage_display'] == '40%'
    assert summary['risk_headline'] == 'Threat evidence was detected'
