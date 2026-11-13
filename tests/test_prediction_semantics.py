from pathlib import Path

import pandas as pd
import pytest

import predict
from config import MODEL_PATH
from phishing_app.validation import normalize_url


class FixedModel:
    classes_ = [0, 1]

    def __init__(self, probabilities):
        self.probabilities = probabilities

    def predict_proba(self, frame):
        assert len(frame) == 1
        return [self.probabilities]


def _mock_prediction_dependencies(monkeypatch, probabilities):
    monkeypatch.setattr(predict, "load_model", lambda: FixedModel(probabilities))
    monkeypatch.setattr(predict, "load_model_metadata", lambda: {"positive_class_label": 0, "model_version": "test", "deployment_status": "validated"})
    monkeypatch.setattr(predict, "check_threat_intelligence", lambda *args, **kwargs: [])
    monkeypatch.setattr(predict, "get_domain_intelligence", lambda *args, **kwargs: {
        "domain": "example.com", "domain_age_days": None, "lookup_status": "not_performed",
    })


def test_class_zero_probability_is_phishing_probability(monkeypatch):
    _mock_prediction_dependencies(monkeypatch, [0.91, 0.09])

    result = predict.predict_url("https://example.com/path", rdap_enabled=False)

    assert result["ml_phishing_probability"] == 0.91
    assert result["ml_prediction"] == "PHISHING"
    assert result["prediction"] == "PHISHING"


def test_class_one_probability_is_legitimate_probability(monkeypatch):
    _mock_prediction_dependencies(monkeypatch, [0.08, 0.92])

    result = predict.predict_url("https://example.com/path", rdap_enabled=False)

    assert result["ml_phishing_probability"] == 0.08
    assert result["ml_prediction"] == "LEGITIMATE"
    assert result["prediction"] == "LEGITIMATE"


@pytest.mark.parametrize('score', [0.01, 0.99])
def test_unvalidated_model_cannot_issue_definitive_verdict_or_inflate_risk(monkeypatch, score):
    _mock_prediction_dependencies(monkeypatch, [score, 1 - score])
    monkeypatch.setattr(predict, 'load_model_metadata', lambda: {
        'positive_class_label': 0, 'model_version': 'research-test', 'deployment_status': 'research_only',
    })
    result = predict.predict_url('https://example.com', rdap_enabled=False)
    assert result['prediction'] == 'UNVERIFIED'
    assert result['model_warning']
    assert result['risk_score'] is None
    assert result['url_indicator_score'] == 0
    assert result['ml_phishing_probability'] == score


def test_confirmed_threat_match_still_produces_phishing_verdict(monkeypatch):
    _mock_prediction_dependencies(monkeypatch, [0.01, 0.99])
    monkeypatch.setattr(predict, 'load_model_metadata', lambda: {
        'positive_class_label': 0, 'deployment_status': 'research_only',
    })
    monkeypatch.setattr(predict, 'check_threat_intelligence', lambda *a, **k: [
        {'provider': 'Test provider', 'status': 'confirmed_match', 'matched': True, 'evidence': {}},
    ])
    result = predict.predict_url('https://example.com', rdap_enabled=False)
    assert result['prediction'] == 'PHISHING'
    assert result['decision_source'] == 'confirmed_threat_intelligence'


def test_research_model_keeps_independent_url_rule_warning(monkeypatch):
    _mock_prediction_dependencies(monkeypatch, [0.01, 0.99])
    monkeypatch.setattr(predict, 'load_model_metadata', lambda: {
        'positive_class_label': 0, 'deployment_status': 'research_only',
    })
    result = predict.predict_url('https://paypal-login-verify.invalid/account', rdap_enabled=False)
    assert result['prediction'] == 'SUSPICIOUS'
    assert result['decision_source'] == 'url_rules'


def test_missing_model_is_unverified_not_legitimate(monkeypatch):
    def missing_model():
        raise predict.ModelUnavailableError("unavailable")

    monkeypatch.setattr(predict, "load_model", missing_model)
    monkeypatch.setattr(predict, "check_threat_intelligence", lambda *args, **kwargs: [])
    monkeypatch.setattr(predict, "get_domain_intelligence", lambda *args, **kwargs: {
        "domain": "example.com", "domain_age_days": None, "lookup_status": "not_performed",
    })

    result = predict.predict_url("https://example.com/path", rdap_enabled=False)

    assert result["model_status"] == "unavailable"
    assert result["ml_phishing_probability"] is None
    assert result["prediction"] == "UNVERIFIED"


@pytest.mark.skipif(not Path(MODEL_PATH).is_file(), reason="Preserved model artifact is not present")
def test_preserved_model_pipeline_uses_metadata_positive_class_without_network(monkeypatch):
    model = predict.load_model()
    metadata = predict.load_model_metadata()
    url = "https://www.jedonneenligne.org"
    normalized_url = normalize_url(url)
    expected = float(model.predict_proba(pd.DataFrame({"url": [normalized_url]}))[0][list(model.classes_).index(metadata["positive_class_label"])])
    monkeypatch.setattr(predict, "check_threat_intelligence", lambda *args, **kwargs: [])
    monkeypatch.setattr(predict, "get_domain_intelligence", lambda *args, **kwargs: {
        "domain": "jedonneenligne.org", "domain_age_days": None, "lookup_status": "not_performed",
    })
    monkeypatch.setattr(predict, "_local_ablation_explanation", lambda *args, **kwargs: {
        "status": "unavailable", "method": None, "items": [],
    })

    result = predict.predict_url(url, rdap_enabled=False)

    assert result["model_status"] == "available"
    assert result["normalized_url"] == normalized_url
    assert result["ml_phishing_probability"] == pytest.approx(expected, abs=1e-6)


@pytest.mark.skipif(not Path(MODEL_PATH).is_file(), reason='Preserved model artifact is not present')
@pytest.mark.parametrize('url', ['https://www.google.com', 'https://www.google.com/', 'https://google.com/'])
def test_real_google_variants_are_not_confirmed_phishing_from_research_model(monkeypatch, url):
    if predict.load_model_metadata().get('deployment_status') != 'research_only':
        pytest.skip('This regression targets the preserved research model')
    monkeypatch.setattr(predict, 'check_threat_intelligence', lambda *a, **k: [])
    monkeypatch.setattr(predict, 'get_domain_intelligence', lambda *a, **k: {
        'domain': 'google.com', 'domain_age_days': None, 'lookup_status': 'not_performed',
    })
    monkeypatch.setattr(predict, '_local_ablation_explanation', lambda *a, **k: {
        'status': 'unavailable', 'method': None, 'items': [],
    })
    result = predict.predict_url(url, rdap_enabled=False)
    assert result['model_status'] == 'available'
    assert result['prediction'] == 'UNVERIFIED'
    assert result['risk_score'] is None
    assert result['url_indicator_score'] == 0
    assert result['model_warning']
