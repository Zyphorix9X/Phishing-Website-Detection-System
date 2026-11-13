"""Present a weighted risk index as a percentage, without claiming probability."""
from __future__ import annotations

import math


def summarize_risk(result: dict) -> dict:
    validated = result.get('model_deployment_status') == 'validated' and result.get('model_status') == 'available'
    basis = 'validated_model_and_indicators' if validated and result.get('risk_score') is not None else 'completed_rule_checks'
    raw = result.get('risk_score') if basis == 'validated_model_and_indicators' else result.get('url_indicator_score')
    try:
        value = float(raw) if raw is not None and not isinstance(raw, bool) else None
        value = round(min(100, max(0, value)), 1) if value is not None and math.isfinite(value) else None
    except (TypeError, ValueError):
        value = None
    if value is None:
        headline = 'Run a new scan for a risk score'
    elif result.get('prediction') == 'PHISHING':
        headline = 'Threat evidence was detected'
    elif result.get('prediction') == 'SUSPICIOUS':
        headline = 'Risk indicators need your review'
    elif value == 0:
        headline = 'No scored risk indicators found'
    else:
        headline = 'Some risk indicators were observed'
    return {
        'risk_percentage': value,
        'risk_percentage_display': f'{value:g}%' if value is not None else '—',
        'risk_percentage_basis': basis,
        'risk_percentage_calibrated': False,
        'risk_headline': headline,
        'risk_percentage_explanation': 'A weighted score of the indicators found by completed checks, shown on a 0–100% scale. It is not the probability that this website is harmful.',
    }
