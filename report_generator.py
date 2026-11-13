"""Compatibility entry point for the owner-scoped PDF report service."""

from types import SimpleNamespace

from phishing_app.services.reporting import generate_pdf_report as _generate_pdf_report


def generate_pdf_report(scan, user=None) -> bytes:
    if isinstance(scan, dict):
        result = {
            "url": scan.get("url"),
            "normalized_url": scan.get("url"),
            "prediction": scan.get("prediction", "UNVERIFIED"),
            "risk_score": scan.get("risk_score"),
            "ml_phishing_probability": scan.get("ml_probability"),
            "ml_prediction": scan.get("ml_prediction"),
            "reasons": scan.get("reasons", []),
            "whois": {"domain": scan.get("domain"), "domain_age_days": scan.get("domain_age_days")},
            "threat_intelligence": [],
            "model_explanation": {"status": "unavailable", "items": []},
        }
        scan = SimpleNamespace(
            id=scan.get("id", 0), submitted_url=scan.get("url", ""),
            prediction=scan.get("prediction", "UNVERIFIED"), risk_score=scan.get("risk_score"),
            ml_probability=scan.get("ml_probability"), result_data=result,
            created_at=scan.get("scanned_at", ""),
        )
    return _generate_pdf_report(scan, user)
