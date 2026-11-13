"""Compatibility helpers backed by the account-scoped SQLAlchemy models."""

from sqlalchemy import func, select

from phishing_app.extensions import db
from phishing_app.models import Scan


def init_db():
    """Initialize local development tables; production uses Flask-Migrate."""
    from flask import current_app
    if current_app.config.get("APP_ENV") == "production":
        raise RuntimeError("Use 'flask db upgrade' for production schema changes.")
    db.create_all()


def save_scan(result, user_id=None):
    """Save a result only when its owner is explicit or currently signed in."""
    if user_id is None:
        try:
            from flask_login import current_user
            if current_user.is_authenticated:
                user_id = current_user.id
        except RuntimeError:
            pass
    if user_id is None:
        raise PermissionError("Anonymous scans are ephemeral and are not stored.")
    from phishing_app.blueprints.main import persist_scan
    return persist_scan(result, user_id)


def get_scan_history(limit=100, user_id=None):
    owner_id, all_scans = _scope(user_id)
    if owner_id is None and not all_scans:
        return []
    query = select(Scan)
    if not all_scans:
        query = query.where(Scan.user_id == owner_id)
    return [_serialize(scan) for scan in db.session.scalars(query.order_by(Scan.created_at.desc()).limit(min(max(int(limit), 1), 500))).all()]


def get_dashboard_stats(user_id=None):
    owner_id, all_scans = _scope(user_id)
    if owner_id is None and not all_scans:
        return {"total_scans": 0, "phishing_count": 0, "suspicious_count": 0, "legitimate_count": 0, "unverified_count": 0, "avg_risk": 0, "top_domains": []}
    condition = True if all_scans else Scan.user_id == owner_id
    total = db.session.scalar(select(func.count(Scan.id)).where(condition)) or 0
    counts = {label: db.session.scalar(select(func.count(Scan.id)).where(condition, Scan.prediction == label.upper())) or 0 for label in ("phishing", "suspicious", "legitimate", "unverified")}
    avg = db.session.scalar(select(func.avg(Scan.risk_score)).where(condition)) or 0
    top = db.session.execute(select(Scan.result_data["whois"]["domain"].as_string(), func.count(Scan.id)).where(condition).group_by(Scan.result_data["whois"]["domain"].as_string()).order_by(func.count(Scan.id).desc()).limit(5)).all()
    return {"total_scans": total, "phishing_count": counts["phishing"], "suspicious_count": counts["suspicious"], "legitimate_count": counts["legitimate"], "unverified_count": counts["unverified"], "avg_risk": round(float(avg), 2), "top_domains": top}


def get_scan_by_id(scan_id, user_id=None):
    owner_id, all_scans = _scope(user_id)
    if owner_id is None and not all_scans:
        return None
    query = select(Scan).where(Scan.id == scan_id)
    if not all_scans:
        query = query.where(Scan.user_id == owner_id)
    scan = db.session.scalar(query)
    return _serialize(scan) if scan else None


def _scope(user_id):
    if user_id is not None:
        return user_id, False
    try:
        from flask_login import current_user
        if current_user.is_authenticated:
            return current_user.id, bool(current_user.is_admin)
    except RuntimeError:
        pass
    return None, False


def _serialize(scan: Scan):
    data = scan.result_data or {}
    return {
        "id": scan.id, "url": scan.submitted_url, "normalized_url": scan.normalized_url,
        "prediction": scan.prediction, "ml_prediction": scan.ml_prediction,
        "risk_score": scan.risk_score, "ml_probability": scan.ml_probability,
        "domain": (data.get("whois") or {}).get("domain"),
        "is_blacklisted": bool((data.get("blacklist") or {}).get("is_blacklisted")),
        "domain_age_days": (data.get("whois") or {}).get("domain_age_days"),
        "reasons": data.get("reasons", []), "features": data.get("features", {}),
        "scanned_at": scan.created_at.isoformat(), "scan_status": scan.scan_status,
    }
