from __future__ import annotations

from io import BytesIO

from flask import Blueprint, abort, current_app, jsonify, request, send_file
from flask_login import current_user, login_required
from flask_wtf.csrf import generate_csrf
from sqlalchemy import select

from phishing_app.extensions import db, limiter
from phishing_app.models import Report, Scan
from phishing_app.services.analysis import analyze_url
from phishing_app.services.reporting import generate_pdf_report
from phishing_app.blueprints.main import complete_scan, create_queued_scan, fail_scan, get_user_statistics, persist_scan
from phishing_app.validation import URLValidationError
from risk_summary import summarize_risk
from time_utils import sri_lanka_isoformat

api_bp = Blueprint("api", __name__)


@api_bp.get("/csrf-token")
@login_required
def csrf_token():
    return jsonify({"csrf_token": generate_csrf()})


@api_bp.post("/scans")
@login_required
@limiter.limit("20 per hour")
def create_scan():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {"url"} or not isinstance(payload.get("url"), str):
        return jsonify({"error": "invalid_request", "message": "Send a JSON object with one string field named url."}), 400
    queued = None
    try:
        celery_task = current_app.extensions.get("scan_task")
        if current_app.config["BACKGROUND_ANALYSIS_ENABLED"] and celery_task is not None:
            queued = create_queued_scan(payload["url"], current_user.id)
            try:
                celery_task.delay(queued.id)
                return jsonify({"scan_id": queued.id, "status": "queued"}), 202
            except Exception:
                current_app.logger.exception("Queue unavailable; falling back to inline API analysis")
        result = analyze_url(
            payload["url"], rdap_enabled=current_app.config["RDAP_ENABLED"],
            phishtank_api_key=current_app.config["PHISHTANK_API_KEY"],
            openphish_feed_url=current_app.config["OPENPHISH_FEED_URL"],
        )
    except URLValidationError as exc:
        return jsonify({"error": "invalid_url", "message": str(exc)}), 422
    except Exception:
        current_app.logger.exception("API URL analysis failed")
        if queued is not None:
            fail_scan(queued.id)
        return jsonify({"error": "analysis_unavailable", "message": "The URL could not be analyzed."}), 503
    scan = complete_scan(queued.id, result) if queued is not None else persist_scan(result, current_user.id)
    data = dict(result)
    data['scanned_at_local'] = sri_lanka_isoformat(data.get('scanned_at') or scan.completed_at or scan.created_at)
    data['display_timezone'] = 'Asia/Colombo'
    return jsonify({"scan_id": scan.id, "scan": data}), 201


@api_bp.get("/scans")
@login_required
def list_scans():
    limit = min(max(request.args.get("limit", 20, type=int), 1), 100)
    before = request.args.get("before", type=int)
    query = select(Scan).where(Scan.user_id == current_user.id)
    if before:
        query = query.where(Scan.id < before)
    scans = db.session.scalars(query.order_by(Scan.id.desc()).limit(limit)).all()
    return jsonify({"items": [_scan_summary(scan) for scan in scans], "next_before": scans[-1].id if len(scans) == limit else None})


@api_bp.get("/scans/<int:scan_id>")
@login_required
def get_scan(scan_id: int):
    scan = _owned_scan(scan_id)
    if scan is None:
        abort(404)
    data = dict(scan.result_data or {})
    data.update(summarize_risk(data))
    data['scanned_at_local'] = sri_lanka_isoformat(data.get('scanned_at') or scan.completed_at or scan.created_at)
    data['display_timezone'] = 'Asia/Colombo'
    return jsonify({"id": scan.id, "created_at": scan.created_at.isoformat(), "created_at_local": sri_lanka_isoformat(scan.created_at), "scan": data})


@api_bp.get("/scans/<int:scan_id>/report")
@login_required
def get_report(scan_id: int):
    scan = _owned_scan(scan_id)
    if scan is None:
        abort(404)
    db.session.add(Report(scan_id=scan.id, user_id=current_user.id, report_type="pdf"))
    db.session.commit()
    response = send_file(BytesIO(generate_pdf_report(scan, current_user)), mimetype="application/pdf", as_attachment=True, download_name=f"sentinel-scan-{scan.id}.pdf")
    response.headers["Cache-Control"] = "private, no-store"
    return response


@api_bp.get("/dashboard/statistics")
@login_required
def dashboard_statistics():
    return jsonify(get_user_statistics(current_user.id))


def _owned_scan(scan_id: int):
    return db.session.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id))


def _scan_summary(scan: Scan):
    return {
        "id": scan.id,
        "url": scan.submitted_url,
        "prediction": scan.prediction,
        "risk_score": scan.risk_score,
        "ml_phishing_probability": scan.ml_probability,
        "model_deployment_status": (scan.result_data or {}).get('model_deployment_status', 'not_recorded'),
        "url_indicator_score": (scan.result_data or {}).get('url_indicator_score'),
        "risk_percentage": summarize_risk(scan.result_data or {})['risk_percentage'],
        "risk_percentage_calibrated": False,
        "created_at": scan.created_at.isoformat(),
        "created_at_local": sri_lanka_isoformat(scan.created_at),
        "display_timezone": "Asia/Colombo",
    }
