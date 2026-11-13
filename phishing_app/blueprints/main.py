from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from phishing_app.extensions import db, limiter
from phishing_app.forms import AccountForm, ScanForm
from phishing_app.models import AuditLog, DomainIntelligence, Report, Scan, ScanFinding, ThreatIntelligence, User, utcnow
from phishing_app.services.analysis import analyze_url
from phishing_app.services.reporting import generate_pdf_report
from phishing_app.validation import normalize_url
from risk_summary import summarize_risk
from time_utils import sri_lanka_day_window

main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def index():
    return render_template("index.html", form=ScanForm())


@main_bp.get("/health")
def health():
    try:
        db.session.execute(select(1))
        return jsonify({"status": "ok"}), 200
    except Exception:
        current_app.logger.exception("Database health check failed")
        return jsonify({"status": "unavailable"}), 503


@main_bp.route("/scan", methods=["GET", "POST"])
@limiter.limit("20 per hour")
def scan():
    form = ScanForm()
    if request.method == "GET":
        return render_template("scan.html", form=form)
    if not form.validate_on_submit():
        return render_template("index.html", form=form), 400
    celery_task = current_app.extensions.get("scan_task")
    if current_user.is_authenticated and current_app.config["BACKGROUND_ANALYSIS_ENABLED"] and celery_task is not None:
        record = create_queued_scan(form.url.data, current_user.id)
        try:
            celery_task.delay(record.id)
            return render_template("result.html", result=record.result_data, scan=record, guest=False)
        except Exception:
            current_app.logger.exception("Queue unavailable; running bounded analysis inline")
            try:
                result = analyze_url(
                    record.normalized_url, rdap_enabled=current_app.config["RDAP_ENABLED"],
                    phishtank_api_key=current_app.config["PHISHTANK_API_KEY"],
                    openphish_feed_url=current_app.config["OPENPHISH_FEED_URL"],
                )
                complete_scan(record.id, result)
                return render_template("result.html", result=result, scan=record, guest=False)
            except Exception:
                current_app.logger.exception("Inline URL analysis failed after queue fallback")
                flash("The URL could not be analyzed. Please try again.", "error")
                return render_template("index.html", form=form), 503
    try:
        result = analyze_url(
            form.url.data,
            rdap_enabled=current_app.config["RDAP_ENABLED"],
            phishtank_api_key=current_app.config["PHISHTANK_API_KEY"],
            openphish_feed_url=current_app.config["OPENPHISH_FEED_URL"],
        )
    except Exception:
        current_app.logger.exception("URL analysis failed")
        flash("The URL could not be analyzed. Please try again.", "error")
        return render_template("index.html", form=form), 503

    scan_record = None
    if current_user.is_authenticated:
        scan_record = persist_scan(result, current_user.id)
    return render_template("result.html", result=result, scan=scan_record, guest=not current_user.is_authenticated)


@main_bp.get("/dashboard")
@login_required
def dashboard():
    stats = get_user_statistics(current_user.id)
    recent = db.session.scalars(
        select(Scan).where(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).limit(6)
    ).all()
    return render_template("dashboard.html", stats=stats, scans=recent)


@main_bp.get("/history")
@login_required
def history():
    page = max(request.args.get("page", 1, type=int), 1)
    limit = min(max(request.args.get("limit", 20, type=int), 1), 100)
    query = select(Scan).where(Scan.user_id == current_user.id)
    verdict = request.args.get("verdict", "").upper()
    if verdict in {"PHISHING", "SUSPICIOUS", "LEGITIMATE", "UNVERIFIED"}:
        query = query.where(Scan.prediction == verdict)
    search = request.args.get("q", "").strip()[:100]
    if search:
        query = query.where(or_(Scan.submitted_url.ilike(f"%{search}%"), Scan.normalized_url.ilike(f"%{search}%")))
    total = db.session.scalar(select(func.count()).select_from(query.subquery())) or 0
    scans = db.session.scalars(query.order_by(Scan.created_at.desc()).offset((page - 1) * limit).limit(limit)).all()
    return render_template("history.html", scans=scans, page=page, limit=limit, total=total, search=search, verdict=verdict)


@main_bp.get("/scans/<int:scan_id>")
@login_required
def scan_detail(scan_id: int):
    record = get_owned_scan(scan_id)
    if record is None:
        abort(404)
    return render_template("result.html", result=_result_for_view(record), scan=record, guest=False)


@main_bp.get("/scans/<int:scan_id>/status")
@login_required
def scan_status(scan_id: int):
    record = get_owned_scan(scan_id)
    if record is None:
        abort(404)
    return jsonify({"status": record.scan_status, "url": url_for("main.scan_detail", scan_id=record.id)})


@main_bp.get("/analytics")
@login_required
def analytics():
    return render_template("analytics.html", stats=get_user_statistics(current_user.id))


@main_bp.get("/reports")
@login_required
def reports():
    items = db.session.scalars(select(Report).where(Report.user_id == current_user.id).order_by(Report.created_at.desc()).limit(100)).all()
    return render_template("reports.html", reports=items)


@main_bp.get("/report/<int:scan_id>")
@login_required
def download_report(scan_id: int):
    record = get_owned_scan(scan_id)
    if record is None:
        abort(404)
    db.session.add(Report(scan_id=record.id, user_id=current_user.id, report_type="pdf"))
    db.session.commit()
    pdf = generate_pdf_report(record, current_user)
    response = send_file(BytesIO(pdf), mimetype="application/pdf", as_attachment=True, download_name=f"sentinel-scan-{record.id}.pdf")
    response.headers["Cache-Control"] = "private, no-store"
    return response


@main_bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    form = AccountForm(obj=current_user)
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        duplicate = db.session.scalar(select(User.id).where(User.email == email, User.id != current_user.id))
        sensitive_change = email != current_user.email or bool(form.new_password.data)
        if duplicate is not None:
            form.email.errors.append("That email address is already in use.")
        elif sensitive_change and (not form.current_password.data or not current_user.check_password(form.current_password.data)):
            form.current_password.errors.append("Enter your correct current password to change your email or password.")
        elif form.new_password.data and current_user.check_password(form.new_password.data):
            form.new_password.errors.append("Choose a password different from your current password.")
        else:
            current_user.full_name = form.full_name.data.strip()
            if email != current_user.email:
                current_user.email_verified = False
            current_user.email = email
            if form.new_password.data:
                current_user.set_password(form.new_password.data)
            db.session.add(AuditLog(actor_id=current_user.id, action="account.updated", metadata_json={"password_changed": bool(form.new_password.data)}))
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                form.email.errors.append("That email address is already in use.")
            else:
                flash("Your profile has been updated.", "success")
                return redirect(url_for("main.account"))
    return render_template("account.html", form=form)


def persist_scan(result: dict, user_id: int | None) -> Scan:
    record = Scan(
        user_id=user_id,
        submitted_url=result["url"],
        normalized_url=result["normalized_url"],
        prediction="UNVERIFIED", ml_prediction="UNVERIFIED", scan_status="queued",
        result_data={},
    )
    db.session.add(record)
    db.session.flush()
    record_id = record.id
    complete_scan(record_id, result)
    return db.session.get(Scan, record_id)


def create_queued_scan(url: str, user_id: int) -> Scan:
    normalized = normalize_url(url)
    record = Scan(
        user_id=user_id, submitted_url=url, normalized_url=normalized,
        prediction="UNVERIFIED", ml_prediction="UNVERIFIED", scan_status="queued",
        result_data={
            "url": url, "normalized_url": normalized, "prediction": "UNVERIFIED",
            "ml_prediction": "UNVERIFIED", "risk_score": None,
            "ml_phishing_probability": None, "model_status": "pending",
            "scanned_at": None, "score_explanation": "Analysis is in progress.",
            "reasons": [], "features": {}, "threat_intelligence": [],
            "whois": {"domain": "Looking up…", "lookup_status": "pending"},
            "model_explanation": {"status": "unavailable", "method": None, "items": []},
            "screenshot_analysis": {"status": "unavailable", "message": "Isolated webpage analysis is disabled."},
        },
    )
    db.session.add(record)
    db.session.flush()
    db.session.add(AuditLog(actor_id=user_id, action="scan.queued", metadata_json={"scan_id": record.id}))
    db.session.commit()
    return record


def complete_scan(scan_id: int, result: dict) -> Scan:
    record = db.session.get(Scan, scan_id)
    if record is None:
        raise ValueError("Scan record no longer exists.")
    record.prediction = result["prediction"]
    record.ml_prediction = result["ml_prediction"]
    record.ml_probability = result["ml_phishing_probability"]
    record.risk_score = result["risk_score"]
    record.scan_status = "completed"
    record.completed_at = utcnow()
    record.result_data = result
    indicators = result.get('url_indicators')
    findings = indicators if indicators is not None else [{'description': reason, 'severity': 'medium'} for reason in result.get('reasons', [])]
    for finding in findings:
        db.session.add(ScanFinding(
            scan_id=record.id, finding_type="url_indicator", severity=finding['severity'],
            description=finding['description'], source="rule_based_analysis",
            metadata_json={key: finding[key] for key in ('code', 'points') if key in finding},
        ))
    domain = result.get("whois", {})
    registered = _date_or_none(domain.get("registration_date"))
    expires = _date_or_none(domain.get("expiration_date"))
    db.session.add(DomainIntelligence(
        scan_id=record.id, domain=domain.get("domain") or "unknown",
        registration_date=registered, expiration_date=expires,
        domain_age_days=domain.get("domain_age_days"), registrar=domain.get("registrar"),
        lookup_status=domain.get("lookup_status", "unavailable"),
    ))
    for item in result.get("threat_intelligence", []):
        db.session.add(ThreatIntelligence(
            scan_id=record.id, provider=item.get("provider", "unknown"),
            match_status=item.get("status", "unavailable"), evidence=item.get("evidence", {}),
        ))
    if record.user_id is not None:
        db.session.add(AuditLog(actor_id=record.user_id, action="scan.completed", metadata_json={"scan_id": record.id, "verdict": record.prediction}))
    db.session.commit()
    return record


def fail_scan(scan_id: int, *, user_message: str = "Analysis is temporarily unavailable.") -> Scan:
    """Mark an asynchronous scan as failed without storing exception details."""
    record = db.session.get(Scan, scan_id)
    if record is None:
        raise ValueError("Scan record no longer exists.")
    record.scan_status = "failed"
    record.completed_at = utcnow()
    record.result_data = {
        "url": record.submitted_url,
        "normalized_url": record.normalized_url,
        "prediction": "UNVERIFIED",
        "ml_prediction": "UNVERIFIED",
        "risk_score": None,
        "ml_phishing_probability": None,
        "scanned_at": None,
        "score_explanation": "No analysis result was produced.",
        "reasons": [],
        "features": {},
        "whois": {"domain": "Unavailable", "lookup_status": "unavailable"},
        "blacklist": {"status": "unavailable", "is_blacklisted": False},
        "threat_intelligence": [],
        "model_explanation": {"status": "unavailable", "method": None, "items": []},
        "screenshot_analysis": {"status": "unavailable", "message": "Isolated webpage analysis is disabled."},
        "error": user_message,
    }
    if record.user_id is not None:
        db.session.add(AuditLog(actor_id=record.user_id, action="scan.failed", metadata_json={"scan_id": record.id}))
    db.session.commit()
    return record


def _result_for_view(record: Scan) -> dict:
    result = dict(record.result_data or {})
    result.setdefault("url", record.submitted_url)
    result.setdefault("normalized_url", record.normalized_url)
    result.setdefault("prediction", record.prediction)
    result.setdefault("ml_prediction", record.ml_prediction)
    result.setdefault("risk_score", record.risk_score)
    result.setdefault("ml_phishing_probability", record.ml_probability)
    result.setdefault("threat_intelligence", [])
    result.setdefault("whois", {"domain": "Unavailable", "lookup_status": "unavailable"})
    result.setdefault("reasons", [])
    result.setdefault("features", {})
    result.setdefault("model_explanation", {"status": "unavailable", "method": None, "items": []})
    result.setdefault("screenshot_analysis", {"status": "unavailable", "message": "Isolated webpage analysis is disabled."})
    result.setdefault("score_explanation", "Heuristic index, not a probability.")
    result.update(summarize_risk(result))
    return result


def get_owned_scan(scan_id: int) -> Scan | None:
    query = select(Scan).where(Scan.id == scan_id)
    if not current_user.is_admin:
        query = query.where(Scan.user_id == current_user.id)
    return db.session.scalar(query)


def get_user_statistics(user_id: int) -> dict:
    base = Scan.user_id == user_id
    counts = {}
    for verdict in ("PHISHING", "SUSPICIOUS", "LEGITIMATE", "UNVERIFIED"):
        counts[verdict.lower()] = db.session.scalar(select(func.count(Scan.id)).where(base, Scan.prediction == verdict)) or 0
    total = db.session.scalar(select(func.count(Scan.id)).where(base)) or 0
    avg_risk = db.session.scalar(select(func.avg(Scan.risk_score)).where(base))
    lower_bound, labels = sri_lanka_day_window()
    day = func.date(func.timezone('Asia/Colombo', Scan.created_at)) if db.engine.dialect.name == 'postgresql' else func.date(Scan.created_at, '+330 minutes')
    rows = db.session.execute(
        select(day, func.count(Scan.id)).where(base, Scan.created_at >= lower_bound).group_by(day).order_by(day)
    ).all()
    daily = {str(day): int(count) for day, count in rows}
    return {
        "total": total,
        "phishing": counts["phishing"],
        "suspicious": counts["suspicious"],
        "legitimate": counts["legitimate"],
        "unverified": counts["unverified"],
        "average_risk": round(float(avg_risk), 1) if avg_risk is not None else None,
        "trend_labels": labels,
        "trend_values": [daily.get(day, 0) for day in labels],
        "distribution_labels": ["Phishing", "Suspicious", "Legitimate", "Unverified"],
        "distribution_values": [counts["phishing"], counts["suspicious"], counts["legitimate"], counts["unverified"]],
    }


def _date_or_none(value: str | None):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None
