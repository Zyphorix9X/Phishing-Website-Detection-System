from __future__ import annotations

import json
from functools import wraps
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, redirect, request, render_template, url_for
from flask_login import current_user, login_required
from sqlalchemy import case, func, select

from phishing_app.extensions import db
from phishing_app.models import AuditLog, Scan, User
from time_utils import sri_lanka_day_window

admin_bp = Blueprint("admin", __name__)


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@admin_bp.get("")
@admin_required
def overview():
    stats = {
        "users": db.session.scalar(select(func.count(User.id))) or 0,
        "scans": db.session.scalar(select(func.count(Scan.id))) or 0,
        "phishing": _count("PHISHING"),
        "suspicious": _count("SUSPICIOUS"),
        "legitimate": _count("LEGITIMATE"),
        "unverified": _count("UNVERIFIED"),
        "average_risk": round(float(db.session.scalar(select(func.avg(Scan.risk_score))) or 0), 1),
    }
    recent = db.session.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(12)).all()
    distribution = [stats[key] for key in ("phishing", "suspicious", "legitimate", "unverified")]
    trend = _platform_trend()
    return render_template("admin.html", stats=stats, scans=recent, distribution=distribution, trend=trend, metrics=_load_verified_metrics())


@admin_bp.get("/users")
@admin_required
def users():
    search = request.args.get("q", "").strip()[:100]
    query = select(User)
    if search:
        query = query.where(or_user_search(search))
    rows = db.session.scalars(query.order_by(User.created_at.desc()).limit(200)).all()
    return render_template("admin_users.html", users=rows, search=search)


@admin_bp.post("/users/<int:user_id>/toggle-active")
@admin_required
def toggle_user_active(user_id: int):
    target = db.session.get(User, user_id)
    if target is None:
        abort(404)
    if target.id == current_user.id:
        flash("You cannot deactivate your own administrator account.", "error")
    elif target.is_admin:
        flash("Administrator access is managed through the protected CLI.", "error")
    else:
        target.is_active = not target.is_active
        db.session.add(AuditLog(
            actor_id=current_user.id,
            action="user.activated" if target.is_active else "user.deactivated",
            metadata_json={"user_id": target.id, "email": target.email},
        ))
        db.session.commit()
        flash(f"Account {'activated' if target.is_active else 'deactivated'}.", "success")
    return redirect(url_for("admin.users", q=request.form.get("q", "")))


@admin_bp.get("/audit")
@admin_required
def audit():
    events = db.session.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(200)).all()
    return render_template("admin_audit.html", events=events)


@admin_bp.get("/system")
@admin_required
def system():
    model_path = Path(current_app.config["MODEL_PATH"])
    metrics = _load_verified_metrics()
    try:
        db.session.execute(select(1))
        database_status = "Connected"
    except Exception:
        db.session.rollback()
        database_status = "Unavailable"
    return render_template(
        "admin_system.html", model_exists=model_path.is_file(), metrics=metrics,
        queue_status=_worker_status(), database_status=database_status,
    )


def _count(verdict: str) -> int:
    return db.session.scalar(select(func.count(Scan.id)).where(Scan.prediction == verdict)) or 0


def _platform_trend() -> dict:
    lower_bound, labels = sri_lanka_day_window()
    day = func.date(func.timezone('Asia/Colombo', Scan.created_at)) if db.engine.dialect.name == 'postgresql' else func.date(Scan.created_at, '+330 minutes')
    rows = db.session.execute(
        select(
            day,
            func.count(Scan.id),
            func.sum(case((Scan.prediction == "PHISHING", 1), else_=0)),
        )
        .where(Scan.created_at >= lower_bound)
        .group_by(day)
        .order_by(day)
    ).all()
    daily = {str(day): (int(count), int(phishing or 0)) for day, count, phishing in rows}
    return {
        "labels": labels,
        "scan_values": [daily.get(day, (0, 0))[0] for day in labels],
        "phishing_values": [daily.get(day, (0, 0))[1] for day in labels],
    }


def _worker_status() -> str:
    celery = current_app.extensions.get("celery")
    if celery is None:
        return "Not configured"
    try:
        workers = celery.control.inspect(timeout=0.5).ping()
        return "Online" if workers else "No worker response"
    except Exception:
        return "Unavailable"


def or_user_search(search: str):
    return User.full_name.ilike(f"%{search}%") | User.email.ilike(f"%{search}%")


def _load_verified_metrics():
    try:
        metadata = json.loads(Path(current_app.config["MODEL_METADATA_PATH"]).read_text(encoding="utf-8"))
        metrics = json.loads(Path(current_app.config["METRICS_PATH"]).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if metadata.get("evaluation_label_mapping") != {"0": "legitimate", "1": "phishing"} or metadata.get("evaluation_schema_version") != 2:
        return None
    return metrics
