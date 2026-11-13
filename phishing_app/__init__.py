"""Application package for the phishing intelligence platform."""

from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

import click
from flask import Flask, current_app, jsonify, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import inspect, select

from config import BASE_DIR, CONFUSION_MATRIX_PATH, LOG_FILE_PATH, METRICS_PATH
from phishing_app.extensions import csrf, db, limiter, login_manager, migrate
from phishing_app.models import AuditLog, Scan, User
from time_utils import format_sri_lanka_time


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    database_url = os.getenv("DATABASE_URL")
    if database_url and database_url.startswith(("postgres://", "postgresql://")):
        database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1).replace("postgresql://", "postgresql+psycopg://", 1)
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "local-development-key-change-before-deploy"),
        APP_ENV=os.getenv("APP_ENV", "development"),
        SQLALCHEMY_DATABASE_URI=database_url or f"sqlite:///{Path(BASE_DIR, 'phishing_detection.db').as_posix()}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
        AUTO_CREATE_DB=os.getenv("AUTO_CREATE_DB", "false").lower() == "true",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
        SESSION_COOKIE_SAMESITE="Lax",
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
        WTF_CSRF_TIME_LIMIT=3600,
        MAX_CONTENT_LENGTH=16 * 1024,
        MODEL_PATH=os.getenv("MODEL_PATH", os.path.join(BASE_DIR, "models", "phishing_model.pkl")),
        MODEL_METADATA_PATH=os.getenv("MODEL_METADATA_PATH", os.path.join(BASE_DIR, "models", "model_metadata.json")),
        METRICS_PATH=METRICS_PATH,
        CONFUSION_MATRIX_PATH=CONFUSION_MATRIX_PATH,
        RDAP_ENABLED=os.getenv("ENABLE_RDAP_LOOKUP", "true").lower() == "true",
        PHISHTANK_API_KEY=os.getenv("PHISHTANK_API_KEY", ""),
        OPENPHISH_FEED_URL=os.getenv("OPENPHISH_FEED_URL", ""),
        REDIS_URL=os.getenv("REDIS_URL", ""),
        BACKGROUND_ANALYSIS_ENABLED=os.getenv("BACKGROUND_ANALYSIS_ENABLED", "false").lower() == "true",
        LEGACY_SQLITE_PATH=os.getenv("LEGACY_SQLITE_PATH", ""),
        RATE_LIMIT_STORAGE_URI=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
        RATELIMIT_STORAGE_URI=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
    )
    if test_config:
        app.config.update(test_config)
    app.jinja_env.filters['sl_time'] = format_sri_lanka_time

    if app.config["APP_ENV"] == "production":
        secret = app.config["SECRET_KEY"]
        if len(secret) < 32 or secret.startswith("replace-with-") or secret == "local-development-key-change-before-deploy":
            raise RuntimeError("Set SECRET_KEY to a random value of at least 32 characters before starting in production.")
        database_host = urlsplit(app.config["SQLALCHEMY_DATABASE_URI"]).hostname
        postgres_password = os.getenv("POSTGRES_PASSWORD", "")
        if database_host == "db" and (len(postgres_password) < 24 or postgres_password.startswith("replace-")):
            raise RuntimeError("Set POSTGRES_PASSWORD to a strong URL-safe value before starting Docker Compose.")

    Path(LOG_FILE_PATH).parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[logging.StreamHandler()],
    )

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "info"

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify({"error": "authentication_required", "message": "Sign in to use this endpoint."}), 401
        return redirect(url_for("auth.login", next=request.url))

    csrf.init_app(app)
    limiter.init_app(app)

    from phishing_app.blueprints.admin import admin_bp
    from phishing_app.blueprints.api import api_bp
    from phishing_app.blueprints.auth import auth_bp
    from phishing_app.blueprints.main import main_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    from phishing_app.celery_ext import init_celery
    init_celery(app)

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:
        user = db.session.get(User, int(user_id))
        return user if user is not None and user.is_active else None

    @app.context_processor
    def inject_navigation_state() -> dict:
        return {"current_user": current_user}

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; connect-src 'self'; "
            "font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.errorhandler(400)
    def bad_request(error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "bad_request", "message": "The request could not be processed."}), 400
        return render_template("error.html", code=400, message="The request could not be processed."), 400

    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "not_found", "message": "Resource not found."}), 404
        return render_template("error.html", code=404, message="That page could not be found."), 404

    @app.errorhandler(429)
    def rate_limited(error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "rate_limited", "message": "Too many requests. Try again shortly."}), 429
        return render_template("error.html", code=429, message="Too many requests. Try again shortly."), 429

    @app.cli.command("promote-user")
    @click.argument("email")
    def promote_user(email: str) -> None:
        """Promote an existing account to administrator."""
        user = db.session.scalar(select(User).where(User.email == email.strip().lower()))
        if user is None:
            raise click.ClickException("No account exists for that email address.")
        if user.role == "admin":
            click.echo("That account is already an administrator.")
            return
        user.role = "admin"
        db.session.add(AuditLog(actor_id=None, action="user.promoted_to_admin", metadata_json={"user_id": user.id, "email": user.email}))
        db.session.commit()
        click.echo(f"Promoted {user.email} to administrator.")

    @app.cli.command("init-local-db")
    def init_local_db() -> None:
        """Create local SQLite tables and preserve legacy scan records."""
        with app.app_context():
            db.create_all()
            migrated = _migrate_legacy_scans()
        click.echo(f"Database ready. Preserved {migrated} legacy scan records.")

    if app.config.get("AUTO_CREATE_DB") and app.config.get("APP_ENV") != "production":
        with app.app_context():
            db.create_all()
            _migrate_legacy_scans()
    elif app.config.get("APP_ENV") != "production":
        with app.app_context():
            if db.engine.dialect.name == "sqlite" and "scans" in inspect(db.engine).get_table_names():
                _migrate_legacy_scans()
    elif app.config.get("LEGACY_SQLITE_PATH") and Path(app.config["LEGACY_SQLITE_PATH"]).is_file():
        with app.app_context():
            if "scans" in inspect(db.engine).get_table_names():
                _migrate_legacy_scans()

    return app


def _migrate_legacy_scans() -> int:
    """Copy the legacy SQLite history into the new schema without deleting it."""
    if "scans" not in inspect(db.engine).get_table_names():
        return 0
    legacy_path = current_app.config.get("LEGACY_SQLITE_PATH")
    current_path = db.engine.url.database if db.engine.dialect.name == "sqlite" else None
    use_legacy_file = bool(legacy_path and Path(legacy_path).is_file() and (not current_path or Path(legacy_path).resolve() != Path(current_path).resolve()))
    source_path = legacy_path if use_legacy_file else current_path
    if not source_path:
        return 0
    connection = sqlite3.connect(source_path)
    try:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "scan_history" not in tables:
            return 0
        columns = {column[1] for column in connection.execute("PRAGMA table_info(scan_history)")}
        required = {"id", "url", "prediction", "ml_prediction", "risk_score", "ml_probability", "domain", "is_blacklisted", "domain_age_days", "reasons", "features", "scanned_at"}
        if not required.issubset(columns):
            logging.getLogger(__name__).warning("Legacy scan_history has an unexpected schema; leaving it untouched.")
            return 0
        rows = connection.execute(
            "SELECT id, url, prediction, ml_prediction, risk_score, ml_probability, domain, "
            "is_blacklisted, domain_age_days, reasons, features, scanned_at FROM scan_history ORDER BY id"
        ).fetchall()
    finally:
        connection.close()
    migrated = 0
    for row in rows:
        if db.session.get(Scan, int(row[0])) is not None:
            continue
        try:
            import json
            reasons = json.loads(row[9] or "[]")
            features = json.loads(row[10] or "{}")
        except (TypeError, ValueError):
            reasons, features = [], {}
        result_data = {
            "legacy_record": True,
            "legacy_verdict_semantics": "Stored by the previous application. Historical predictions are preserved as recorded and may use reversed PhiUSIIL class names.",
            "url": row[1],
            "normalized_url": row[1],
            "scanned_at": row[11],
            "risk_score": float(row[4] or 0),
            "ml_phishing_probability": float(row[5]) if row[5] is not None else None,
            "ml_prediction": row[3] or "UNVERIFIED",
            "score_explanation": "Legacy stored value; the original risk calculation was not a calibrated probability.",
            "reasons": reasons if isinstance(reasons, list) else [],
            "features": features if isinstance(features, dict) else {},
            "domain": row[6],
            "is_blacklisted": bool(row[7]),
            "domain_age_days": row[8],
            "blacklist": {"domain": row[6], "is_blacklisted": bool(row[7]), "status": "legacy_record"},
            "whois": {"domain": row[6], "domain_age_days": row[8], "lookup_status": "legacy_record"},
            "threat_intelligence": [],
            "model_explanation": {"status": "unavailable", "method": None, "items": []},
            "screenshot_analysis": {"status": "unavailable", "message": "Legacy records did not include isolated webpage analysis."},
        }
        db.session.add(Scan(
            id=int(row[0]), user_id=None, submitted_url=row[1], normalized_url=row[1],
            prediction=row[2], ml_prediction=row[3] or "UNVERIFIED", risk_score=float(row[4] or 0),
            ml_probability=float(row[5]) if row[5] is not None else None,
            scan_status="completed", created_at=_parse_legacy_datetime(row[11]),
            completed_at=_parse_legacy_datetime(row[11]), result_data=result_data,
        ))
        migrated += 1
    if migrated:
        db.session.commit()
    return migrated


def _parse_legacy_datetime(value):
    from datetime import datetime, timezone
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
