def init_celery(app):
    broker_url = app.config.get("REDIS_URL")
    if not broker_url:
        app.extensions["celery"] = None
        app.extensions["scan_task"] = None
        return None

    from celery import Celery

    celery = Celery("phishing_app", broker=broker_url, backend=app.config.get("CELERY_RESULT_BACKEND"))
    celery.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        task_ignore_result=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        broker_connection_retry_on_startup=True,
        task_track_started=True,
    )

    @celery.task(name="phishing_app.analyze_scan", autoretry_for=(), ignore_result=True)
    def analyze_scan(scan_id: int):
        from phishing_app.extensions import db
        from phishing_app.models import AuditLog, Scan
        from phishing_app.services.analysis import analyze_url
        from phishing_app.blueprints.main import complete_scan

        with app.app_context():
            scan = db.session.get(Scan, scan_id)
            if scan is None or scan.scan_status != "queued":
                return
            try:
                result = analyze_url(
                    scan.normalized_url,
                    rdap_enabled=app.config["RDAP_ENABLED"],
                    phishtank_api_key=app.config["PHISHTANK_API_KEY"],
                    openphish_feed_url=app.config["OPENPHISH_FEED_URL"],
                )
                complete_scan(scan.id, result)
            except Exception:
                app.logger.exception("Background URL analysis failed for scan %s", scan.id)
                scan.scan_status = "failed"
                scan.result_data = {
                    "url": scan.submitted_url,
                    "normalized_url": scan.normalized_url,
                    "prediction": "UNVERIFIED",
                    "ml_prediction": "UNVERIFIED",
                    "risk_score": None,
                    "ml_phishing_probability": None,
                    "scanned_at": None,
                    "reasons": [],
                    "features": {},
                    "whois": {"domain": "Unavailable", "lookup_status": "unavailable"},
                    "blacklist": {"status": "unavailable", "is_blacklisted": False},
                    "threat_intelligence": [],
                    "model_explanation": {"status": "unavailable", "method": None, "items": []},
                    "screenshot_analysis": {"status": "unavailable", "message": "Isolated webpage analysis is disabled."},
                    "error": "Analysis is temporarily unavailable.",
                }
                db.session.add(AuditLog(actor_id=scan.user_id, action="scan.failed", metadata_json={"scan_id": scan.id}))
                db.session.commit()

    app.extensions["celery"] = celery
    app.extensions["scan_task"] = analyze_scan
    return celery
