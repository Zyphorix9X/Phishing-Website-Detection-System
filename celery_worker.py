"""Celery worker entry point; shares the Flask application configuration."""

from app import app

celery = app.extensions.get("celery")
if celery is None:
    raise RuntimeError("Set REDIS_URL to start the background worker.")
