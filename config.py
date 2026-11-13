"""Shared paths and environment-backed configuration defaults."""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = str(Path(__file__).resolve().parent)
load_dotenv(Path(BASE_DIR) / ".env")

DATASET_PATH = os.path.join(BASE_DIR, "data", "phishing_dataset.csv")
BLACKLIST_PATH = os.getenv("BLACKLIST_PATH", os.path.join(BASE_DIR, "data", "blacklist.txt"))

MODEL_PATH = os.getenv("MODEL_PATH", os.path.join(BASE_DIR, "models", "phishing_model.pkl"))
MODEL_METADATA_PATH = os.getenv("MODEL_METADATA_PATH", os.path.join(BASE_DIR, "models", "model_metadata.json"))
METRICS_PATH = os.getenv("METRICS_PATH", os.path.join(BASE_DIR, "models", "model_metrics.json"))
CONFUSION_MATRIX_PATH = os.getenv("CONFUSION_MATRIX_PATH", os.path.join(BASE_DIR, "models", "confusion_matrix.png"))

DATABASE_PATH = os.path.join(BASE_DIR, "phishing_detection.db")
LOG_FILE_PATH = os.path.join(BASE_DIR, "logs", "predictions.log")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

# Operating thresholds are documented in README.md; scores are not calibrated.
PHISHING_THRESHOLD = float(os.getenv("PHISHING_THRESHOLD", "0.85"))
SUSPICIOUS_THRESHOLD = float(os.getenv("SUSPICIOUS_THRESHOLD", "0.55"))
ENABLE_WHOIS_LOOKUP = os.getenv("ENABLE_RDAP_LOOKUP", "true").lower() == "true"
