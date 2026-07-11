import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.join(BASE_DIR, "data", "phishing_dataset.csv")
BLACKLIST_PATH = os.path.join(BASE_DIR, "data", "blacklist.txt")

MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "models", "model_metrics.json")
CONFUSION_MATRIX_PATH = os.path.join(BASE_DIR, "models", "confusion_matrix.png")

DATABASE_PATH = os.path.join(BASE_DIR, "phishing_detection.db")
LOG_FILE_PATH = os.path.join(BASE_DIR, "logs", "predictions.log")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

PHISHING_THRESHOLD = 0.60

ENABLE_WHOIS_LOOKUP = True