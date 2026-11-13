"""Train and evaluate a versioned Random Forest URL classifier."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from config import CONFUSION_MATRIX_PATH, METRICS_PATH, MODEL_METADATA_PATH, MODEL_PATH
from ml_transformers import URLFeatureExtractor
from prepare_dataset import domain_group

BASE_DIR = Path(__file__).resolve().parent
TRAIN_DATASET_PATH = BASE_DIR / "data" / "train_dataset.csv"
TEST_DATASET_PATH = BASE_DIR / "data" / "test_dataset.csv"
DATASET_REPORT_PATH = BASE_DIR / "data" / "dataset_report.json"
LABEL_MAPPING = {"0": "legitimate", "1": "phishing"}


def _load_prepared_data():
    if not TRAIN_DATASET_PATH.exists() or not TEST_DATASET_PATH.exists() or not DATASET_REPORT_PATH.exists():
        raise FileNotFoundError("Prepared domain-grouped datasets are missing. Run python prepare_dataset.py first.")
    manifest = json.loads(DATASET_REPORT_PATH.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 2 or manifest.get("source_profile") != "phiusiil" or manifest.get("label_standard") != LABEL_MAPPING:
        raise ValueError("Dataset labels are not verified for the project convention (0=legitimate, 1=phishing). Run python prepare_dataset.py first.")
    train = pd.read_csv(TRAIN_DATASET_PATH, usecols=["url", "label"])
    test = pd.read_csv(TEST_DATASET_PATH, usecols=["url", "label"])
    for name, frame in (("train", train), ("test", test)):
        if frame.empty or set(frame.label.astype(int).unique()) != {0, 1}:
            raise ValueError(f"{name} data must contain both project labels 0 and 1.")
        if frame.url.isna().any():
            raise ValueError(f"{name} data contains missing URLs.")
        frame["label"] = frame["label"].astype(int)
    train_urls = set(train.url.astype(str))
    test_urls = set(test.url.astype(str))
    if train_urls & test_urls:
        raise ValueError("Train/test URL overlap detected; recreate the grouped split.")
    train_domains = {domain_group(url) for url in train_urls}
    test_domains = {domain_group(url) for url in test_urls}
    if train_domains & test_domains:
        raise ValueError("Train/test domain leakage detected; recreate the grouped split.")
    return train, test, manifest


def _make_model():
    preprocessor = ColumnTransformer(
        transformers=[
            ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=10000, lowercase=True), "url"),
            ("manual_features", Pipeline([
                ("extractor", URLFeatureExtractor()),
                ("scaler", StandardScaler()),
            ]), "url"),
        ],
    )
    return Pipeline([
        ("features", preprocessor),
        ("classifier", RandomForestClassifier(
            n_estimators=500,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])


def _backup(path: Path) -> str | None:
    if not path.is_file():
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, backup_path)
    return str(backup_path)


def train() -> dict:
    train_df, test_df, dataset_manifest = _load_prepared_data()
    x_train = pd.DataFrame({"url": train_df.url.astype(str)})
    y_train = train_df.label.astype(int)
    x_test = pd.DataFrame({"url": test_df.url.astype(str)})
    y_test = test_df.label.astype(int)
    if y_test.nunique() != 2:
        raise ValueError("Held-out evaluation needs both classes; do not balance or rewrite the test set to force this.")

    model = _make_model()
    print(f"[INFO] Training on {len(x_train):,} domain-grouped URLs; held-out test has {len(x_test):,} URLs.")
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    phishing_index = list(model.classes_).index(1)
    phishing_scores = model.predict_proba(x_test)[:, phishing_index]
    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    metrics = {
        "evaluation_schema_version": 2,
        "label_mapping": LABEL_MAPPING,
        "dataset": {
            "train_rows": int(len(train_df)), "test_rows": int(len(test_df)),
            "train_legitimate": int((y_train == 0).sum()), "train_phishing": int((y_train == 1).sum()),
            "test_legitimate": int((y_test == 0).sum()), "test_phishing": int((y_test == 1).sum()),
            "train_domains": dataset_manifest.get("train_domains"),
            "test_domains": dataset_manifest.get("test_domains"),
            "domain_overlap": 0,
        },
        "performance": {
            "accuracy": round(float(accuracy_score(y_test, predictions)), 6),
            "precision": round(float(precision_score(y_test, predictions, pos_label=1, zero_division=0)), 6),
            "recall": round(float(recall_score(y_test, predictions, pos_label=1, zero_division=0)), 6),
            "f1_score": round(float(f1_score(y_test, predictions, pos_label=1, zero_division=0)), 6),
            "roc_auc": round(float(roc_auc_score(y_test, phishing_scores)), 6),
            "false_positive_rate": round(fp / max(tn + fp, 1), 6),
            "false_negative_rate": round(fn / max(fn + tp, 1), 6),
        },
        "confusion_matrix": {"labels": ["legitimate", "phishing"], "true_negative": tn, "false_positive": fp, "false_negative": fn, "true_positive": tp},
        "classification_report": classification_report(y_test, predictions, labels=[0, 1], target_names=["legitimate", "phishing"], output_dict=True, zero_division=0),
    }
    metadata = {
        "model_version": f"rf-url-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}",
        "model_type": "RandomForestClassifier pipeline with character TF-IDF and URLFeatureExtractor",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "python_sklearn_version": sklearn.__version__,
        "source_profile": dataset_manifest["source_profile"],
        "source_label_mapping": dataset_manifest["source_label_mapping"],
        "positive_class_label": 1,
        "deployment_status": "research_only",
        "deployment_warning": "This research model requires independent testing on representative legitimate paths, hostnames, and current phishing URLs before its scores can determine definitive verdicts.",
        "class_meanings": {"0": "legitimate", "1": "phishing"},
        "evaluation_schema_version": 2,
        "evaluation_label_mapping": LABEL_MAPPING,
        "feature_pipeline": ["character-level TF-IDF (3-5 grams)", "URL lexical and structural features"],
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "test_domain_overlap": 0,
        "metrics_file": Path(METRICS_PATH).name,
    }

    model_path = Path(MODEL_PATH)
    metrics_path = Path(METRICS_PATH)
    metadata_path = Path(MODEL_METADATA_PATH)
    confusion_path = Path(CONFUSION_MATRIX_PATH)
    for path in (model_path, metrics_path, metadata_path, confusion_path):
        path.parent.mkdir(parents=True, exist_ok=True)
    backups = {str(path): _backup(path) for path in (model_path, metrics_path, metadata_path, confusion_path)}
    temp_model = model_path.with_name(model_path.name + ".tmp")
    joblib.dump(model, temp_model, compress=3)
    os.replace(temp_model, model_path)
    metadata["replaced_artifact_backups"] = backups
    metrics["training_metadata"] = metadata
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    display = ConfusionMatrixDisplay(confusion_matrix=matrix, display_labels=["Legitimate", "Phishing"])
    display.plot(cmap="Blues", colorbar=False)
    plt.title("Phishing detection · domain-grouped held-out test")
    plt.tight_layout()
    plt.savefig(confusion_path, bbox_inches="tight")
    plt.close()
    print(json.dumps(metrics, indent=2))
    print(f"[SUCCESS] Versioned model, metadata, metrics, and confusion matrix saved. Backups: {backups}")
    return metrics


if __name__ == "__main__":
    train()
