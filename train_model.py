import json
import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    roc_auc_score
)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from config import MODEL_PATH, METRICS_PATH, CONFUSION_MATRIX_PATH
from ml_transformers import URLFeatureExtractor


TRAIN_DATASET_PATH = os.path.join("data", "train_dataset.csv")
TEST_DATASET_PATH = os.path.join("data", "test_dataset.csv")


def train():
    print("[INFO] Loading prepared train/test datasets...")

    if not os.path.exists(TRAIN_DATASET_PATH) or not os.path.exists(TEST_DATASET_PATH):
        raise FileNotFoundError(
            "Prepared train/test datasets not found. Run python prepare_dataset.py first."
        )

    train_df_raw = pd.read_csv(TRAIN_DATASET_PATH)
    test_df_raw = pd.read_csv(TEST_DATASET_PATH)

    X_train = train_df_raw["url"].astype(str)
    y_train = train_df_raw["label"].astype(int)

    X_test = test_df_raw["url"].astype(str)
    y_test = test_df_raw["label"].astype(int)

    print(f"[INFO] Training rows: {len(X_train)}")
    print(f"[INFO] Testing rows: {len(X_test)}")

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 5),
                    max_features=10000,
                    lowercase=True
                ),
                "url"
            ),
            (
                "manual_features",
                Pipeline([
                    ("extractor", URLFeatureExtractor()),
                    ("scaler", StandardScaler())
                ]),
                "url"
            )
        ]
    )

    model = Pipeline([
        ("features", preprocessor),
        ("classifier", RandomForestClassifier(
            n_estimators=500,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        ))
    ])

    train_df = pd.DataFrame({"url": X_train})
    test_df = pd.DataFrame({"url": X_test})

    print("[INFO] Training Random Forest model...")
    model.fit(train_df, y_train)

    print("[INFO] Evaluating model...")
    y_pred = model.predict(test_df)
    y_prob = model.predict_proba(test_df)[:, 1]

    metrics = {
        "dataset": {
            "train_rows": int(len(X_train)),
            "test_rows": int(len(X_test)),
            "train_legitimate": int((y_train == 0).sum()),
            "train_phishing": int((y_train == 1).sum()),
            "test_legitimate": int((y_test == 0).sum()),
            "test_phishing": int((y_test == 1).sum())
        },
        "performance": {
            "accuracy": round(accuracy_score(y_test, y_pred), 4),
            "precision": round(precision_score(y_test, y_pred), 4),
            "recall": round(recall_score(y_test, y_pred), 4),
            "f1_score": round(f1_score(y_test, y_pred), 4),
            "roc_auc": round(roc_auc_score(y_test, y_prob), 4)
        },
        "classification_report": classification_report(y_test, y_pred)
    }

    print("\n===== MODEL METRICS =====")
    print(json.dumps(metrics, indent=4))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    with open(METRICS_PATH, "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=4)

    cm = confusion_matrix(y_test, y_pred)

    display = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=["Legitimate", "Phishing"]
    )

    display.plot()
    plt.title("Phishing Detection Confusion Matrix")
    plt.savefig(CONFUSION_MATRIX_PATH, bbox_inches="tight")
    plt.close()

    print(f"[SUCCESS] Model saved: {MODEL_PATH}")
    print(f"[SUCCESS] Metrics saved: {METRICS_PATH}")
    print(f"[SUCCESS] Confusion matrix saved: {CONFUSION_MATRIX_PATH}")


if __name__ == "__main__":
    train()