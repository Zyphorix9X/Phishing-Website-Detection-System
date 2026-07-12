import json
import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from config import DATASET_PATH, MODEL_PATH, METRICS_PATH, CONFUSION_MATRIX_PATH
from ml_transformers import URLFeatureExtractor


def train():
    print("[INFO] Loading dataset...")

    df = pd.read_csv(DATASET_PATH)

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    df = df.dropna(subset=["url", "label"])
    df["url"] = df["url"].astype(str)
    df["label"] = df["label"].astype(int)

    print("[INFO] Dataset size:", len(df))
    print("[INFO] Legitimate:", len(df[df["label"] == 0]))
    print("[INFO] Phishing:", len(df[df["label"] == 1]))

    X = df["url"]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 5),
                    max_features=7000,
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
            n_estimators=400,
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

    print("[INFO] Training model...")
    model.fit(train_df, y_train)

    print("[INFO] Evaluating model...")
    y_pred = model.predict(test_df)

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
        "classification_report": classification_report(y_test, y_pred)
    }

    print("\n===== MODEL METRICS =====")
    print(json.dumps(metrics, indent=4))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    print("[INFO] Saving model...")
    joblib.dump(model, MODEL_PATH)

    with open(METRICS_PATH, "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=4)

    print("[INFO] Creating confusion matrix...")
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