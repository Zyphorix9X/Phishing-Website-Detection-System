import os
import json
import pandas as pd
from sklearn.model_selection import train_test_split

RAW_DATASET_PATH = os.path.join("data", "raw", "phiusiil.csv")
FINAL_DATASET_PATH = os.path.join("data", "phishing_dataset.csv")
TRAIN_DATASET_PATH = os.path.join("data", "train_dataset.csv")
TEST_DATASET_PATH = os.path.join("data", "test_dataset.csv")
REPORT_PATH = os.path.join("data", "dataset_report.json")


POSSIBLE_URL_COLUMNS = [
    "url",
    "URL",
    "Url",
    "website",
    "Website",
    "URLWebsite",
    "URL_Name"
]


POSSIBLE_LABEL_COLUMNS = [
    "label",
    "Label",
    "class",
    "Class",
    "status",
    "Status",
    "phishing",
    "Phishing"
]


def find_column(df, possible_names):
    for name in possible_names:
        if name in df.columns:
            return name

    raise ValueError(
        f"Could not find required column. Available columns: {list(df.columns)}"
    )


def normalize_url(url):
    url = str(url).strip()

    if not url:
        return None

    url = url.replace(" ", "")
    url = url.replace("\n", "")
    url = url.replace("\t", "")

    return url.lower()


def normalize_label(value):
    """
    Project standard:
    0 = legitimate
    1 = phishing

    PhiUSIIL Kaggle version may use:
    1 = legitimate
    0 = phishing

    So this function handles both text labels and numeric labels.
    """

    if isinstance(value, str):
        value_clean = value.strip().lower()

        if value_clean in ["phishing", "phish", "malicious", "bad", "1"]:
            return 1

        if value_clean in ["legitimate", "legit", "benign", "good", "safe", "0"]:
            return 0

    try:
        value_int = int(value)

        # IMPORTANT:
        # If your downloaded PhiUSIIL says 1 = legitimate and 0 = phishing,
        # keep this conversion:
        if value_int == 1:
            return 0
        if value_int == 0:
            return 1

    except Exception:
        pass

    raise ValueError(f"Unknown label value: {value}")


def prepare_dataset(max_rows_per_class=None):
    print("[INFO] Loading raw dataset...")

    if not os.path.exists(RAW_DATASET_PATH):
        raise FileNotFoundError(
            f"Raw dataset not found: {RAW_DATASET_PATH}\n"
            "Place your downloaded PhiUSIIL CSV file there."
        )

    df = pd.read_csv(RAW_DATASET_PATH)

    print("[INFO] Raw columns:")
    print(list(df.columns))

    url_column = find_column(df, POSSIBLE_URL_COLUMNS)
    label_column = find_column(df, POSSIBLE_LABEL_COLUMNS)

    print(f"[INFO] URL column detected: {url_column}")
    print(f"[INFO] Label column detected: {label_column}")

    cleaned = pd.DataFrame()
    cleaned["url"] = df[url_column].apply(normalize_url)
    cleaned["label"] = df[label_column].apply(normalize_label)

    before_drop = len(cleaned)

    cleaned = cleaned.dropna(subset=["url", "label"])
    cleaned = cleaned.drop_duplicates(subset=["url"])

    cleaned = cleaned[cleaned["url"].str.len() > 5]
    cleaned = cleaned[cleaned["url"].str.contains(r"\.", regex=True)]

    after_clean = len(cleaned)

    legitimate = cleaned[cleaned["label"] == 0]
    phishing = cleaned[cleaned["label"] == 1]

    print("[INFO] After cleaning:")
    print(f"Legitimate: {len(legitimate)}")
    print(f"Phishing: {len(phishing)}")

    if max_rows_per_class:
        legitimate = legitimate.sample(
            n=min(max_rows_per_class, len(legitimate)),
            random_state=42
        )

        phishing = phishing.sample(
            n=min(max_rows_per_class, len(phishing)),
            random_state=42
        )

    min_class_size = min(len(legitimate), len(phishing))

    legitimate = legitimate.sample(n=min_class_size, random_state=42)
    phishing = phishing.sample(n=min_class_size, random_state=42)

    final_df = pd.concat([legitimate, phishing])
    final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)

    train_df, test_df = train_test_split(
        final_df,
        test_size=0.2,
        random_state=42,
        stratify=final_df["label"]
    )

    os.makedirs("data", exist_ok=True)

    final_df.to_csv(FINAL_DATASET_PATH, index=False)
    train_df.to_csv(TRAIN_DATASET_PATH, index=False)
    test_df.to_csv(TEST_DATASET_PATH, index=False)

    report = {
        "raw_rows": before_drop,
        "cleaned_rows": after_clean,
        "final_rows": len(final_df),
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "legitimate_rows": int(len(final_df[final_df["label"] == 0])),
        "phishing_rows": int(len(final_df[final_df["label"] == 1])),
        "label_standard": {
            "0": "legitimate",
            "1": "phishing"
        },
        "url_column_detected": url_column,
        "label_column_detected": label_column,
        "notes": [
            "Duplicate URLs removed.",
            "Labels normalized to project standard.",
            "Dataset balanced to avoid class bias.",
            "Train/test split created using stratified sampling."
        ]
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n===== DATASET PREPARATION COMPLETE =====")
    print(json.dumps(report, indent=4))


if __name__ == "__main__":
    prepare_dataset()