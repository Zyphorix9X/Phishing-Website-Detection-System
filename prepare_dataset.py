"""Prepare a duplicate-safe, domain-grouped PhiUSIIL URL dataset."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
import tldextract

BASE_DIR = Path(__file__).resolve().parent
RAW_DATASET_PATH = BASE_DIR / "data" / "raw" / "phiusiil.csv"
FINAL_DATASET_PATH = BASE_DIR / "data" / "phishing_dataset.csv"
TRAIN_DATASET_PATH = BASE_DIR / "data" / "train_dataset.csv"
TEST_DATASET_PATH = BASE_DIR / "data" / "test_dataset.csv"
REPORT_PATH = BASE_DIR / "data" / "dataset_report.json"
URL_COLUMNS = {"url", "website", "urlwebsite", "url_name"}
LABEL_COLUMNS = {"label", "class", "status", "phishing"}
_extract = tldextract.TLDExtract(suffix_list_urls=())


def find_column(df: pd.DataFrame, possible_names: set[str]) -> str:
    for name in df.columns:
        if re.sub(r"[^a-z0-9]", "", name.lower()) in possible_names:
            return name
    raise ValueError(f"Required column missing. Available columns: {list(df.columns)}")


def normalize_label(value, profile: str = "phiusiil") -> int:
    """Map labels using an explicit source profile, never a guessed column name."""
    if isinstance(value, str):
        clean = value.strip().lower()
        if clean in {"phishing", "phish", "malicious", "bad"}:
            return 1
        if clean in {"legitimate", "legit", "benign", "good", "safe"}:
            return 0
        value = clean
    if profile == "phiusiil":
        if str(value).strip() == "0":
            return 1  # UCI PhiUSIIL source: 0 = phishing
        if str(value).strip() == "1":
            return 0  # UCI PhiUSIIL source: 1 = legitimate
    elif profile == "project-standard":
        if str(value).strip() == "0":
            return 0
        if str(value).strip() == "1":
            return 1
    raise ValueError(f"Unsupported label value {value!r} for source profile {profile!r}.")


def normalize_url(url) -> str | None:
    raw = str(url).strip()
    if not raw or raw.lower() in {"nan", "none"} or any(ord(c) < 32 for c in raw):
        return None
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if parsed.username is not None or parsed.password is not None:
            return None
        port = parsed.port
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = f"{host}:{port}" if port else host
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, parsed.fragment))
    except (UnicodeError, ValueError):
        return None


def domain_group(url: str) -> str:
    host = urlsplit(url).hostname or ""
    parsed = _extract(host)
    return f"{parsed.domain}.{parsed.suffix}" if parsed.domain and parsed.suffix else host.lower()


def backup_if_present(path: Path) -> str | None:
    if not path.exists():
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = path.with_name(f"{path.name}.bak-{timestamp}")
    shutil.copy2(path, backup)
    return str(backup)


def prepare_dataset(raw_path: Path = RAW_DATASET_PATH, max_rows: int | None = None) -> dict:
    if not raw_path.is_file():
        raise FileNotFoundError(f"Source dataset not found: {raw_path}")
    header = pd.read_csv(raw_path, nrows=0)
    url_column = find_column(header, URL_COLUMNS)
    label_column = find_column(header, LABEL_COLUMNS)
    raw = pd.read_csv(raw_path, usecols=[url_column, label_column])
    raw_rows = len(raw)

    cleaned = pd.DataFrame({
        "url": raw[url_column].map(normalize_url),
        "label": raw[label_column].map(lambda value: normalize_label(value, "phiusiil")),
    }).dropna(subset=["url"])
    cleaned["url"] = cleaned["url"].astype(str)

    conflicts = cleaned.groupby("url")["label"].nunique()
    conflicting_urls = set(conflicts[conflicts > 1].index)
    no_conflicts = cleaned[~cleaned["url"].isin(conflicting_urls)]
    duplicate_rows_removed = int(len(no_conflicts) - no_conflicts["url"].nunique())
    cleaned = no_conflicts.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    cleaned["domain_group"] = cleaned["url"].map(domain_group)

    if max_rows is not None:
        if max_rows < 100:
            raise ValueError("--max-rows must be at least 100; small balanced demos can misstate evaluation quality.")
        cleaned = cleaned.iloc[:max_rows].copy()
    if cleaned["label"].nunique() != 2:
        raise ValueError("Both legitimate and phishing examples are required after cleaning.")
    if cleaned["domain_group"].nunique() < 2:
        raise ValueError("Domain-grouped splitting needs at least two registrable domains.")

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(splitter.split(cleaned, cleaned["label"], groups=cleaned["domain_group"]))
    train_df = cleaned.iloc[train_idx].drop(columns="domain_group").reset_index(drop=True)
    test_df = cleaned.iloc[test_idx].drop(columns="domain_group").reset_index(drop=True)
    if set(train_df.label) != {0, 1} or set(test_df.label) != {0, 1}:
        raise ValueError("Grouped split left a class out of train or test. Adjust domains or split size; labels were not rebalanced.")

    outputs = [FINAL_DATASET_PATH, TRAIN_DATASET_PATH, TEST_DATASET_PATH, REPORT_PATH]
    backups = {str(path): backup_if_present(path) for path in outputs}
    FINAL_DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    cleaned.drop(columns="domain_group").to_csv(FINAL_DATASET_PATH, index=False)
    train_df.to_csv(TRAIN_DATASET_PATH, index=False)
    test_df.to_csv(TEST_DATASET_PATH, index=False)

    train_domains = set(cleaned.iloc[train_idx]["domain_group"])
    test_domains = set(cleaned.iloc[test_idx]["domain_group"])
    report = {
        "schema_version": 2,
        "source_profile": "phiusiil",
        "source_dataset": "UCI PhiUSIIL Phishing URL Dataset",
        "source_label_mapping": {"0": "phishing", "1": "legitimate"},
        "label_standard": {"0": "legitimate", "1": "phishing"},
        "label_mapping": {"source_0_to_project_1": "phishing", "source_1_to_project_0": "legitimate"},
        "raw_rows": raw_rows,
        "cleaned_rows": len(cleaned),
        "conflicting_url_groups_removed": len(conflicting_urls),
        "duplicate_rows_removed": duplicate_rows_removed,
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "train_legitimate": int((train_df.label == 0).sum()),
        "train_phishing": int((train_df.label == 1).sum()),
        "test_legitimate": int((test_df.label == 0).sum()),
        "test_phishing": int((test_df.label == 1).sum()),
        "train_domains": len(train_domains),
        "test_domains": len(test_domains),
        "domain_overlap": len(train_domains & test_domains),
        "split_method": "GroupShuffleSplit by registrable domain; test set is not balanced",
        "url_column_detected": url_column,
        "label_column_detected": label_column,
        "backups_created": backups,
        "prepared_at": datetime.now(timezone.utc).isoformat(),
        "notes": [
            "Dataset labels were mapped from the documented PhiUSIIL source semantics.",
            "Conflicting labels for the same normalized URL were removed as a group.",
            "Exact duplicate URLs were removed without balancing classes.",
            "Train and test domains are disjoint.",
        ],
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, default=RAW_DATASET_PATH)
    parser.add_argument("--max-rows", type=int, help="Optional first-N row smoke run; never class-balances the output.")
    arguments = parser.parse_args()
    print(json.dumps(prepare_dataset(arguments.raw, arguments.max_rows), indent=2))
