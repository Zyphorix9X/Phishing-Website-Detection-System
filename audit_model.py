"""Audit the preserved URL model against source labels and URL formatting changes.

Reads existing files, performs no network requests, and writes only the audit reports.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import pandas as pd

from config import MODEL_METADATA_PATH, MODEL_PATH, PHISHING_THRESHOLD
from prepare_dataset import domain_group

ROOT = Path(__file__).resolve().parent


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _url_key(url: str) -> str:
    parsed = urlsplit(url.strip().lower())
    return urlunsplit(parsed._replace(path=parsed.path or '/'))


def _root_variant(url: str, slash: bool) -> str:
    parsed = urlsplit(url)
    if parsed.path in ('', '/'):
        return urlunsplit(parsed._replace(path='/' if slash else ''))
    return url


def audit(sample_size: int = 2000) -> dict:
    if sample_size < 1:
        raise ValueError('Sample size must be positive.')
    raw = pd.read_csv(ROOT / 'data/raw/phiusiil.csv', usecols=['URL', 'label'])
    raw['key'] = raw.URL.astype(str).map(_url_key)
    groups = raw.groupby('key').label
    unambiguous = groups.nunique().eq(1)
    source_labels = groups.first()[unambiguous]
    test = pd.read_csv(ROOT / 'data/test_dataset.csv')
    test['source_label'] = test.url.astype(str).map(_url_key).map(source_labels)
    covered = test.dropna(subset=['source_label'])
    train = pd.read_csv(ROOT / 'data/train_dataset.csv', usecols=['url'])
    train_domains = set(train.url.map(domain_group))
    test_domains = set(test.url.map(domain_group))
    metadata = json.loads(Path(MODEL_METADATA_PATH).read_text(encoding='utf-8'))
    model = joblib.load(MODEL_PATH)
    positive_index = list(model.classes_).index(metadata['positive_class_label'])

    def score(urls):
        return model.predict_proba(pd.DataFrame({'url': list(urls)}))[:, positive_index]

    source_formatting = []
    for label, frame in raw.groupby('label'):
        parsed = frame.URL.astype(str).map(urlsplit)
        source_formatting.append({
            'source_label': int(label), 'meaning': 'legitimate' if label == 1 else 'phishing',
            'rows': len(frame),
            'empty_path_percent': round(100 * float(parsed.map(lambda item: not item.path).mean()), 4),
            'root_slash_percent': round(100 * float(parsed.map(lambda item: item.path == '/').mean()), 4),
            'www_prefix_percent': round(100 * float(parsed.map(lambda item: (item.hostname or '').startswith('www.')).mean()), 4),
        })
    legitimate = covered[covered.source_label == 1].sample(n=min(sample_size, int((covered.source_label == 1).sum())), random_state=42)
    phishing = covered[covered.source_label == 0].sample(n=min(sample_size, int((covered.source_label == 0).sum())), random_state=42)
    if legitimate.empty or phishing.empty:
        raise ValueError('Source-label verification did not identify examples of both classes.')
    checks = []
    for name, frame, urls, benign in [
        ('legitimate_original', legitimate, legitimate.url, True),
        ('legitimate_root_slash', legitimate, legitimate.url.map(lambda url: _root_variant(url, True)), True),
        ('phishing_original', phishing, phishing.url, False),
        ('phishing_root_slash_removed', phishing, phishing.url.map(lambda url: _root_variant(url, False)), False),
    ]:
        scores = score(urls)
        flagged = int((scores >= PHISHING_THRESHOLD).sum())
        checks.append({
            'check': name, 'rows': len(frame), 'flagged_as_phishing': flagged,
            'false_positives' if benign else 'missed_at_threshold': flagged if benign else len(frame) - flagged,
            'mean_phishing_score': round(float(scores.mean()), 6),
        })
    report = {
        'created_at': datetime.now(timezone.utc).isoformat(),
        'model_sha256': _digest(Path(MODEL_PATH)),
        'feature_extractor_sha256': _digest(ROOT / 'feature_extractor.py'),
        'deployment_status': metadata.get('deployment_status', 'research_only'),
        'source': 'UCI PhiUSIIL',
        'source_reference': 'https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset',
        'source_labels': {'0': 'phishing', '1': 'legitimate'},
        'source_formatting': source_formatting,
        'split': {'train_rows': len(train), 'test_rows': len(test), 'test_domains': len(test_domains),
                  'overlapping_domains': len(train_domains & test_domains),
                  'test_rows_with_unambiguous_source_label': len(covered)},
        'threshold': PHISHING_THRESHOLD, 'sample_seed': 42, 'checks': checks,
        'limitations': [
            'These are diagnostics of the preserved split, not independent deployment accuracy estimates.',
            'All legitimate source examples share www and empty-path formatting, allowing a spurious shortcut.',
            'Removing root slashes can reduce false positives while also hiding genuine phishing examples; it is not a general accuracy fix.',
            'Independent, representative legitimate hosts and paths and current phishing examples are needed before deployment validation.',
        ],
    }
    output = ROOT / 'reports'
    output.mkdir(exist_ok=True)
    (output / 'model_quality_audit.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    lines = ['# Preserved model quality audit', '',
             'The model is a research artifact and must not determine definitive verdicts alone.', '',
             f"Model SHA-256: `{report['model_sha256']}`", '',
             '[Source label documentation](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)', '',
             '| Source class | Rows | Empty path | Root slash | www prefix |',
             '| --- | ---: | ---: | ---: | ---: |']
    for row in source_formatting:
        lines.append(f"| {row['meaning']} | {row['rows']} | {row['empty_path_percent']}% | {row['root_slash_percent']}% | {row['www_prefix_percent']}% |")
    lines += ['', f"Train/test domain overlap: **{report['split']['overlapping_domains']}** domains.", '',
              f'Fixed sample seed: 42. Model score threshold: {PHISHING_THRESHOLD}.', '',
              '| Diagnostic | Rows | Flagged phishing | Mean model score |', '| --- | ---: | ---: | ---: |']
    for row in checks:
        lines.append(f"| {row['check']} | {row['rows']} | {row['flagged_as_phishing']} | {row['mean_phishing_score']} |")
    lines += ['', *('- ' + item for item in report['limitations']), '']
    (output / 'model_quality_audit.md').write_text('\n'.join(lines), encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sample-size', type=int, default=2000)
    print(json.dumps(audit(parser.parse_args().sample_size), indent=2))
