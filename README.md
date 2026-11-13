# Sentinel Phishing URL Intelligence

Sentinel is a Flask application for analyzing suspicious URLs with the project's preserved Random Forest pipeline, URL indicators, local blacklist, optional RDAP and threat feeds, account-scoped scan history, and PDF reports. The UI borrows common scanner workflows from commercial security tools while using original branding and layout.

The scanner does not open submitted pages. It does not fetch redirects, execute page code, or create screenshots. RDAP requests go only to the fixed `rdap.org` service; optional PhishTank requests send the URL to PhishTank only when an API key is configured.

## Current application

- Flask application factory with Flask-SQLAlchemy, Flask-Migrate/Alembic, Flask-Login, Flask-WTF CSRF protection, and Flask-Limiter.
- SQLite for local development; PostgreSQL through `DATABASE_URL` for deployment.
- User registration, login, password hashing, remember-me sessions, per-IP login/scan rate limits, server-side role checks, and a protected `promote-user` CLI command.
- Public scans are ephemeral. Signed-in scans are stored and visible to their owner; administrators can review aggregate platform activity.
- Administrators can search accounts and disable or reactivate regular users; administrator role changes remain CLI-only, and an admin cannot disable their own account or another administrator.
- URL normalization supports HTTP/HTTPS, IDNs, IPv4, and IPv6 and rejects unsupported schemes, embedded credentials, malformed hosts, control characters, and overlong URLs.
- Risk index and model output are separate. The risk index is a heuristic, not a probability. The Random Forest class score is uncalibrated and is labeled accordingly.
- The preserved model is marked `research_only`: its score alone produces neither PHISHING nor LEGITIMATE. A confirmed threat-source match produces PHISHING; strong URL rules produce SUSPICIOUS; otherwise the result is UNVERIFIED. The overall risk rating is unavailable (`risk_score: null`) for an unvalidated or unavailable model. Separately recorded `url_indicator_score` points explain observed structure and do not establish safety.
- Result pages lead with verification status and provider coverage. Unvalidated scores are shown only in expandable experimental model details; PDFs use the same distinction. Hostname rules inspect the actual hostname rather than treating UUIDs, digits, hyphens, or ordinary query parameters as hostile domains. Existing scans retain their stored evidence; earlier rule notes are labelled historical.
- The main report shows `risk_percentage`, a weighted 0–100 indicator index displayed with a percent sign. For research models this uses completed rule checks (`url_indicator_score`), excluding the raw classifier output. For validated, available models it uses the combined heuristic index. It is explicitly uncalibrated (`risk_percentage_calibrated: false`) and is not a statistical phishing probability. A 0% indicator score means no scored indicators were found; verification can still be incomplete. PDF and API responses use the same calculation. Earlier scans without a recorded indicator score require a rescan.
- Only a model explicitly marked `deployment_status=validated` after independent review may use the model thresholds (`>= 0.85` PHISHING, `>= 0.55` SUSPICIOUS, lower LEGITIMATE). A training run does not grant this status automatically. LEGITIMATE is never a safety guarantee.
- Threat-source status distinguishes match, no match, unavailable, and not configured. The local list is always checked; OpenPhish and PhishTank are opt-in.
- RDAP registration lookups use short timeouts, one bounded retry, and an in-process cache. Missing registration data is displayed as unavailable.
- SHAP TreeExplainer is used when compatible with the loaded Random Forest; the application falls back to fitted-model feature ablation. Rule indicators remain separate from model explanations.
- Redis/Celery background analysis is optional locally and enabled in Docker Compose. Screenshot/DOM analysis remains disabled because an isolated browser worker is not included.
- PDF generation is in memory and report routes enforce scan ownership.

## Model and dataset notes

The preserved model has a severe formatting shortcut. In the raw PhiUSIIL file, every legitimate example uses a `www` hostname and an empty path. Adding an equivalent root slash to legitimate URLs can reverse the model's output. The earlier split also shares registrable domains between train and test. Domain grouping alone cannot remove the source formatting bias. Research-only scoring is now enforced to prevent these scores from becoming definitive accusations or safety claims.

Reproduce the offline diagnostic without changing the model, dataset, or scan history:

```powershell
python audit_model.py --sample-size 2000
```

The results are written to `reports/model_quality_audit.json` and `reports/model_quality_audit.md`, including source-label verification, formatting frequencies, domain overlap, and fixed-sample robustness checks. These are diagnostics, not independent deployment accuracy estimates. Existing historical scan verdicts remain as originally recorded; rescan a URL to use the new decision policy.

Before deployment, collect independently labeled legitimate URLs with varied hosts, paths, queries, and formatting, alongside current phishing data. Split by domain and evaluate false positives, recall, and equivalent root-URL spellings on an independent test set. Do not add an allowlist for a few well-known sites or strip all paths to make sample checks pass. Source labels must remain documented.

The existing 73 MB model artifact is preserved. Its pipeline serializes the importable `URLFeatureExtractor` in `ml_transformers.py`. The original training script retained the PhiUSIIL numeric labels, but the prediction code interpreted the positive class backwards. The [UCI PhiUSIIL dataset record](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) defines source label `0` as phishing and `1` as legitimate. Sentinel now maps those estimator classes correctly without rewriting the model.

The old `model_metrics.json` does not record that source-label meaning. Its phishing-specific metrics are therefore withheld in the admin UI. To create a new documented model version and verified evaluation:

```powershell
python prepare_dataset.py
python train_model.py
```

Preparation keeps the full cleaned dataset, removes duplicate URLs and conflicting URL labels, maps labels explicitly to `0 = legitimate` and `1 = phishing`, and creates a domain-grouped held-out split without balancing the test set. Existing prepared CSVs are copied to timestamped backups before replacement. Training verifies label metadata and rejects URL or registrable-domain overlap. The existing model, metadata, metrics, and confusion matrix are also backed up before a new model is written.

No training or metrics have been regenerated during this refactor. The source CSVs, train/test CSVs, model artifact, SQLite database, existing PDF, and the user's pre-existing change in `logs/predictions.log` were left intact.

## Windows PowerShell: local setup

Use Python 3.13. If the existing `.venv` points at an unavailable Microsoft Store Python installation, recreate it after installing Python 3.13 from python.org.

If the Python launcher does not list Python 3.13, use its installed executable directly. For the current workspace installation:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe" -m venv .venv
```

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and replace `SECRET_KEY` with a random value. Generate one with:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

For first-time setup against the preserved local SQLite file, apply migrations and start the server:

```powershell
flask --app app:app db upgrade
python app.py
```

The app imports existing `scan_history` rows into the new `scans` table without deleting the old table. Legacy rows remain unowned and are visible only to administrators; new scans belong to the signed-in user. Existing scan records keep their original verdict values because they cannot be safely recomputed from stored evidence alone.

Register an account at `http://127.0.0.1:5000/auth/register`, then promote it in a second PowerShell window:

```powershell
flask --app app:app promote-user you@example.com
```

The local app uses `http://127.0.0.1:5000`. It runs with debug mode disabled.

## Docker Compose

Docker Compose runs the Flask app, PostgreSQL, Redis, and Celery worker. The app image includes the preserved model and local blacklist but excludes the large training datasets. The existing SQLite database is mounted read-only for one-time scan-history import.

```powershell
Copy-Item .env.example .env
# Set SECRET_KEY to a random value and POSTGRES_PASSWORD to a strong URL-safe value.
docker compose up --build
```

After registering an account in the browser, promote it with:

```powershell
docker compose exec app flask --app app:app promote-user you@example.com
```

Set `SESSION_COOKIE_SECURE=true` when serving behind HTTPS. Do not expose the application directly to the public internet without TLS termination and a production secret. PostgreSQL data and Redis queues use named Docker volumes. No container runs privileged.

## REST API v1

All scan APIs require an authenticated session. POST requests also require a CSRF token. Fetch one from `GET /api/v1/csrf-token`, then send it in the `X-CSRFToken` header.

- `POST /api/v1/scans` — JSON body `{"url":"https://example.com"}`; returns `201` for inline analysis or `202` when queued.
- `GET /api/v1/scans` — current user's scans with bounded pagination (`limit`, `before`).
- `GET /api/v1/scans/<scan_id>` — one scan owned by the current user.
- `GET /api/v1/scans/<scan_id>/report` — private PDF for an owned scan.
- `GET /api/v1/dashboard/statistics` — statistics for the current user only.

## Main pages

Application event times are displayed in Sri Lanka Standard Time, labelled `SLST (GMT+05:30)`. Storage and the existing canonical API timestamps remain UTC. API responses also provide `scanned_at_local`/`created_at_local` with an explicit `+05:30` offset. Scan charts group events by the Sri Lankan calendar day. This conversion also applies to existing records without rewriting database timestamps.

- `/` — scanner landing page
- `/auth/register`, `/auth/login` — account entry
- `/dashboard` — personal scan overview and charts
- `/scan`, `/history`, `/analytics`, `/reports`, `/account` — user workspace
- `/admin` — administrator overview; `/admin/users`, `/admin/audit`, `/admin/system`
- `/health` — database readiness check for Docker

## Tests

Run the test suite from the project root:

```powershell
pytest
```

Tests use temporary SQLite databases and mocks for network providers. They do not visit submitted websites or run a live malicious-URL scan.

## Environment variables

See `.env.example` for the full template. Important settings:

- `SECRET_KEY` — required outside development.
- `DATABASE_URL` — leave blank to use the existing SQLite file; set a `postgresql+psycopg://...` URL for PostgreSQL.
- `AUTO_CREATE_DB` — defaults to false; use `flask db upgrade` for schema changes.
- `ENABLE_RDAP_LOOKUP` — toggles the bounded registration lookup.
- `PHISHTANK_API_KEY` — enables PhishTank checks and sends scanned URLs to the provider.
- `OPENPHISH_FEED_URL` — optional; only `https://openphish.com/feed.txt` is accepted.
- `REDIS_URL`, `BACKGROUND_ANALYSIS_ENABLED` — enable the background queue.
- `RATE_LIMIT_STORAGE_URI` — use Redis for shared limits across multiple app workers; defaults to process-local memory.
- `SESSION_COOKIE_SECURE` — enable behind HTTPS.

## Known limitations

- Password recovery, email verification, and administrator MFA are not implemented. Registration and password changes work; an email provider is not configured.
- SHAP is optional at runtime; if unavailable, explanations use model-feature ablation. If neither method can explain a loaded model, the UI says so.
- Screenshot, DOM, redirect, and brand-impersonation analysis are unavailable. Submitted pages are never opened.
- RDAP and external threat sources need network access. External feeds/credentials are optional and provider failures are shown as unavailable.
- Rate limits use process-local memory unless Redis storage is configured. Docker Compose configures Redis for shared rate limits and queued jobs.
- Administrator account controls are limited to regular-user activation; account deletion and administrator role changes are deliberately not available in the web interface.
- The preserved model's previous held-out metrics have not been recalculated with corrected label semantics. The admin panel hides them until the dataset is prepared and the model is retrained.
