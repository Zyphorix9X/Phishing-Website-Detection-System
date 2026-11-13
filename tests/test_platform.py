import json
import sqlite3
from datetime import datetime, timezone

from sqlalchemy import func, select

import pytest

from phishing_app import create_app
from phishing_app.extensions import db
from phishing_app.models import Report, Scan, User


PASSWORD = "Strong-password-123!"


@pytest.fixture
def app(tmp_path):
    application = create_app({
        "TESTING": True,
        "APP_ENV": "test",
        "SECRET_KEY": "unit-test-session-secret-1234567890",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'platform.sqlite').as_posix()}",
        "AUTO_CREATE_DB": True,
        "WTF_CSRF_ENABLED": False,
        "RATELIMIT_ENABLED": False,
        "RDAP_ENABLED": False,
        "BACKGROUND_ANALYSIS_ENABLED": False,
    })
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def _registration_data(email="person@example.com", password=PASSWORD):
    return {
        "full_name": "Test User",
        "email": email,
        "password": password,
        "confirm_password": password,
    }


def _create_user(app, email, role="user"):
    with app.app_context():
        user = User(full_name=email.split("@")[0], email=email, role=role)
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()
        return user.id


def _create_scan(app, owner_id):
    with app.app_context():
        scan = Scan(
            user_id=owner_id,
            submitted_url="https://example.com/path",
            normalized_url="https://example.com/path",
            prediction="LEGITIMATE",
            ml_prediction="LEGITIMATE",
            ml_probability=0.08,
            risk_score=12,
            scan_status="completed",
            result_data={"url": "https://example.com/path", "scanned_at": "2026-01-01T00:00:00+00:00"},
        )
        db.session.add(scan)
        db.session.commit()
        return scan.id


def test_application_factory_can_start_before_migrations(tmp_path):
    app = create_app({
        "TESTING": True,
        "APP_ENV": "test",
        "SECRET_KEY": "unit-test-session-secret-1234567890",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'not-initialized.sqlite').as_posix()}",
        "AUTO_CREATE_DB": False,
    })

    assert app.config["AUTO_CREATE_DB"] is False


def test_legacy_sqlite_scans_are_copied_without_deleting_source(tmp_path):
    legacy_path = tmp_path / "legacy.sqlite"
    connection = sqlite3.connect(legacy_path)
    connection.execute(
        "CREATE TABLE scan_history (id INTEGER PRIMARY KEY, url TEXT, prediction TEXT, ml_prediction TEXT, "
        "risk_score REAL, ml_probability REAL, domain TEXT, is_blacklisted INTEGER, domain_age_days INTEGER, "
        "reasons TEXT, features TEXT, scanned_at TEXT)"
    )
    connection.execute(
        "INSERT INTO scan_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (7, "https://legacy.example/path", "LEGITIMATE", "LEGITIMATE", 12.0, 0.08, "example", 0, None,
         json.dumps(["Historical finding"]), json.dumps({"url_length": 28}), "2025-01-02T03:04:05"),
    )
    connection.commit()
    connection.close()

    app = create_app({
        "TESTING": True,
        "APP_ENV": "test",
        "SECRET_KEY": "migration-test-session-secret-1234567890",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'new.sqlite').as_posix()}",
        "AUTO_CREATE_DB": True,
        "LEGACY_SQLITE_PATH": str(legacy_path),
    })
    with app.app_context():
        migrated = db.session.get(Scan, 7)
        assert migrated is not None
        assert migrated.user_id is None
        assert migrated.result_data["legacy_record"] is True
        assert migrated.result_data["features"] == {"url_length": 28}

    connection = sqlite3.connect(legacy_path)
    assert connection.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0] == 1
    connection.close()


def test_registration_hashes_password_and_login_logout_work(client, app):
    response = client.post("/auth/register", data=_registration_data(), follow_redirects=False)
    assert response.status_code == 302

    with app.app_context():
        user = db.session.scalar(select(User).where(User.email == "person@example.com"))
        assert user is not None
        assert user.password_hash != PASSWORD
        assert user.check_password(PASSWORD)

    assert client.post("/auth/logout").status_code == 302
    assert client.post("/auth/login", data={"email": "person@example.com", "password": PASSWORD}).status_code == 302
    assert client.get("/dashboard").status_code == 200


def test_registration_rejects_weak_password(client, app):
    response = client.post("/auth/register", data=_registration_data(password="weak"))
    assert response.status_code == 200
    assert b"at least 12 characters" in response.data
    with app.app_context():
        assert db.session.scalar(select(func.count(User.id))) == 0


def test_duplicate_registration_is_rejected(client, app):
    client.post("/auth/register", data=_registration_data())
    client.post("/auth/logout")
    response = client.post("/auth/register", data=_registration_data())
    assert response.status_code == 200
    assert b"An account already exists" in response.data
    with app.app_context():
        assert db.session.scalar(select(func.count(User.id))) == 1


def test_non_admin_cannot_access_admin_routes(client):
    client.post("/auth/register", data=_registration_data())
    assert client.get("/admin").status_code == 403


def test_admin_can_access_admin_overview(client, app):
    _create_user(app, "admin@example.com", role="admin")
    response = client.post("/auth/login", data={"email": "admin@example.com", "password": PASSWORD})
    assert response.status_code == 302
    assert client.get("/admin").status_code == 200


def test_admin_can_disable_regular_user_and_their_session_is_invalidated(app):
    admin_id = _create_user(app, "admin@example.com", role="admin")
    user_id = _create_user(app, "person@example.com")
    admin_client = app.test_client()
    user_client = app.test_client()
    assert admin_client.post("/auth/login", data={"email": "admin@example.com", "password": PASSWORD}).status_code == 302
    assert user_client.post("/auth/login", data={"email": "person@example.com", "password": PASSWORD}).status_code == 302

    changed = admin_client.post(f"/admin/users/{user_id}/toggle-active", data={"q": "person"})
    assert changed.status_code == 302
    assert user_client.get("/dashboard").status_code == 302
    assert user_client.post("/auth/login", data={"email": "person@example.com", "password": PASSWORD}).status_code == 200
    with app.app_context():
        assert db.session.get(User, admin_id).is_active is True
        assert db.session.get(User, user_id).is_active is False


def test_admin_cannot_disable_self_or_another_admin(client, app):
    admin_id = _create_user(app, "admin@example.com", role="admin")
    other_admin_id = _create_user(app, "other-admin@example.com", role="admin")
    client.post("/auth/login", data={"email": "admin@example.com", "password": PASSWORD})

    assert client.post(f"/admin/users/{admin_id}/toggle-active").status_code == 302
    assert client.post(f"/admin/users/{other_admin_id}/toggle-active").status_code == 302
    with app.app_context():
        assert db.session.get(User, admin_id).is_active is True
        assert db.session.get(User, other_admin_id).is_active is True


def test_user_cannot_read_or_download_another_users_scan(client, app):
    owner_id = _create_user(app, "owner@example.com")
    other_id = _create_user(app, "other@example.com")
    scan_id = _create_scan(app, owner_id)
    client.post("/auth/login", data={"email": "other@example.com", "password": PASSWORD})

    assert client.get(f"/scans/{scan_id}").status_code == 404
    assert client.get(f"/report/{scan_id}").status_code == 404
    assert client.get(f"/api/v1/scans/{scan_id}").status_code == 404
    with app.app_context():
        assert db.session.scalar(select(func.count(Report.id))) == 0


def test_owner_can_download_pdf_report(client, app):
    owner_id = _create_user(app, "owner@example.com")
    scan_id = _create_scan(app, owner_id)
    client.post("/auth/login", data={"email": "owner@example.com", "password": PASSWORD})

    response = client.get(f"/report/{scan_id}")

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF")
    with app.app_context():
        assert db.session.scalar(select(func.count(Report.id))) == 1


def test_research_result_shows_warning_and_generates_pdf(client, app):
    owner_id = _create_user(app, 'owner@example.com')
    scan_id = _create_scan(app, owner_id)
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        scan.prediction = 'UNVERIFIED'
        scan.ml_prediction = 'PHISHING'
        scan.ml_probability = 0.964
        scan.risk_score = 0
        scan.result_data = dict(scan.result_data, model_warning='The research classifier is not independently validated.',
            decision_explanation='No confirmed threat-source match was found.')
        db.session.commit()
    client.post('/auth/login', data={'email': 'owner@example.com', 'password': PASSWORD})
    response = client.get(f'/scans/{scan_id}')
    assert response.status_code == 200
    assert b'The research classifier is not independently validated.' in response.data
    assert b'not a confirmed detection' in response.data
    main_result = response.data.split(b'<details class="content-card model-diagnostics"')[0]
    assert b'RISK INDICATOR SCORE' in main_result
    assert b'Run a new scan for a risk score' in main_result
    assert b'96.4%' not in main_result
    assert b'96.4%' in response.data
    pdf = client.get(f'/report/{scan_id}')
    assert pdf.status_code == 200
    assert pdf.mimetype == 'application/pdf'
    assert pdf.data.startswith(b'%PDF')


def test_course_link_report_keeps_diagnostics_separate_and_saves_consistent_indicators(client, app, monkeypatch):
    import predict

    class ResearchModel:
        classes_ = [0, 1]

        def predict_proba(self, frame):
            return [[0.958, 0.042]]

    monkeypatch.setattr(predict, 'load_model', lambda: ResearchModel())
    monkeypatch.setattr(predict, 'load_model_metadata', lambda: {
        'positive_class_label': 0, 'deployment_status': 'research_only', 'model_version': 'test-research',
    })
    monkeypatch.setattr(predict, 'check_threat_intelligence', lambda *a, **k: [
        {'provider': 'Local blacklist', 'status': 'no_match', 'matched': False, 'evidence': {}},
        {'provider': 'OpenPhish', 'status': 'not_configured', 'matched': False, 'evidence': {}},
        {'provider': 'PhishTank', 'status': 'not_configured', 'matched': False, 'evidence': {}},
    ])
    monkeypatch.setattr(predict, 'get_domain_intelligence', lambda *a, **k: {
        'domain': 'netacad.com', 'domain_age_days': None, 'registration_date': None,
        'expiration_date': None, 'registrar': None, 'lookup_status': 'unavailable',
    })
    client.post('/auth/register', data=_registration_data())
    response = client.post('/api/v1/scans', json={
        'url': 'https://www.netacad.com/launch?id=aaaaaaaa-1234-4567-8901-aaaaaaaaaaaa&view=bbbbbbbb-2345-4567-8901-bbbbbbbbbbbb',
    })
    assert response.status_code == 201
    result = response.json['scan']
    assert result['prediction'] == 'UNVERIFIED'
    assert result['risk_score'] is None
    assert result['url_indicator_score'] == 0
    assert result['risk_percentage'] == 0
    assert result['risk_percentage_calibrated'] is False
    assert all(item['severity'] == 'info' for item in result['url_indicators'])
    scan_id = response.json['scan_id']
    page = client.get(f'/scans/{scan_id}')
    assert page.status_code == 200
    primary = page.data.split(b'<details class="content-card model-diagnostics"')[0]
    assert b'95.8%' not in primary
    assert b'95.8%' in page.data
    assert b'<strong class="risk-score-value">0%</strong>' in primary
    assert b'No scored risk indicators found' in primary
    assert b'Verification incomplete' in primary
    assert b'not the probability' in primary
    assert b'2 not configured' in primary
    assert b'0 indicator points' in primary
    assert b'URL contains many hyphens' not in page.data
    assert client.get('/api/v1/dashboard/statistics').json['average_risk'] is None
    pdf = client.get(f'/report/{scan_id}')
    assert pdf.status_code == 200
    assert pdf.data.startswith(b'%PDF')
    with app.app_context():
        record = db.session.get(Scan, scan_id)
        assert record.risk_score is None
        assert all(finding.metadata_json['points'] == 0 for finding in record.findings)


def test_api_requires_login_and_validates_json(client):
    unauthorized = client.get("/api/v1/scans")
    assert unauthorized.status_code == 401
    assert unauthorized.json["error"] == "authentication_required"

    client.post("/auth/register", data=_registration_data())
    invalid_shape = client.post("/api/v1/scans", json={"url": "https://example.com", "extra": True})
    invalid_url = client.post("/api/v1/scans", json={"url": "file:///etc/passwd"})
    assert invalid_shape.status_code == 400
    assert invalid_url.status_code == 422


def test_csrf_protection_rejects_post_without_token(tmp_path):
    app = create_app({
        "TESTING": True,
        "APP_ENV": "test",
        "SECRET_KEY": "csrf-test-session-secret-1234567890",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'csrf.sqlite').as_posix()}",
        "AUTO_CREATE_DB": True,
        "WTF_CSRF_ENABLED": True,
        "RATELIMIT_ENABLED": False,
    })
    response = app.test_client().post("/auth/login", data={"email": "person@example.com", "password": PASSWORD})
    assert response.status_code == 400


def test_guest_scan_is_ephemeral_and_does_not_store_history(client, app, monkeypatch):
    from phishing_app.blueprints import main

    result = {
        "url": "https://example.com/path",
        "normalized_url": "https://example.com/path",
        "prediction": "UNVERIFIED",
        "ml_prediction": "UNVERIFIED",
        "risk_score": None,
        "ml_phishing_probability": None,
        "model_status": "unavailable",
        "reasons": [],
        "features": {},
        "whois": {"domain": "example.com", "lookup_status": "unavailable"},
        "threat_intelligence": [],
        "model_explanation": {"status": "unavailable", "method": None, "items": []},
        "screenshot_analysis": {"status": "unavailable", "message": "disabled"},
        "scanned_at": "2026-01-01T00:00:00+00:00",
    }
    monkeypatch.setattr(main, "analyze_url", lambda *args, **kwargs: result)

    response = client.post("/scan", data={"url": "https://example.com/path"})

    assert response.status_code == 200
    assert b"UNVERIFIED" in response.data
    with app.app_context():
        assert db.session.scalar(select(func.count(Scan.id))) == 0


def _profile_data(**changes):
    fields = {
        'full_name': 'Test User', 'email': 'person@example.com',
        'current_password': '', 'new_password': '', 'confirm_password': '',
    }
    fields.update(changes)
    return fields


def test_scan_time_is_local_in_pages_and_api_while_storage_remains_utc(client, app):
    owner_id = _create_user(app, 'owner@example.com')
    scan_id = _create_scan(app, owner_id)
    utc = datetime(2026, 11, 13, 16, 40, 17, tzinfo=timezone.utc)
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        scan.created_at = utc
        scan.completed_at = utc
        scan.result_data = dict(scan.result_data, scanned_at=utc.isoformat())
        db.session.commit()
    client.post('/auth/login', data={'email': 'owner@example.com', 'password': PASSWORD})
    page = client.get(f'/scans/{scan_id}')
    assert page.status_code == 200
    assert b'13 Nov 2026, 10:10 PM SLST (GMT+05:30)' in page.data
    assert b'22:10 SLST (GMT+05:30)' in client.get('/history').data
    response = client.get(f'/api/v1/scans/{scan_id}').json
    assert response['scan']['scanned_at'] == utc.isoformat()
    assert response['scan']['scanned_at_local'] == '2026-11-13T22:10:17+05:30'
    assert response['created_at_local'] == '2026-11-13T22:10:17+05:30'
    assert response['scan']['display_timezone'] == 'Asia/Colombo'
    assert client.get(f'/report/{scan_id}').status_code == 200
    with app.app_context():
        stored = db.session.get(Scan, scan_id)
        assert stored.created_at.hour == 16
        assert stored.result_data['scanned_at'] == utc.isoformat()


def test_scan_trends_group_using_sri_lanka_calendar_days(app, monkeypatch):
    from phishing_app.blueprints import main, admin
    from time_utils import sri_lanka_day_window

    owner_id = _create_user(app, 'owner@example.com')
    window = sri_lanka_day_window(now=datetime(2026, 11, 13, 19, tzinfo=timezone.utc))
    monkeypatch.setattr(main, 'sri_lanka_day_window', lambda: window)
    monkeypatch.setattr(admin, 'sri_lanka_day_window', lambda: window)
    with app.app_context():
        for stamp in [datetime(2026, 11, 13, 0, tzinfo=timezone.utc),
                      datetime(2026, 11, 13, 18, 29, tzinfo=timezone.utc),
                      datetime(2026, 11, 13, 18, 30, tzinfo=timezone.utc)]:
            db.session.add(Scan(user_id=owner_id, submitted_url='https://example.org', normalized_url='https://example.org',
                prediction='UNVERIFIED', ml_prediction='UNVERIFIED', created_at=stamp, result_data={}))
        db.session.commit()
        personal = main.get_user_statistics(owner_id)
        platform = admin._platform_trend()
        assert personal['trend_labels'][-2:] == ['2026-11-13', '2026-11-14']
        assert personal['trend_values'][-2:] == [2, 1]
        assert platform['labels'][-2:] == ['2026-11-13', '2026-11-14']
        assert platform['scan_values'][-2:] == [2, 1]


def test_profile_requires_sign_in_and_account_link_opens_profile(client):
    assert client.get('/account').status_code == 302
    client.post('/auth/register', data=_registration_data())
    response = client.get('/account')
    assert response.status_code == 200
    assert b'aria-label="Edit your profile"' in response.data
    assert b'href="/dashboard"' in response.data
    assert b'aria-label="Main navigation"' in response.data
    assert b'id="profile-form"' in response.data
    assert b'type="email"' in response.data


def test_profile_name_edit_normalizes_whitespace_without_changing_role(client, app):
    client.post('/auth/register', data=_registration_data())
    response = client.post('/account', data=_profile_data(full_name="  Senura   D’Silva  ", role='admin'))
    assert response.status_code == 302
    with app.app_context():
        user = db.session.scalar(select(User))
        assert user.full_name == 'Senura D’Silva'
        assert user.role == 'user'


@pytest.mark.parametrize('name', [' ', 'A', '12345', '<script>alert(1)</script>', 'Name\nInjected', 'A' * 121])
def test_profile_rejects_invalid_names_without_saving(client, app, name):
    client.post('/auth/register', data=_registration_data())
    response = client.post('/account', data=_profile_data(full_name=name))
    assert response.status_code == 200
    assert b'Your changes have not been saved' in response.data
    with app.app_context():
        assert db.session.scalar(select(User)).full_name == 'Test User'


@pytest.mark.parametrize('email', ['invalid', 'name..test@example.com', 'person@-example.com', 'person@example..com'])
def test_profile_rejects_invalid_emails(client, app, email):
    client.post('/auth/register', data=_registration_data())
    response = client.post('/account', data=_profile_data(email=email, current_password=PASSWORD))
    assert response.status_code == 200
    with app.app_context():
        assert db.session.scalar(select(User)).email == 'person@example.com'


@pytest.mark.parametrize('password', ['', 'Incorrect-password-123!'])
def test_email_change_requires_correct_current_password(client, app, password):
    client.post('/auth/register', data=_registration_data())
    response = client.post('/account', data=_profile_data(email='new@example.com', current_password=password))
    assert response.status_code == 200
    assert b'correct current password' in response.data
    with app.app_context():
        assert db.session.scalar(select(User)).email == 'person@example.com'


def test_profile_rejects_duplicate_email_without_partial_updates(client, app):
    _create_user(app, 'taken@example.com')
    client.post('/auth/register', data=_registration_data())
    response = client.post('/account', data=_profile_data(full_name='Changed Name', email='taken@example.com', current_password=PASSWORD))
    assert b'email address is already in use' in response.data
    with app.app_context():
        user = db.session.scalar(select(User).where(User.email == 'person@example.com'))
        assert user.full_name == 'Test User'


def test_profile_changes_email_and_password_and_resets_verification(client, app):
    client.post('/auth/register', data=_registration_data())
    with app.app_context():
        db.session.scalar(select(User)).email_verified = True
        db.session.commit()
    new_password = 'Replacement-password-456!'
    response = client.post('/account', data=_profile_data(
        email='NEW@example.com', current_password=PASSWORD,
        new_password=new_password, confirm_password=new_password,
    ))
    assert response.status_code == 302
    with app.app_context():
        user = db.session.scalar(select(User))
        assert user.email == 'new@example.com'
        assert user.email_verified is False
        assert user.check_password(new_password)
        assert not user.check_password(PASSWORD)


@pytest.mark.parametrize('new_password,confirmation', [
    ('weak', 'weak'), (PASSWORD, PASSWORD),
    ('New-password-456!', 'Different-password-456!'),
    ('A' * 257, 'A' * 257),
])
def test_profile_rejects_weak_reused_or_unconfirmed_password(client, app, new_password, confirmation):
    client.post('/auth/register', data=_registration_data())
    response = client.post('/account', data=_profile_data(
        current_password=PASSWORD, new_password=new_password, confirm_password=confirmation,
    ))
    assert response.status_code == 200
    assert b'Your changes have not been saved' in response.data
    with app.app_context():
        assert db.session.scalar(select(User)).check_password(PASSWORD)
