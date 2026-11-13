import requests

import blacklist_checker
from phishing_app.services import domain_intelligence, threat_intelligence


def test_local_blacklist_reports_confirmed_match(tmp_path, monkeypatch):
    blacklist_path = tmp_path / "blacklist.txt"
    blacklist_path.write_text("example.com\n", encoding="utf-8")
    monkeypatch.setattr(blacklist_checker, "BLACKLIST_PATH", str(blacklist_path))

    result = blacklist_checker.check_blacklist("https://login.example.com/account")

    assert result["is_blacklisted"] is True
    assert result["status"] == "confirmed_match"
    assert result["source"] == "local_blacklist"


def test_missing_local_blacklist_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(blacklist_checker, "BLACKLIST_PATH", str(tmp_path / "missing.txt"))

    result = blacklist_checker.check_blacklist("https://example.com")

    assert result["is_blacklisted"] is False
    assert result["status"] == "unavailable"


def test_rdap_network_failure_degrades_without_failing_scan(monkeypatch):
    domain_intelligence._cache.clear()
    requested_urls = []

    def fail_request(url, *args, **kwargs):
        requested_urls.append(url)
        raise requests.Timeout("simulated timeout")

    monkeypatch.setattr(domain_intelligence.requests, "get", fail_request)
    result = domain_intelligence.get_domain_intelligence("https://example-test-rdap-failure.com", enabled=True)

    assert result["domain"] == "example-test-rdap-failure.com"
    assert result["lookup_status"] == "unavailable"
    assert result["domain_age_days"] is None
    assert requested_urls
    assert set(requested_urls) == {"https://rdap.org/domain/example-test-rdap-failure.com"}


def test_openphish_feed_rejects_unapproved_hosts(monkeypatch):
    def unexpected_request(*args, **kwargs):
        raise AssertionError("An unapproved feed host must not be contacted")

    monkeypatch.setattr(threat_intelligence.requests, "get", unexpected_request)
    result = threat_intelligence._check_openphish("https://example.com", "https://attacker.invalid/feed.txt")

    assert result["status"] == "unavailable"
    assert result["matched"] is False


def test_openphish_feed_records_fetch_time_and_closes_response(monkeypatch):
    calls = []

    class Response:
        closed = False

        def raise_for_status(self):
            return None

        def iter_lines(self, **kwargs):
            return iter([b"https://suspected.example/path"])

        def close(self):
            self.closed = True

    response = Response()

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return response

    monkeypatch.setattr(threat_intelligence, "_openphish_cache", None)
    monkeypatch.setattr(threat_intelligence.requests, "get", fake_get)
    result = threat_intelligence._check_openphish(
        "https://suspected.example/path", "https://openphish.com/feed.txt",
    )

    assert result["status"] == "confirmed_match"
    assert result["checked_at"]
    assert result["feed_updated_at"]
    assert calls[0][0] == "https://openphish.com/feed.txt"
    assert calls[0][1]["allow_redirects"] is False
    assert response.closed is True


def test_phishtank_uses_fixed_provider_endpoint_and_disables_redirects(monkeypatch):
    calls = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"results": {"in_database": True, "valid": True}}

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr(threat_intelligence.requests, "post", fake_post)
    result = threat_intelligence._check_phishtank("https://suspected.example/path", "test-key")

    assert result["status"] == "confirmed_match"
    assert calls[0][0] == "https://checkurl.phishtank.com/checkurl/"
    assert calls[0][1]["allow_redirects"] is False
    assert calls[0][1]["data"]["url"] == "https://suspected.example/path"
