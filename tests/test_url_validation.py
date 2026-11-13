import pytest

from phishing_app.validation import URLValidationError, normalize_url


def test_normalizes_idn_and_preserves_path_query_and_port():
    assert normalize_url(" HTTPS://Exämple.com:8443/a?b=1 ") == "https://xn--exmple-cua.com:8443/a?b=1"


def test_accepts_and_normalizes_ip_addresses():
    assert normalize_url("http://192.0.2.1/login") == "http://192.0.2.1/login"
    assert normalize_url("http://[2001:0db8::1]:8080/a") == "http://[2001:db8::1]:8080/a"


@pytest.mark.parametrize("value", [
    "file:///C:/Windows/win.ini",
    "javascript:alert(1)",
    "data:text/html,hello",
    "https://user:password@example.com/",
    "https://localhost/",
    "https://example.com:bad/",
    "https://example.com/\\\\evil",
    "https://example.com/" + "a" * 2050,
])
def test_rejects_unsafe_or_malformed_urls(value):
    with pytest.raises(URLValidationError):
        normalize_url(value)


def test_adds_https_when_scheme_is_omitted():
    assert normalize_url("Example.com/path") == "https://example.com/path"


def test_does_not_invent_a_trailing_slash_for_host_only_urls():
    assert normalize_url("https://example.com") == "https://example.com"
