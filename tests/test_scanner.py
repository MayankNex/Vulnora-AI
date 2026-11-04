import pytest
from vulnora.scanner import ScanError, _normalize_url


def test_adds_https_by_default(monkeypatch):
    monkeypatch.setattr("vulnora.scanner._validate_public_host", lambda host: None)
    assert _normalize_url("example.com") == "https://example.com"


def test_rejects_unsupported_scheme():
    with pytest.raises(ScanError):
        _normalize_url("file:///etc/passwd")


def test_rejects_embedded_credentials(monkeypatch):
    monkeypatch.setattr("vulnora.scanner._validate_public_host", lambda host: None)
    with pytest.raises(ScanError):
        _normalize_url("https://user:pass@example.com")


def test_rejects_localhost():
    with pytest.raises(ScanError):
        _normalize_url("http://localhost")
