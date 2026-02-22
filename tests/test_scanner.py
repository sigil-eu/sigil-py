"""Tests for sigil-protocol core scanner."""

import json
import pytest
from unittest.mock import patch, MagicMock

from sigil_protocol.scanner import RemoteScanner, ScanResult, Severity, scan


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def offline_scanner(monkeypatch):
    """Scanner forced to use built-in patterns (no HTTP)."""
    monkeypatch.setenv("SIGIL_OFFLINE", "true")
    s = RemoteScanner()
    s._needs_refresh = lambda: True  # force reload
    return s


# ── Core scanner ──────────────────────────────────────────────────────────────

def test_clean_payload(offline_scanner):
    result = offline_scanner.scan('{"query": "SELECT name FROM users WHERE id=1"}')
    assert not result.hit
    assert not result.blocked
    assert result.severity is None


def test_aws_key_detected(offline_scanner):
    result = offline_scanner.scan("AKIAIOSFODNN7EXAMPLE")
    assert result.hit
    assert result.pattern == "aws_access_key_id"
    assert result.severity == Severity.Critical
    assert result.blocked


def test_openai_key_detected(offline_scanner):
    result = offline_scanner.scan("Authorization: Bearer sk-abc123def456ghi789jkl012mno345pqr678")
    assert result.hit
    assert result.severity == Severity.Critical


def test_sql_drop_detected(offline_scanner):
    result = offline_scanner.scan("DROP TABLE users")
    assert result.hit
    assert result.blocked


def test_sql_delete_no_where(offline_scanner):
    result = offline_scanner.scan("DELETE FROM accounts")
    assert result.hit


def test_json_input(offline_scanner):
    payload = {"db": "prod", "query": "DROP TABLE payments"}
    result = offline_scanner.scan(json.dumps(payload))
    assert result.hit


def test_dict_input_coerced(offline_scanner):
    """scan() should accept dict and coerce to JSON string."""
    result = offline_scanner.scan(json.dumps({"key": "AKIAIOSFODNN7EXAMPLE"}))
    assert result.hit


def test_multiple_hits_highest_severity_returned(offline_scanner):
    """When multiple patterns hit, the most severe should be primary."""
    payload = json.dumps({
        "key": "AKIAIOSFODNN7EXAMPLE",
        "q": "DROP TABLE payments",
    })
    result = offline_scanner.scan(payload)
    assert result.severity == Severity.Critical
    assert len(result.all_hits) >= 2


def test_scan_result_bool_false():
    r = ScanResult(hit=False)
    assert not r
    assert not r.blocked
    assert not r.warned


def test_scan_result_bool_true():
    r = ScanResult(hit=True, severity=Severity.Critical, pattern="aws_access_key_id")
    assert r
    assert r.blocked
    assert not r.warned


def test_scan_result_high_severity():
    r = ScanResult(hit=True, severity=Severity.High, pattern="generic_secret")
    assert r.warned
    assert not r.blocked


# ── Module-level convenience function ─────────────────────────────────────────

def test_module_scan_clean(monkeypatch):
    monkeypatch.setenv("SIGIL_OFFLINE", "true")
    from sigil_protocol.scanner import RemoteScanner, scan as module_scan
    s = RemoteScanner()
    result = s.scan("hello world — nothing sensitive here at all")
    assert not result.hit
    assert result.severity is None


# ── Severity ordering ─────────────────────────────────────────────────────────

def test_severity_ordering():
    assert Severity.Critical >= Severity.High
    assert Severity.High >= Severity.Warn
    assert not (Severity.Warn >= Severity.Critical)
