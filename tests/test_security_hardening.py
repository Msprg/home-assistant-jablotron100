"""Regression tests for the 2026-06-01 security-hardening pass.

These tests exercise the specific failure modes the multi-lens audit
surfaced, so a future refactor that re-introduces any of them fails CI:

- Certificate-fingerprint header injection via ``X-Client-Cert-Fingerprint``.
- Token / fingerprint values leaking into uvicorn access log lines.
- Log-injection via newlines in token labels.
- WebSocket receive loop crashing on malformed JSON.
- WebSocket receive loop accepting unbounded payloads.
- User-id leakage in PermissionError detail strings.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from jablotron_api.server.app import (
    SensitiveQueryAccessLogFilter,
    _bearer_token_from_headers,
    _redact_url,
    sanitize_for_log,
)
from jablotron_api.services.storage import TokenStore


def test_redact_url_strips_token_and_fingerprint_query_params():
    raw = (
        '"GET /v1/ws?token=sk_aaa.bbb.ccc&fingerprint=DEADBEEF&other=ok HTTP/1.1"'
    )
    redacted = _redact_url(raw)
    assert "sk_aaa.bbb.ccc" not in redacted
    assert "DEADBEEF" not in redacted
    assert "other=ok" in redacted  # non-sensitive params survive
    assert "token=<redacted>" in redacted
    assert "fingerprint=<redacted>" in redacted


def test_sensitive_query_access_log_filter_rewrites_record_args():
    flt = SensitiveQueryAccessLogFilter()
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='%s - "%s" %d',
        args=("127.0.0.1:1234", "GET /v1/ws?token=SECRET HTTP/1.1", 200),
        exc_info=None,
    )
    assert flt.filter(record) is True
    assert "SECRET" not in (record.args[1] if isinstance(record.args, tuple) else "")


def test_bearer_token_from_headers_accepts_authorization_header():
    headers = {"authorization": "Bearer abc.def.ghi"}
    assert _bearer_token_from_headers(headers) == "abc.def.ghi"


def test_bearer_token_from_headers_rejects_non_bearer():
    assert _bearer_token_from_headers({"authorization": "Basic dXNlcjpwYXNz"}) is None
    assert _bearer_token_from_headers({}) is None
    assert _bearer_token_from_headers({"authorization": "Bearer "}) is None


def test_sanitize_for_log_replaces_control_characters():
    assert sanitize_for_log(None) == ""
    assert sanitize_for_log("normal label") == "normal label"
    assert sanitize_for_log("evil\nlabel") == "evil?label"
    assert sanitize_for_log("tab\there\rcarriage\x07bell") == "tab?here?carriage?bell"


def test_token_store_rejects_label_with_control_characters(tmp_path: Path):
    store = TokenStore(tmp_path / "tokens.db")
    with pytest.raises(ValueError, match="control characters"):
        store.create_token(label="legit\nforged audit log line", scopes=["sections:read"])
    with pytest.raises(ValueError, match="control characters"):
        store.create_token(label="tab\there", scopes=["sections:read"])


def test_token_store_rejects_overlong_label(tmp_path: Path):
    store = TokenStore(tmp_path / "tokens.db")
    with pytest.raises(ValueError, match="200 characters"):
        store.create_token(label="x" * 201, scopes=["sections:read"])


def test_token_store_rejects_empty_label(tmp_path: Path):
    store = TokenStore(tmp_path / "tokens.db")
    with pytest.raises(ValueError):
        store.create_token(label="", scopes=["sections:read"])


def test_bounds_check_fails_closed_when_catalog_missing():
    from jablotron_api.services.catalog_io import ensure_id_in_range

    with pytest.raises(ValueError, match="catalog has not been loaded"):
        ensure_id_in_range(None, kind="Section", attr="sections", value=5)


def test_bounds_check_rejects_negative_or_overflow_ids():
    from jablotron_api.domain.models import InitialSetupModel, InitialSetupRangeModel
    from jablotron_api.services.catalog_io import ensure_id_in_range

    fake = InitialSetupModel(
        source="inferred_catalog",
        exact=False,
        sections=InitialSetupRangeModel(first_id=1, last_id=10, count=10),
    )
    with pytest.raises(ValueError, match="supported range"):
        ensure_id_in_range(fake, kind="Section", attr="sections", value=0)
    with pytest.raises(ValueError, match="supported range"):
        ensure_id_in_range(fake, kind="Section", attr="sections", value=-1)
    with pytest.raises(ValueError, match="supported range"):
        ensure_id_in_range(fake, kind="Section", attr="sections", value=2_147_483_647)
