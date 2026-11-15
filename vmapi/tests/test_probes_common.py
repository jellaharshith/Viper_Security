"""vmapi.probes._common: arg parsing, session-header loading, JSONL emission — offline only."""
# ruff: noqa: S101 -- pytest assertions

from __future__ import annotations

import json

import pytest
from vmapi.probes._common import (
    build_client,
    emit,
    parse_args_json,
    redact_headers,
    session_headers,
)


def test_parse_args_json_round_trips_a_dict() -> None:
    assert parse_args_json(["--args-json", json.dumps({"target": "t"})]) == {"target": "t"}


def test_parse_args_json_rejects_non_dict_payloads() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        parse_args_json(["--args-json", json.dumps([1, 2])])


def test_session_headers_empty_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VIPER_EXEC_ALSCO_TEST_SESSION_FILE", raising=False)
    assert session_headers() == {}


def test_session_headers_loaded_from_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    f = tmp_path / "session.json"
    f.write_text(json.dumps({"Cookie": "sid=abc"}), encoding="utf-8")
    monkeypatch.setenv("VIPER_EXEC_ALSCO_TEST_SESSION_FILE", str(f))
    assert session_headers() == {"Cookie": "sid=abc"}


def test_session_headers_tolerates_missing_or_bad_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("VIPER_EXEC_ALSCO_TEST_SESSION_FILE", str(tmp_path / "missing.json"))
    assert session_headers() == {}


def test_redact_headers_hides_credentials_but_keeps_other_headers() -> None:
    out = redact_headers({"Cookie": "sid=abc", "Authorization": "Bearer x", "Content-Type": "text/html"})
    assert out == {"Cookie": "<redacted>", "Authorization": "<redacted>", "Content-Type": "text/html"}


def test_emit_writes_one_json_line(capsys: pytest.CaptureFixture[str]) -> None:
    emit({"b": 2, "a": 1})
    out = capsys.readouterr().out
    assert out == '{"a": 1, "b": 2}\n'


def test_build_client_verifies_tls_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VIPER_EXEC_ALSCO_ACCEPT_EXPIRED_CERT", raising=False)
    with build_client() as client:
        assert client._transport._pool._ssl_context.verify_mode.name == "CERT_REQUIRED"


def test_build_client_accepts_expired_cert_only_when_explicitly_opted_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VIPER_EXEC_ALSCO_ACCEPT_EXPIRED_CERT", "1")
    with build_client() as client:
        assert client._transport._pool._ssl_context.verify_mode.name == "CERT_NONE"


def test_build_client_ignores_unexpected_opt_in_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIPER_EXEC_ALSCO_ACCEPT_EXPIRED_CERT", "true")  # only the exact "1" counts
    with build_client() as client:
        assert client._transport._pool._ssl_context.verify_mode.name == "CERT_REQUIRED"
