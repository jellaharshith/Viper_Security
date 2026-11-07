"""Audit safety gates use real files; only OS failures are injected."""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from viper.agents import audit
from viper.config import Settings


def log_at(tmp_path: Path) -> audit.AuditLog:
    return audit.AuditLog(Settings(_env_file=None, audit_dir=tmp_path), "project")


def append(log: audit.AuditLog, **kwargs: object) -> dict[str, object]:
    return log.append(thread_id="thread", event="plan_proposed", actor="agent", **kwargs)


def test_genesis_and_restart_chain(tmp_path: Path) -> None:
    log = log_at(tmp_path)
    first = append(log)
    second = append(log_at(tmp_path))
    assert log.path == tmp_path / "project.jsonl"
    assert first["seq"] == 0
    assert first["prev_hash"] == "0" * 64
    assert second["seq"] == 1
    assert second["prev_hash"] == first["hash"]
    payload = {k: v for k, v in first.items() if k != "hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    assert first["hash"] == hashlib.sha256((canonical + "0" * 64).encode()).hexdigest()
    assert audit.verify(log.path) is None


def test_nested_secrets_and_exception_text_are_scrubbed(tmp_path: Path) -> None:
    log = log_at(tmp_path)
    append(log, detail={
        "args": {"nested": [{"api_key": "sentinel-key", "Cookie": "sentinel-cookie",
                              "Authorization": "Bearer sentinel-auth", "password": "sentinel-pass"}],
                 "message": "failed Authorization: Bearer sentinel-inline password=sentinel-inline2"},
        "error": RuntimeError("token=sentinel-error"),
        "summary": "-----BEGIN PRIVATE KEY-----\nsentinel-pem\n-----END PRIVATE KEY-----",
        "raw_resume_payload": "sentinel-resume",
        "raw_scope": "sentinel-scope",
    })
    text = log.path.read_text()
    assert "sentinel-" not in text
    assert "[REDACTED]" in text
    assert "raw_resume_payload" not in text
    assert "raw_scope" not in text
    assert audit.verify(log.path) is None


@pytest.mark.parametrize("mutation,expected", [
    ("payload", 1), ("prev_hash", 1), ("delete", 1), ("partial", 2), ("newline", 2),
])
def test_tamper_blocks_verification_and_append(tmp_path: Path, mutation: str, expected: int) -> None:
    log = log_at(tmp_path)
    for _ in range(3):
        append(log)
    lines = log.path.read_bytes().splitlines(keepends=True)
    if mutation in {"payload", "prev_hash"}:
        record = json.loads(lines[1])
        record["detail" if mutation == "payload" else "prev_hash"] = "modified"
        lines[1] = (json.dumps(record) + "\n").encode()
    elif mutation == "delete":
        del lines[1]
    elif mutation == "partial":
        lines[-1] = b'{"seq":2'
    else:
        lines[-1] = lines[-1].rstrip(b"\n")
    log.path.write_bytes(b"".join(lines))
    before = log.path.read_bytes()
    assert audit.verify(log.path) == expected
    with pytest.raises(audit.AuditError):
        append(log)
    assert log.path.read_bytes() == before


def test_unwritable_directory_fails_closed(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    with pytest.raises(audit.AuditError):
        append(log_at(blocker))


def test_lock_contention_fails_closed(tmp_path: Path) -> None:
    log = log_at(tmp_path)
    with audit._locked(log.path):
        with pytest.raises(audit.AuditError):
            append(log)
    assert not log.path.exists()


@pytest.mark.parametrize("project", ["../escape", "..", "a/b", "a\\b", "C:escape", ""])
def test_project_cannot_escape_audit_directory(tmp_path: Path, project: str) -> None:
    with pytest.raises(audit.AuditError):
        audit.AuditLog(Settings(_env_file=None, audit_dir=tmp_path), project)


def test_event_allowlist_rejects_unknown_fields_and_values(tmp_path: Path) -> None:
    log = log_at(tmp_path)
    for kwargs in [{"raw_payload": "secret"}, {"decision": "INVALID"}]:
        with pytest.raises(audit.AuditError):
            append(log, **kwargs)
    with pytest.raises(audit.AuditError):
        log.append(thread_id="thread", event="arbitrary", actor="agent")
    with pytest.raises(audit.AuditError):
        log.append(thread_id="thread", event="run_failed", actor="arbitrary")
    assert not log.path.exists()


def test_concurrent_writers_never_fork_chain(tmp_path: Path) -> None:
    def write(_: int) -> bool:
        try:
            append(log_at(tmp_path))
            return True
        except audit.AuditError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        successes = sum(pool.map(write, range(12)))
    assert successes > 0
    log = log_at(tmp_path)
    assert len(log.path.read_text().splitlines()) == successes
    assert audit.verify(log.path) is None


def test_missing_log_is_not_silently_valid(tmp_path: Path) -> None:
    with pytest.raises(audit.AuditError):
        audit.verify(tmp_path / "missing.jsonl")


def test_disk_sync_failure_aborts_without_exposing_error_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_sync(_: int) -> None:
        raise OSError("token=sentinel-os-error")

    monkeypatch.setattr(audit.os, "fsync", fail_sync)
    with pytest.raises(audit.AuditError) as caught:
        append(log_at(tmp_path))
    assert "sentinel" not in str(caught.value)


def test_non_json_details_fail_before_writing(tmp_path: Path) -> None:
    log = log_at(tmp_path)
    with pytest.raises(audit.AuditError):
        append(log, detail={"count": float("nan")})
    assert not log.path.exists()


def test_arbitrary_objects_are_not_formatted(tmp_path: Path) -> None:
    class Unsafe:
        def __str__(self) -> str:
            raise AssertionError("Audit must not invoke arbitrary formatting")

    log = log_at(tmp_path)
    append(log, detail={"summary": Unsafe()})
    assert json.loads(log.path.read_text())["detail"]["summary"] == "[REDACTED]"
