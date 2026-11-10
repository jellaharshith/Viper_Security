"""Fail-closed, sanitized JSONL audit evidence.

Locks are nonblocking: a busy writer raises AuditError, never skips evidence.
The persistent .lock sidecar must not be removed while writers are running.
The chain detects internal edits, not a rewritten chain or a removed valid suffix.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from viper.config import Settings

_ZERO = "0" * 64
_REDACTED = "[REDACTED]"
_EVENTS = frozenset({
    "plan_proposed", "policy_decision", "approval_requested", "approval_granted",
    "approval_denied", "approval_expired", "approval_consumed", "tool_dry_run",
    "run_completed", "run_failed",
    # M7: real dispatch (vs. simulated), finding analysis, report output, external anchoring.
    "tool_dispatch", "tool_result", "findings_generated", "report_generated", "audit_anchored",
    "scope_approved",  # v1: a human approved a model-drafted engagement scope
})
_DETAIL_KEYS = frozenset({
    "action_id", "tool", "tool_name", "args", "summary", "reason", "error", "status",
    "count", "scope_revision", "pending_approval_id", "approver", "results", "message",
    "digest", "simulated", "truncated",
})
_FIELDS = frozenset({
    "seq", "ts", "thread_id", "event", "actor", "action_hash", "decision", "detail",
    "prev_hash", "hash",
})
_SENSITIVE = re.compile(
    r"password|passwd|secret|token|cookie|authorization|apikey|privatekey|credential",
    re.IGNORECASE,
)
_PEM = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.DOTALL)
_ASSIGNMENT = re.compile(
    r"\b(?:authorization|proxy-authorization|set-cookie|cookie)\s*[:=]\s*[^\r\n]+"
    r"|\b(?:[\w-]*(?:token|secret|password|passwd|api[_-]?key|credential)[\w-]*)"
    r"[\"']?\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    r"|\b(?:Bearer|Basic)\s+[^\s,;]+"
    r"|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    r"|\b(?:sk-[A-Za-z0-9_-]+|AKIA[A-Z0-9]{16})",
    re.IGNORECASE,
)


class AuditError(RuntimeError):
    """Audit evidence could not be safely committed; callers must abort dispatch."""


def _text(value: str) -> str:
    return _ASSIGNMENT.sub(_REDACTED, _PEM.sub(_REDACTED, value))


def _sanitize(value: Any) -> Any:
    if isinstance(value, BaseException):
        return _REDACTED  # traces and arbitrary exception text are never audit data
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, dict):
        return {
            _text(str(key)): _REDACTED if _SENSITIVE.search(
                re.sub(r"[^a-zA-Z0-9]", "", str(key))
            ) else _sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [_sanitize(item) for item in value]
    if value is None or type(value) in (int, float, bool):
        return value
    return _REDACTED  # no arbitrary repr()/serialization hooks


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(record: dict[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key != "hash"}
    return hashlib.sha256((_canonical(payload) + record["prev_hash"]).encode()).hexdigest()


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Cross-process exclusive lock covering verification, append, flush and fsync."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.with_suffix(path.suffix + ".lock").open("a+b") as handle:
            if sys.platform == "win32":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                yield
            finally:
                if sys.platform == "win32":
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        raise AuditError("Audit file or lock unavailable") from None


def _scan(path: Path) -> tuple[int | None, dict[str, Any] | None]:
    previous: dict[str, Any] | None = None
    with path.open("rb") as handle:
        for expected, line in enumerate(handle):
            try:
                if not line.endswith(b"\n"):
                    return expected, previous
                record = json.loads(line)
                if not isinstance(record, dict) or set(record) != _FIELDS:
                    return expected, previous
                if type(record["seq"]) is not int or record["seq"] != expected:
                    return expected, previous
                prev_hash = _ZERO if previous is None else previous["hash"]
                if record["prev_hash"] != prev_hash or record["hash"] != _hash(record):
                    return expected, previous
                previous = record
            except (ValueError, TypeError, KeyError, UnicodeError):
                return expected, previous
    return None, previous


def verify(path: Path | str) -> int | None:
    """Return the first broken sequence, or None for an internally valid chain.

    Missing/unreadable files and lock failures raise AuditError. A valid empty
    file has no broken sequence. No automatic repair or truncation is performed.
    """
    path = Path(path)
    with _locked(path):
        broken, _ = _scan(path)
        return broken


class AuditLog:
    """One project log stored at Settings.audit_dir/<project_id>.jsonl."""

    def __init__(self, settings: Settings, project_id: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", project_id):
            raise AuditError("Invalid audit project identifier")
        self.path = settings.audit_dir / f"{project_id}.jsonl"

    def append(
        self, *, thread_id: str, event: str, actor: str,
        action_hash: str | None = None, decision: str | None = None,
        detail: dict[str, Any] | None = None, **extra: Any,
    ) -> dict[str, Any]:
        """Sanitize, verify and durably append; return the committed safe record."""
        if extra or event not in _EVENTS or actor not in {"agent", "policy", "human"}:
            raise AuditError("Invalid audit event schema")
        if decision not in {None, "ALLOW", "DENY", "REQUIRE_APPROVAL"}:
            raise AuditError("Invalid audit decision")
        if not isinstance(thread_id, str) or not thread_id:
            raise AuditError("Missing audit thread identifier")
        if action_hash is not None and not re.fullmatch(r"[a-f0-9]{64}", action_hash):
            raise AuditError("Invalid action hash")
        if detail is not None and not isinstance(detail, dict):
            raise AuditError("Invalid audit detail")
        try:
            safe_detail = _sanitize({k: v for k, v in (detail or {}).items() if k in _DETAIL_KEYS})
            with _locked(self.path):
                previous = None
                if self.path.exists():
                    broken, previous = _scan(self.path)
                    if broken is not None:
                        raise AuditError(f"Broken audit chain at sequence {broken}")
                record = {
                    "seq": 0 if previous is None else previous["seq"] + 1,
                    "ts": datetime.now(UTC).isoformat(), "thread_id": _text(thread_id),
                    "event": event, "actor": actor, "action_hash": action_hash,
                    "decision": decision, "detail": safe_detail,
                    "prev_hash": _ZERO if previous is None else previous["hash"],
                }
                record["hash"] = _hash(record)
                line = (_canonical(record) + "\n").encode()
                with self.path.open("ab") as handle:
                    if handle.write(line) != len(line):
                        raise AuditError("Incomplete audit write")
                    handle.flush()
                    os.fsync(handle.fileno())
                return record
        except (OSError, ValueError, TypeError, RecursionError):
            raise AuditError("Audit event could not be committed") from None

    def _records(self) -> list[dict[str, Any]]:
        """All committed records. Refuses to read a broken chain; a missing file is empty."""
        if not self.path.exists():
            return []
        try:
            with _locked(self.path):
                broken, _ = _scan(self.path)
                if broken is not None:
                    raise AuditError(f"Broken audit chain at sequence {broken}")
                return [json.loads(line) for line in self.path.read_bytes().splitlines()]
        except (OSError, ValueError):
            raise AuditError("Audit log could not be read") from None

    def events(self, thread_id: str) -> list[dict[str, Any]]:
        """Committed events for one thread, in order. A report cites these hashes, so it is
        never built from a tampered log."""
        return [r for r in self._records() if r.get("thread_id") == thread_id]

    def index(self) -> dict[str, int]:
        """Record hash -> sequence number, for judging how much of the chain an anchor covers."""
        return {str(r["hash"]): int(r["seq"]) for r in self._records()}

    def hashes(self) -> set[str]:
        return set(self.index())

    def head(self) -> str | None:
        """Hash of the newest record (what an external anchor timestamps), or None if empty."""
        records = self._records()
        return str(records[-1]["hash"]) if records else None
