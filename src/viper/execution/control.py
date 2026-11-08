"""Exclusive-control lock: the AI and a human never drive the VM at once.

Security design principle 6 ("exclusive control"): a single holder per project. A human can
always *take over* (preempt) the agent; the agent refuses to dispatch while a human holds the lock.
Built on SQLite so the claim is atomic across the orchestrator's processes, like ``SqliteClaims``.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

AGENT = "agent"  # the holder string the agent uses when it drives the VM


class ControlLock:
    def __init__(self, path: Path, project_id: str) -> None:
        self._path = path
        self._project = project_id
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS control (project TEXT PRIMARY KEY, holder TEXT NOT NULL)"
            )
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=30, isolation_level=None)

    def holder(self) -> str | None:
        """The current holder of this project's lock, or ``None`` if it is free."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT holder FROM control WHERE project = ?", (self._project,)
            ).fetchone()
            return str(row[0]) if row else None
        finally:
            conn.close()

    def acquire(self, holder: str) -> bool:
        """Grant the lock to ``holder`` if free or already theirs; refuse if someone else holds it.

        The ``INSERT`` is itself the atomic compare-and-set (the ``project`` primary key makes a
        second inserter fail), so this is race-free across processes without an explicit lock. A
        conflict means a row already exists: we re-read it and grant only if it is this same
        ``holder`` (reentrant — an agent re-asking never deadlocks itself), else refuse. Fail closed.
        """
        conn = self._connect()
        try:
            try:
                conn.execute(
                    "INSERT INTO control (project, holder) VALUES (?, ?)", (self._project, holder)
                )
                return True  # the lock was free; we now hold it
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT holder FROM control WHERE project = ?", (self._project,)
                ).fetchone()
                return row is not None and str(row[0]) == holder
        finally:
            conn.close()

    def takeover(self, holder: str) -> None:
        """A human preempts the agent: force ``holder`` to own the lock regardless of who held it."""
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO control (project, holder) VALUES (?, ?) "
                "ON CONFLICT(project) DO UPDATE SET holder = excluded.holder",
                (self._project, holder),
            )
        finally:
            conn.close()

    def release(self, holder: str) -> bool:
        """Release the lock only if ``holder`` currently owns it; return whether anything was freed."""
        conn = self._connect()
        try:
            cur = conn.execute(
                "DELETE FROM control WHERE project = ? AND holder = ?", (self._project, holder)
            )
            return cur.rowcount > 0
        finally:
            conn.close()
