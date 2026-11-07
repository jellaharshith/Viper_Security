"""Durable single-use claims. A key can be claimed exactly once, across threads and processes."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Protocol


class ClaimStore(Protocol):
    def claim(self, key: str) -> bool:
        """Return True only for the first caller to claim ``key``."""
        ...


class MemoryClaims:
    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    def claim(self, key: str) -> bool:
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            return True


class SqliteClaims:
    """A primary-key insert is the compare-and-set; it is atomic across processes."""

    def __init__(self, path: Path) -> None:
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS claims (key TEXT PRIMARY KEY)")
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=30, isolation_level=None)

    def claim(self, key: str) -> bool:
        conn = self._connect()
        try:
            conn.execute("INSERT INTO claims (key) VALUES (?)", (key,))
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
