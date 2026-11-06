"""Exact pgvector search and transactional KB pointers; apply 0001_kb.sql first."""

from __future__ import annotations

import json
import math
import re
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb
from pydantic import SecretStr

from viper.rag.types import Document, Hit


def _collection(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", name):
        raise ValueError("invalid collection name")
    return name


def _vector(vector: list[float]) -> str:
    if len(vector) != 768 or not all(math.isfinite(x) for x in vector):
        raise ValueError("expected 768 finite vector components")
    return json.dumps(vector)


def _connect(database_url: str | SecretStr) -> psycopg.Connection[Any]:
    url = database_url.get_secret_value() if isinstance(database_url, SecretStr) else database_url
    if not url:
        raise ValueError("VIPER_DATABASE_URL is required for pgvector")
    try:
        return psycopg.connect(url, autocommit=True)
    except psycopg.Error:
        # Connection diagnostics can contain credentials. Do not propagate them to health/logs.
        raise RuntimeError("could not connect to pgvector database") from None


def _doc(row: tuple[Any, ...]) -> Document:
    return Document(id=row[0], text=row[1], source=row[2], url=row[3], title=row[4], meta=row[5])


class PgVectorStore:
    def __init__(
        self, database_url: str | SecretStr, collection: str,
        *, connection: psycopg.Connection[Any] | None = None,
    ) -> None:
        self.collection = _collection(collection)
        self._conn = connection if connection is not None else _connect(database_url)
        self._owner = connection is None

    def view(self, collection: str) -> PgVectorStore:
        """Share the connection; only the original store owns its lifetime."""
        return PgVectorStore("", collection, connection=self._conn)

    def exists(self) -> bool:
        with self._conn.cursor() as cur:
            cur.execute("SELECT EXISTS (SELECT 1 FROM kb_docs WHERE collection = %s)",
                        (self.collection,))
            row = cur.fetchone()
        return bool(row and row[0])

    def count(self) -> int:
        with self._conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM kb_docs WHERE collection = %s", (self.collection,))
            row = cur.fetchone()
        return int(row[0]) if row else 0

    def drop(self) -> None:
        with self._conn.transaction(), self._conn.cursor() as cur:
            cur.execute("DELETE FROM kb_docs WHERE collection = %s", (self.collection,))

    def upsert(self, docs: list[Document], vectors: list[list[float]]) -> None:
        if len(docs) != len(vectors):
            raise ValueError("docs and vectors length mismatch")
        rows = [(self.collection, d.id, d.text, d.source, d.url, d.title, Jsonb(d.meta), _vector(v))
                for d, v in zip(docs, vectors, strict=True)]
        if not rows:
            return
        with self._conn.transaction(), self._conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO kb_docs (collection, id, text, source, url, title, meta, embedding) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s::vector) "
                "ON CONFLICT (collection, id) DO UPDATE SET text = EXCLUDED.text, "
                "source = EXCLUDED.source, url = EXCLUDED.url, title = EXCLUDED.title, "
                "meta = EXCLUDED.meta, embedding = EXCLUDED.embedding", rows,
            )

    def get_many(self, doc_ids: list[str]) -> list[Document]:
        if not doc_ids:
            return []
        with self._conn.cursor() as cur:
            cur.execute("SELECT id, text, source, url, title, meta FROM kb_docs "
                        "WHERE collection = %s AND id = ANY(%s)", (self.collection, doc_ids))
            return [_doc(row) for row in cur.fetchall()]

    def export(self) -> list[tuple[Document, list[float]]]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT id, text, source, url, title, meta, embedding::text FROM kb_docs "
                        "WHERE collection = %s ORDER BY id", (self.collection,))
            return [(_doc(row), [float(x) for x in json.loads(row[6])]) for row in cur.fetchall()]

    def search(self, vector: list[float], k: int) -> list[Hit]:
        encoded = _vector(vector)
        if k < 1:
            raise ValueError("k must be positive")
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT id, text, source, url, title, meta, "
                "1 - (embedding <=> %s::vector) AS score FROM kb_docs "
                "WHERE collection = %s ORDER BY embedding <=> %s::vector, id LIMIT %s",
                (encoded, self.collection, encoded, k),
            )
            return [Hit(document=_doc(row), score=float(row[6])) for row in cur.fetchall()]

    def close(self) -> None:
        if self._owner:
            self._conn.close()


class PgKBRegistry:
    """KBRegistry counterpart. Refresh under a row lock before every pointer change.

    Injected connections must use autocommit, as connections created here do. A store's
    connection can be shared; the caller then owns its lifetime.
    """

    def __init__(
        self, database_url: str | SecretStr, *, connection: psycopg.Connection[Any] | None = None,
    ) -> None:
        self._conn = connection if connection is not None else _connect(database_url)
        self._owner = connection is None
        self.active: str | None = None
        self.previous: str | None = None
        self.history: list[dict[str, str]] = []
        self.refresh()

    def refresh(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT active, previous, history FROM kb_registry WHERE singleton = true")
            row = cur.fetchone()
        if row is None:
            raise RuntimeError("missing kb_registry singleton; apply 0001_kb.sql")
        self.active, self.previous, self.history = row

    def _change(self, event: str, collection: str | None = None) -> str:
        if collection is not None:
            _collection(collection)
        with self._conn.transaction(), self._conn.cursor() as cur:
            cur.execute("SELECT active, previous, history FROM kb_registry "
                        "WHERE singleton = true FOR UPDATE")
            row = cur.fetchone()
            if row is None:
                raise RuntimeError("missing kb_registry singleton; apply 0001_kb.sql")
            active, previous, old_history = row
            if event == "bootstrap":
                if active is not None:
                    self.active, self.previous, self.history = row
                    return str(active)
                active = collection
            elif event == "promote":
                if collection == active:
                    raise ValueError("collection is already active")
                previous, active = active, collection
            else:
                if not previous:
                    raise ValueError("no previous collection to roll back to")
                active, previous = previous, active
            history = [*old_history, {"at": datetime.now(UTC).isoformat(timespec="seconds"),
                                      "event": event, "collection": active or ""}]
            cur.execute("UPDATE kb_registry SET active = %s, previous = %s, history = %s "
                        "WHERE singleton = true", (active, previous, Jsonb(history)))
        # Publish the local snapshot only after the transaction commits successfully.
        self.active, self.previous, self.history = active, previous, history
        return str(active or "")

    def bootstrap(self, collection: str) -> None:
        self._change("bootstrap", collection)

    def promote(self, collection: str) -> None:
        self._change("promote", collection)

    def rollback(self) -> str:
        return self._change("rollback")

    def close(self) -> None:
        if self._owner:
            self._conn.close()
