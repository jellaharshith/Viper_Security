"""SQL contract tests with recording fakes; no database or network."""

import json
from contextlib import contextmanager
from pathlib import Path

import psycopg
import pytest
from pydantic import SecretStr

from viper.rag.pgstore import PgKBRegistry, PgVectorStore
from viper.rag.types import Document

VECTOR = [1.0] + [0.0] * 767
DOC = Document("attack:T1059.001", "text '); DROP TABLE kb_docs; --", "mitre-attack",
               "https://example.test/technique", "PowerShell", {"tactic": "execution"})
ROW = (DOC.id, DOC.text, DOC.source, DOC.url, DOC.title, DOC.meta)


class FakeConnection:
    def __init__(self):
        self.calls = []
        self.rows = []
        self.state = (None, None, [])
        self.events = []
        self.closed = False
        self.fail_update = False

    @contextmanager
    def transaction(self):
        self.events.append("begin")
        before = self.state
        try:
            yield
        except Exception:
            self.state = before
            self.events.append("rollback")
            raise
        else:
            self.events.append("commit")

    @contextmanager
    def cursor(self):
        yield self

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        self.events.append(sql)
        if sql.startswith("UPDATE kb_registry"):
            if self.fail_update:
                raise RuntimeError("simulated write failure")
            self.state = (params[0], params[1], params[2].obj)

    def executemany(self, sql, rows):
        for row in rows:
            self.execute(sql, row)

    def fetchone(self):
        if "FROM kb_registry" in self.calls[-1][0]:
            return self.state
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows

    def close(self):
        self.closed = True


def test_upsert_is_parameterised_and_atomic():
    conn = FakeConnection()
    store = PgVectorStore("", "kb_v2", connection=conn)
    store.upsert([DOC], [VECTOR])
    sql, params = conn.calls[0]
    assert "ON CONFLICT (collection, id) DO UPDATE" in sql
    assert DOC.text not in sql and DOC.id not in sql and "kb_v2" not in sql
    assert params[:6] == ("kb_v2", *ROW[:5])
    assert params[6].obj == DOC.meta and json.loads(params[7]) == VECTOR
    assert conn.events[0] == "begin" and conn.events[-1] == "commit"


@pytest.mark.parametrize("name", ["", "x'; DROP TABLE kb_docs;--", "has space", "a.b", "x" * 129])
def test_invalid_collections_never_connect(name, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("validation must precede connection")
    monkeypatch.setattr(psycopg, "connect", forbidden)
    with pytest.raises(ValueError, match="collection"):
        PgVectorStore("", name)
    store = PgVectorStore("", "live", connection=FakeConnection())
    with pytest.raises(ValueError, match="collection"):
        store.view(name)


def test_search_uses_cosine_similarity_and_bound_limit():
    conn = FakeConnection()
    conn.rows = [(*ROW, 0.9)]
    store = PgVectorStore("", "live", connection=conn)
    hits = store.search(VECTOR, 4)
    assert hits[0].document == DOC and hits[0].score == 0.9
    sql, params = conn.calls[-1]
    assert "1 - (embedding <=> %s::vector)" in sql
    assert "ORDER BY embedding <=> %s::vector, id LIMIT %s" in sql
    assert params == (json.dumps(VECTOR), "live", json.dumps(VECTOR), 4)


def test_lookup_export_count_exists_and_drop_are_scoped():
    conn = FakeConnection()
    store = PgVectorStore("", "live", connection=conn)
    conn.rows = [ROW]
    assert store.get_many([DOC.id]) == [DOC]
    assert conn.calls[-1][1] == ("live", [DOC.id])
    assert DOC.id not in conn.calls[-1][0]
    assert store.get_many([]) == []
    conn.rows = [(*ROW, json.dumps(VECTOR))]
    assert store.export() == [(DOC, VECTOR)]
    conn.rows = [(3,)]
    assert store.count() == 3
    conn.rows = [(True,)]
    assert store.exists()
    store.drop()
    assert conn.calls[-1] == ("DELETE FROM kb_docs WHERE collection = %s", ("live",))
    assert all("live" not in sql for sql, _ in conn.calls)
    conn.rows = []
    assert store.export() == [] and store.get_many(["missing"]) == []
    assert store.count() == 0 and not store.exists()


@pytest.mark.parametrize("vector", [[1.0], [float("nan")] * 768, [float("inf")] * 768])
def test_invalid_vectors_never_write(vector):
    conn = FakeConnection()
    store = PgVectorStore("", "live", connection=conn)
    with pytest.raises(ValueError):
        store.upsert([DOC], [vector])
    with pytest.raises(ValueError):
        store.search(vector, 4)
    assert conn.calls == []


def test_empty_upsert_mismatch_and_invalid_limit():
    conn = FakeConnection()
    store = PgVectorStore("", "live", connection=conn)
    store.upsert([], [])
    with pytest.raises(ValueError, match="mismatch"):
        store.upsert([DOC], [])
    with pytest.raises(ValueError, match="positive"):
        store.search(VECTOR, 0)
    assert conn.calls == []


def test_views_and_connection_ownership(monkeypatch):
    conn = FakeConnection()
    seen = []

    def connect(url, **kwargs):
        seen.append((url, kwargs))
        return conn

    monkeypatch.setattr(psycopg, "connect", connect)
    store = PgVectorStore(SecretStr("fixture-dsn"), "live")
    view = store.view("stage")
    assert seen == [("fixture-dsn", {"autocommit": True})]
    view.count()
    assert conn.calls[-1][1] == ("stage",)
    view.close()
    assert not conn.closed
    assert "fixture-dsn" not in repr(store)
    store.close()
    assert conn.closed


def test_connection_errors_mask_dsn(monkeypatch):
    def fail(*args, **kwargs):
        raise psycopg.OperationalError("secret fixture-dsn")
    monkeypatch.setattr(psycopg, "connect", fail)
    with pytest.raises(RuntimeError) as exc:
        PgVectorStore("fixture-dsn", "live")
    assert "fixture-dsn" not in str(exc.value)
    assert exc.value.__suppress_context__
    with pytest.raises(ValueError, match="required"):
        PgVectorStore("", "live")


def test_registry_promote_rollback_lock_and_update_in_one_transaction():
    conn = FakeConnection()
    registry = PgKBRegistry("", connection=conn)
    registry.bootstrap("a")
    registry.promote("b")
    assert (registry.active, registry.previous) == ("b", "a")
    assert registry.rollback() == "a"
    assert conn.state[:2] == ("a", "b")
    assert [h["event"] for h in registry.history] == ["bootstrap", "promote", "rollback"]
    assert PgKBRegistry("", connection=conn).active == "a"
    updates = [params for sql, params in conn.calls if sql.startswith("UPDATE")]
    assert [p[:2] for p in updates] == [("a", None), ("b", "a"), ("a", "b")]
    events = conn.events[1:]  # initial refresh is outside transaction
    for offset in range(0, 12, 4):
        assert events[offset] == "begin"
        assert events[offset + 1].endswith("FOR UPDATE")
        assert events[offset + 2].startswith("UPDATE kb_registry")
        assert events[offset + 3] == "commit"
    assert all("%s" in sql for sql, params in conn.calls if params)


def test_registry_close_ownership_and_missing_singleton(monkeypatch):
    conn = FakeConnection()
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: conn)
    owner = PgKBRegistry("fixture-dsn")
    PgKBRegistry("", connection=conn).close()
    assert not conn.closed
    owner.close()
    assert conn.closed
    conn.state = None
    with pytest.raises(RuntimeError, match="singleton"):
        PgKBRegistry("", connection=conn)


def test_registry_refreshes_under_lock_and_failed_update_rolls_back():
    conn = FakeConnection()
    registry = PgKBRegistry("", connection=conn)
    registry.bootstrap("a")
    registry.bootstrap("ignored")
    assert registry.active == "a"
    conn.state = ("concurrent", "older", [])
    registry.promote("next")
    assert registry.previous == "concurrent"
    conn.fail_update = True
    with pytest.raises(RuntimeError, match="simulated"):
        registry.rollback()
    assert conn.events[-1] == "rollback"
    assert registry.active == "next" and conn.state[0] == "next"
    with pytest.raises(ValueError, match="already active"):
        registry.promote("next")
    with pytest.raises(ValueError, match="collection"):
        registry.promote("invalid;")
    conn.state = (None, None, [])
    with pytest.raises(ValueError, match="no previous"):
        registry.rollback()


def test_migration_security_and_dimension_contract():
    sql = (Path(__file__).parents[1] / "db/migrations/0001_kb.sql").read_text().lower()
    statements = "\n".join(line for line in sql.splitlines() if not line.startswith("--"))
    assert "create extension if not exists vector" in statements
    assert "embedding vector(768)" in statements
    assert "primary key (collection, id)" in statements
    assert "check (singleton)" in statements
    for table in ("kb_docs", "kb_registry"):
        assert f"alter table {table} enable row level security" in statements
    assert "create policy" not in statements and "grant " not in statements
    assert "create index" not in statements
