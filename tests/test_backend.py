from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from viper.config import Settings
from viper.rag import backend
from viper.rag.registry import KBRegistry
from viper.rag.store import VectorStore


def _settings(tmp_path: Path, **kw: object) -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        qdrant_path=tmp_path / "q",
        kb_registry_path=tmp_path / "reg.json",
        **kw,  # type: ignore[arg-type]
    )


def test_default_backend_is_local_qdrant(tmp_path: Path) -> None:
    s = _settings(tmp_path)
    store = backend.open_store(s, "kb_test")
    try:
        assert isinstance(store, VectorStore)
    finally:
        store.close()
    assert isinstance(backend.open_registry(s), KBRegistry)
    assert backend.active_collection(s) == f"kb_{s.kb_version}"


def test_pgvector_without_url_fails_before_connecting(tmp_path: Path) -> None:
    s = _settings(tmp_path, store="pgvector")
    with pytest.raises(ValueError, match="VIPER_DATABASE_URL"):
        backend.open_store(s, "kb_test")
    with pytest.raises(ValueError, match="VIPER_DATABASE_URL"):
        backend.open_registry(s)


def test_pgvector_selected_with_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class FakeStore:
        def __init__(self, url: str, collection: str) -> None:
            seen["url"], seen["collection"] = url, collection

    monkeypatch.setattr("viper.rag.pgstore.PgVectorStore", FakeStore)
    s = _settings(tmp_path, store="pgvector", database_url=SecretStr("postgresql://u:p@h/db"))
    store = backend.open_store(s, "kb_x")
    assert isinstance(store, FakeStore)
    assert seen == {"url": "postgresql://u:p@h/db", "collection": "kb_x"}
    assert "postgresql" not in repr(s.redacted())
