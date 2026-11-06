"""Backend selection: local embedded Qdrant (default) or Supabase/Postgres pgvector.

``VIPER_STORE`` picks the backend. Nothing here connects until a store/registry is opened,
so the default (qdrant) path never imports or touches psycopg.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from viper.config import Settings
from viper.rag.registry import KBRegistry, resolve_collection
from viper.rag.store import VectorStore
from viper.rag.types import Store

if TYPE_CHECKING:
    from viper.rag.pgstore import PgKBRegistry



def _require_url(settings: Settings) -> str:
    url = settings.database_url.get_secret_value()
    if not url:
        raise ValueError("VIPER_STORE=pgvector needs VIPER_DATABASE_URL (session-pooler string) in .env")
    return url


def open_registry(settings: Settings) -> KBRegistry | PgKBRegistry:
    if settings.store == "pgvector":
        from viper.rag.pgstore import PgKBRegistry

        return PgKBRegistry(_require_url(settings))
    return KBRegistry.load(settings.kb_registry_path)


def open_store(settings: Settings, collection: str) -> Store:
    if settings.store == "pgvector":
        from viper.rag.pgstore import PgVectorStore

        return PgVectorStore(_require_url(settings), collection)
    return VectorStore(settings.qdrant_path, collection)


def active_collection(settings: Settings) -> str:
    fallback = f"kb_{settings.kb_version}"
    if settings.store == "pgvector":
        reg = open_registry(settings)
        try:
            return reg.active or fallback
        finally:
            reg.close()  # type: ignore[union-attr]
    return resolve_collection(settings.kb_registry_path, fallback)
