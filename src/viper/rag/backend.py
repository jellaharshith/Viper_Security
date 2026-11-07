"""Backend selection for the knowledge base.

``VIPER_STORE`` picks the backend:
  * ``qdrant``   (default) local embedded Qdrant, file-based registry
  * ``supabase`` Supabase over HTTPS, reads SUPABASE_URL + SUPABASE_SECRET_KEY from .env
  * ``pgvector`` direct Postgres, reads VIPER_DATABASE_URL

Nothing connects until a store/registry is opened, and each remote driver is imported lazily.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from viper.config import Settings
from viper.rag.registry import KBRegistry, resolve_collection
from viper.rag.store import VectorStore
from viper.rag.types import Store

if TYPE_CHECKING:
    from viper.rag.pgstore import PgKBRegistry
    from viper.rag.reststore import RestKBRegistry


def _require_url(settings: Settings) -> str:
    url = settings.database_url.get_secret_value()
    if not url:
        raise ValueError("VIPER_STORE=pgvector needs VIPER_DATABASE_URL (session-pooler string) in .env")
    return url


def open_registry(settings: Settings) -> KBRegistry | PgKBRegistry | RestKBRegistry:
    if settings.store == "supabase":
        from viper.rag.reststore import RestKBRegistry

        return RestKBRegistry(settings.supabase_url, settings.supabase_secret_key)
    if settings.store == "pgvector":
        from viper.rag.pgstore import PgKBRegistry

        return PgKBRegistry(_require_url(settings))
    return KBRegistry.load(settings.kb_registry_path)


def open_store(settings: Settings, collection: str) -> Store:
    if settings.store == "supabase":
        from viper.rag.reststore import RestVectorStore

        return RestVectorStore(settings.supabase_url, settings.supabase_secret_key, collection)
    if settings.store == "pgvector":
        from viper.rag.pgstore import PgVectorStore

        return PgVectorStore(_require_url(settings), collection)
    return VectorStore(settings.qdrant_path, collection)


def active_collection(settings: Settings) -> str:
    fallback = f"kb_{settings.kb_version}"
    reg = open_registry(settings)
    if isinstance(reg, KBRegistry):
        return resolve_collection(settings.kb_registry_path, fallback)
    try:
        return reg.active or fallback
    finally:
        reg.close()
