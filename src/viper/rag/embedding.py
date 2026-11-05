"""Embedding helpers."""

from __future__ import annotations

from viper.rag.types import Embedder


class PrefixEmbedder:
    """Prepends a fixed prefix to every text before embedding.

    Some embedding models (e.g. nomic-embed-text) are trained to expect task prefixes such as
    "search_query: " for questions and "search_document: " for stored passages.
    """

    def __init__(self, inner: Embedder, prefix: str = "") -> None:
        self._inner = inner
        self._prefix = prefix

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not self._prefix:
            return self._inner.embed(texts)
        return self._inner.embed([self._prefix + t for t in texts])
