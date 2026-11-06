"""Shared RAG data types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Document:
    """One retrievable passage with provenance preserved."""

    id: str  # stable, unique per source record (drives dedupe)
    text: str
    source: str  # human-readable source name, e.g. "CISA KEV"
    url: str  # where a reader can verify it
    title: str
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Hit:
    document: Document
    score: float


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...


class IngestError(RuntimeError):
    """Source data failed validation; nothing should be stored."""


class Store(Protocol):
    collection: str

    def upsert(self, docs: list[Document], vectors: list[list[float]]) -> None: ...
    def search(self, vector: list[float], k: int) -> list[Hit]: ...
    def get_many(self, doc_ids: list[str]) -> list[Document]: ...
    def export(self) -> list[tuple[Document, list[float]]]: ...
    def count(self) -> int: ...
    def drop(self) -> None: ...
    def exists(self) -> bool: ...
    def view(self, collection: str) -> Store: ...
    def close(self) -> None: ...
