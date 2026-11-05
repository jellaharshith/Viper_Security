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
