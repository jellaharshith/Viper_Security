"""Embedded Qdrant vector store (local folder, no server). One collection per KB version."""

from __future__ import annotations

import uuid
from pathlib import Path

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

from viper.rag.types import Document, Hit

_NS = uuid.UUID("6f1c1b0e-0000-4000-8000-00000000a11c")


class VectorStore:
    def __init__(self, path: Path | None, collection: str) -> None:
        # path=None -> in-memory (used by tests)
        self._client = QdrantClient(path=str(path)) if path else QdrantClient(":memory:")
        self.collection = collection

    def _ensure(self, dim: int) -> None:
        if not self._client.collection_exists(self.collection):
            self._client.create_collection(
                self.collection, vectors_config=VectorParams(size=dim, distance=Distance.COSINE)
            )

    def count(self) -> int:
        if not self._client.collection_exists(self.collection):
            return 0
        return int(self._client.count(self.collection, exact=True).count)

    def upsert(self, docs: list[Document], vectors: list[list[float]]) -> None:
        if len(docs) != len(vectors):
            raise ValueError("docs and vectors length mismatch")
        if not docs:
            return
        self._ensure(len(vectors[0]))
        points = [
            PointStruct(
                # deterministic id from the document id => re-ingesting overwrites, never duplicates
                id=str(uuid.uuid5(_NS, d.id)),
                vector=v,
                payload={"id": d.id, "text": d.text, "source": d.source, "url": d.url,
                         "title": d.title, "meta": d.meta},
            )
            for d, v in zip(docs, vectors, strict=True)
        ]
        self._client.upsert(self.collection, points=points)

    def get_many(self, doc_ids: list[str]) -> list[Document]:
        """Exact lookup by document id (no embedding involved)."""
        if not doc_ids or not self._client.collection_exists(self.collection):
            return []
        pts = self._client.retrieve(
            self.collection, ids=[str(uuid.uuid5(_NS, i)) for i in doc_ids], with_payload=True
        )
        return [self._to_doc(p.payload or {}) for p in pts]

    @staticmethod
    def _to_doc(pl: dict) -> Document:  # type: ignore[type-arg]
        return Document(id=pl["id"], text=pl["text"], source=pl["source"], url=pl["url"],
                        title=pl["title"], meta=pl.get("meta", {}))

    def search(self, vector: list[float], k: int) -> list[Hit]:
        if not self._client.collection_exists(self.collection):
            return []
        res = self._client.query_points(self.collection, query=vector, limit=k, with_payload=True)
        hits: list[Hit] = []
        for p in res.points:
            hits.append(Hit(document=self._to_doc(p.payload or {}), score=float(p.score)))
        return hits

    def close(self) -> None:
        self._client.close()
