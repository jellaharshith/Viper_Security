"""Supabase backend over the HTTPS (PostgREST) API, using SUPABASE_URL + SUPABASE_SECRET_KEY.

No Postgres connection string is needed. Apply ``db/migrations/0001_kb.sql`` and
``0002_kb_rest.sql`` once in the Supabase SQL editor (the API keys cannot create tables).
The secret key bypasses RLS, so it stays server-side: it is a ``SecretStr``, is only sent
in headers over https to ``*.supabase.co``, and never appears in errors, repr or logs.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import SecretStr

from viper.rag.types import Document, Hit

_PAGE = 500
_UPSERT_BATCH = 50


class RestError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"supabase request failed ({status}): {message}")
        self.status = status
        self.message = message


def _collection(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", name):
        raise ValueError("invalid collection name")
    return name


def _vector(vector: list[float]) -> str:
    if len(vector) != 768 or not all(math.isfinite(x) for x in vector):
        raise ValueError("expected 768 finite vector components")
    return json.dumps(vector)


def _quote(value: str) -> str:
    """Quote one value for a PostgREST ``in.(...)`` list."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _make_client(url: str, key: SecretStr | str) -> httpx.Client:
    secret = key.get_secret_value() if isinstance(key, SecretStr) else key
    parsed = urlparse(url)
    if parsed.scheme != "https" or not (parsed.hostname or "").endswith(".supabase.co"):
        raise ValueError("SUPABASE_URL must be an https://<project>.supabase.co address")
    if not secret:
        raise ValueError("SUPABASE_SECRET_KEY is required for the supabase store")
    headers = {"apikey": secret, "Content-Type": "application/json"}
    if secret.count(".") == 2:  # legacy JWT-style service key also goes in Authorization
        headers["Authorization"] = f"Bearer {secret}"
    return httpx.Client(
        base_url=f"{parsed.scheme}://{parsed.hostname}/rest/v1",
        headers=headers, timeout=60.0, follow_redirects=False,
    )


def _send(client: httpx.Client, method: str, path: str, **kw: Any) -> httpx.Response:
    try:
        resp = client.request(method, path, **kw)
    except httpx.HTTPError:
        raise RuntimeError("could not reach Supabase") from None  # never echo request details
    if resp.status_code >= 400:
        try:
            body = resp.json()
            message = str(body.get("message", ""))[:200] if isinstance(body, dict) else ""
        except ValueError:
            message = ""
        raise RestError(resp.status_code, message)
    return resp


def _doc(row: dict[str, Any]) -> Document:
    return Document(id=row["id"], text=row["text"], source=row["source"], url=row["url"],
                    title=row["title"], meta=row.get("meta") or {})


class RestVectorStore:
    def __init__(
        self, url: str, key: SecretStr | str, collection: str, *, client: httpx.Client | None = None,
    ) -> None:
        self.collection = _collection(collection)
        self._client = client if client is not None else _make_client(url, key)
        self._owner = client is None

    def __repr__(self) -> str:
        return f"RestVectorStore(collection={self.collection!r})"

    def view(self, collection: str) -> RestVectorStore:
        return RestVectorStore("", "", collection, client=self._client)

    def _scope(self) -> dict[str, str]:
        return {"collection": f"eq.{self.collection}"}

    def count(self) -> int:
        resp = _send(self._client, "GET", "/kb_docs", params={"select": "id", **self._scope()},
                     headers={"Prefer": "count=exact", "Range": "0-0"})
        return int(resp.headers.get("content-range", "*/0").rsplit("/", 1)[-1])

    def exists(self) -> bool:
        return self.count() > 0

    def drop(self) -> None:
        _send(self._client, "DELETE", "/kb_docs", params=self._scope(),
              headers={"Prefer": "return=minimal"})

    def upsert(self, docs: list[Document], vectors: list[list[float]]) -> None:
        if len(docs) != len(vectors):
            raise ValueError("docs and vectors differ in length")
        for i in range(0, len(docs), _UPSERT_BATCH):
            rows = [
                {"collection": self.collection, "id": d.id, "text": d.text, "source": d.source,
                 "url": d.url, "title": d.title, "meta": d.meta, "embedding": _vector(v)}
                for d, v in zip(docs[i:i + _UPSERT_BATCH], vectors[i:i + _UPSERT_BATCH], strict=True)
            ]
            _send(self._client, "POST", "/kb_docs", params={"on_conflict": "collection,id"},
                  json=rows,
                  headers={"Prefer": "resolution=merge-duplicates,return=minimal"})

    def get_many(self, doc_ids: list[str]) -> list[Document]:
        out: list[Document] = []
        for i in range(0, len(doc_ids), 100):
            ids = ",".join(_quote(x) for x in doc_ids[i:i + 100])
            resp = _send(self._client, "GET", "/kb_docs", params={
                "select": "id,text,source,url,title,meta", "id": f"in.({ids})", **self._scope()})
            out.extend(_doc(r) for r in resp.json())
        return out

    def export(self) -> list[tuple[Document, list[float]]]:
        out: list[tuple[Document, list[float]]] = []
        offset = 0
        while True:
            resp = _send(self._client, "GET", "/kb_docs", params={
                "select": "id,text,source,url,title,meta,embedding", "order": "id.asc",
                "limit": str(_PAGE), "offset": str(offset), **self._scope()})
            rows = resp.json()
            for r in rows:
                emb = r["embedding"]
                out.append((_doc(r), json.loads(emb) if isinstance(emb, str) else list(emb)))
            if len(rows) < _PAGE:
                return out
            offset += _PAGE

    def search(self, vector: list[float], k: int) -> list[Hit]:
        resp = _send(self._client, "POST", "/rpc/kb_search", json={
            "p_collection": self.collection, "p_embedding": _vector(vector), "p_k": k})
        return [Hit(document=_doc(r), score=float(r["score"])) for r in resp.json()]

    def close(self) -> None:
        if self._owner:
            self._client.close()


class RestKBRegistry:
    """KBRegistry counterpart; each pointer change is one SQL function call (one transaction)."""

    def __init__(
        self, url: str, key: SecretStr | str, *, client: httpx.Client | None = None,
    ) -> None:
        self._client = client if client is not None else _make_client(url, key)
        self._owner = client is None
        self.active: str | None = None
        self.previous: str | None = None
        self.history: list[dict[str, str]] = []
        self.refresh()

    def __repr__(self) -> str:
        return f"RestKBRegistry(active={self.active!r})"

    def _apply(self, row: dict[str, Any]) -> None:
        self.active, self.previous = row["active"], row["previous"]
        self.history = list(row["history"])

    def refresh(self) -> None:
        resp = _send(self._client, "GET", "/kb_registry", params={
            "select": "active,previous,history", "singleton": "eq.true"})
        rows = resp.json()
        if not rows:
            raise RuntimeError("missing kb_registry row; apply db/migrations/0001_kb.sql")
        self._apply(rows[0])

    def _change(self, event: str, collection: str | None = None) -> str:
        if collection is not None:
            _collection(collection)
        try:
            resp = _send(self._client, "POST", "/rpc/kb_registry_change",
                         json={"p_event": event, "p_collection": collection})
        except RestError as exc:
            if exc.message.startswith("kb: "):
                raise ValueError(exc.message[4:]) from None
            raise
        self._apply(resp.json())
        return self.active or ""

    def bootstrap(self, collection: str) -> None:
        self._change("bootstrap", collection)

    def promote(self, collection: str) -> None:
        self._change("promote", collection)

    def rollback(self) -> str:
        return self._change("rollback")

    def close(self) -> None:
        if self._owner:
            self._client.close()
