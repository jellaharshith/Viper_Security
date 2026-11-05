"""Minimal Ollama HTTP client (local plane). Chat and embeddings only."""

from __future__ import annotations

from typing import Any

import httpx


class LLMError(RuntimeError):
    """Raised when the local model server is unreachable or returns bad data."""


class OllamaClient:
    def __init__(
        self,
        host: str,
        model: str,
        embed_model: str,
        timeout: float = 600.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.model = model
        self.embed_model = embed_model
        # CPU inference is slow: generous timeout. `transport` lets tests inject a fake server.
        self._http = httpx.Client(base_url=host, timeout=timeout, transport=transport)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = self._http.post(path, json=payload)
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
        except httpx.HTTPError as exc:
            raise LLMError(f"Ollama request to {path} failed: {exc}") from exc
        except ValueError as exc:
            raise LLMError(f"Ollama returned invalid JSON from {path}") from exc
        return data

    def chat(self, messages: list[dict[str, str]], temperature: float = 0.2) -> str:
        if not self.model:
            raise LLMError("No chat model configured (set VIPER_OLLAMA_MODEL).")
        data = self._post(
            "/api/chat",
            {"model": self.model, "messages": messages, "stream": False,
             "options": {"temperature": temperature}},
        )
        try:
            return str(data["message"]["content"])
        except (KeyError, TypeError) as exc:
            raise LLMError("Unexpected /api/chat response shape") from exc

    def embed(self, texts: list[str]) -> list[list[float]]:
        data = self._post("/api/embed", {"model": self.embed_model, "input": texts})
        vectors = data.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise LLMError("Unexpected /api/embed response shape")
        return [[float(x) for x in v] for v in vectors]
