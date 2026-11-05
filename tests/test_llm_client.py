import json

import httpx
import pytest

from viper.llm import LLMError, OllamaClient


def _client(handler: httpx.MockTransport, model: str = "m") -> OllamaClient:
    return OllamaClient("http://ollama.test", model, "embed", transport=handler)


def test_chat_returns_content() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        assert req.url.path == "/api/chat" and body["stream"] is False
        return httpx.Response(200, json={"message": {"content": "hi"}})

    assert _client(httpx.MockTransport(h)).chat([{"role": "user", "content": "x"}]) == "hi"


def test_embed_returns_vectors() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"embeddings": [[1, 2], [3, 4]]})

    assert _client(httpx.MockTransport(h)).embed(["a", "b"]) == [[1.0, 2.0], [3.0, 4.0]]


def test_server_error_becomes_llmerror() -> None:
    c = _client(httpx.MockTransport(lambda r: httpx.Response(500)))
    with pytest.raises(LLMError):
        c.chat([{"role": "user", "content": "x"}])


def test_embed_wrong_count_rejected() -> None:
    c = _client(httpx.MockTransport(lambda r: httpx.Response(200, json={"embeddings": [[1.0]]})))
    with pytest.raises(LLMError):
        c.embed(["a", "b"])


def test_missing_model_rejected() -> None:
    with pytest.raises(LLMError):
        _client(httpx.MockTransport(lambda r: httpx.Response(200)), model="").chat([])
