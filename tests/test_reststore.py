from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from viper.config import Settings
from viper.rag import backend
from viper.rag.reststore import RestError, RestKBRegistry, RestVectorStore, _make_client
from viper.rag.types import Document

SECRET = "sb_secret_TOPSECRET"  # noqa: S105 (fake test value)
VEC = [0.5] * 768


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(base_url="https://p.supabase.co/rest/v1", transport=httpx.MockTransport(handler))


def _doc(i: int) -> Document:
    return Document(id=f"attack:T{i:04d}", text="t", source="mitre-attack", url="u", title="n", meta={"a": 1})


def test_upsert_batches_and_sends_vectors() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(201)

    store = RestVectorStore("", "", "kb_v1", client=_client(handler))
    store.upsert([_doc(i) for i in range(120)], [VEC] * 120)
    assert [len(json.loads(r.content)) for r in seen] == [50, 50, 20]
    first = json.loads(seen[0].content)[0]
    assert first["collection"] == "kb_v1" and json.loads(first["embedding"]) == VEC
    assert seen[0].url.params["on_conflict"] == "collection,id"
    assert "merge-duplicates" in seen[0].headers["prefer"]


def test_rejects_bad_vectors_and_collection_names() -> None:
    store = RestVectorStore("", "", "kb_v1", client=_client(lambda r: httpx.Response(200, json=[])))
    with pytest.raises(ValueError):
        store.upsert([_doc(1)], [[0.1] * 5])
    with pytest.raises(ValueError):
        store.upsert([_doc(1)], [VEC, VEC])
    with pytest.raises(ValueError):
        RestVectorStore("", "", "x; drop table kb_docs", client=_client(lambda r: httpx.Response(200)))


def test_get_many_quotes_ids_and_scopes_collection() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=[{"id": 'a"b', "text": "t", "source": "s", "url": "u",
                                         "title": "n", "meta": None}])

    docs = RestVectorStore("", "", "kb_v1", client=_client(handler)).get_many(['a"b', "attack:T1059.001"])
    assert docs[0].id == 'a"b' and docs[0].meta == {}
    assert seen[0].url.params["id"] == 'in.("a\\"b","attack:T1059.001")'
    assert seen[0].url.params["collection"] == "eq.kb_v1"


def test_count_exists_and_drop() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "DELETE":
            assert req.url.params["collection"] == "eq.kb_v1"  # never an unscoped delete
            return httpx.Response(204)
        return httpx.Response(206, headers={"content-range": "0-0/1768"}, json=[{"id": "x"}])

    store = RestVectorStore("", "", "kb_v1", client=_client(handler))
    assert store.count() == 1768 and store.exists()
    store.drop()
    empty = RestVectorStore("", "", "kb_v1", client=_client(
        lambda r: httpx.Response(200, headers={"content-range": "*/0"}, json=[])))
    assert not empty.exists()


def test_export_paginates_and_parses_vectors() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        offset = int(req.url.params["offset"])
        n = 500 if offset == 0 else 3
        rows = [{"id": f"d{offset + i}", "text": "t", "source": "s", "url": "u", "title": "n",
                 "meta": {}, "embedding": json.dumps([0.25] * 768)} for i in range(n)]
        return httpx.Response(200, json=rows)

    out = RestVectorStore("", "", "kb_v1", client=_client(handler)).export()
    assert len(out) == 503 and out[0][1] == [0.25] * 768


def test_search_uses_rpc_and_returns_scored_hits() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        assert req.url.path.endswith("/rpc/kb_search")
        assert body["p_collection"] == "kb_v1" and body["p_k"] == 4
        return httpx.Response(200, json=[{"id": "d1", "text": "t", "source": "s", "url": "u",
                                         "title": "n", "meta": {}, "score": 0.91}])

    hits = RestVectorStore("", "", "kb_v1", client=_client(handler)).search(VEC, 4)
    assert hits[0].document.id == "d1" and hits[0].score == pytest.approx(0.91)


def test_errors_never_leak_the_key_or_request_details() -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("failed", request=req)

    store = RestVectorStore("", "", "kb_v1", client=_client(boom))
    with pytest.raises(RuntimeError, match="could not reach Supabase") as exc:
        store.count()
    assert SECRET not in str(exc.value)
    bad = RestVectorStore("", "", "kb_v1", client=_client(
        lambda r: httpx.Response(401, json={"message": "Invalid API key"})))
    with pytest.raises(RestError) as exc2:
        bad.count()
    assert exc2.value.status == 401


def test_client_requires_https_supabase_host_and_a_key() -> None:
    with pytest.raises(ValueError):
        _make_client("http://p.supabase.co", SECRET)
    with pytest.raises(ValueError):
        _make_client("https://evil.example.com", SECRET)
    with pytest.raises(ValueError):
        _make_client("https://p.supabase.co", "")
    client = _make_client("https://p.supabase.co", SecretStr(SECRET))
    assert client.headers["apikey"] == SECRET and "authorization" not in client.headers
    assert not client.follow_redirects
    jwt = _make_client("https://p.supabase.co", "aaa.bbb.ccc")
    assert jwt.headers["authorization"] == "Bearer aaa.bbb.ccc"
    store = RestVectorStore("https://p.supabase.co", SECRET, "kb_v1")
    assert SECRET not in repr(store)
    store.close()


def _reg_handler(state: dict[str, object]) -> Callable[[httpx.Request], httpx.Response]:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET":
            return httpx.Response(200, json=[state])
        body = json.loads(req.content)
        if body["p_event"] == "rollback" and not state["previous"]:
            return httpx.Response(400, json={"message": "kb: no previous collection to roll back to"})
        if body["p_event"] == "promote":
            state.update(previous=state["active"], active=body["p_collection"])
        return httpx.Response(200, json=state)

    return handler


def test_registry_promote_and_rollback_error_mapping() -> None:
    state: dict[str, object] = {"active": "kb_v1", "previous": None, "history": []}
    reg = RestKBRegistry("", "", client=_client(_reg_handler(state)))
    assert reg.active == "kb_v1"
    with pytest.raises(ValueError, match="no previous collection"):
        reg.rollback()
    reg.promote("kb_v2")
    assert (reg.active, reg.previous) == ("kb_v2", "kb_v1")
    with pytest.raises(ValueError):
        reg.promote("bad name!")
    with pytest.raises(RuntimeError, match="missing kb_registry"):
        RestKBRegistry("", "", client=_client(lambda r: httpx.Response(200, json=[])))


def test_settings_read_the_dotenv_names_the_user_already_has(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(f"SUPABASE_URL=https://p.supabase.co\nSUPABASE_SECRET_KEY={SECRET}\n"
                   "SUPABASE_PUBLISHABLE_KEY=pk\nVIPER_STORE=supabase\n", encoding="utf-8")
    s = Settings(_env_file=env)  # type: ignore[call-arg]
    assert s.store == "supabase" and s.supabase_url == "https://p.supabase.co"
    assert s.supabase_secret_key.get_secret_value() == SECRET
    assert SECRET not in repr(s.redacted())


def test_backend_selects_supabase(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class Fake:
        def __init__(self, url: str, key: object, collection: str) -> None:
            seen.update(url=url, collection=collection)

    monkeypatch.setattr("viper.rag.reststore.RestVectorStore", Fake)
    s = Settings(_env_file=None, store="supabase", supabase_url="https://p.supabase.co",  # type: ignore[call-arg]
                 supabase_secret_key=SecretStr(SECRET))
    assert isinstance(backend.open_store(s, "kb_x"), Fake)
    assert seen == {"url": "https://p.supabase.co", "collection": "kb_x"}
