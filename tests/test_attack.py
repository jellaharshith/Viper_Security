import json
from pathlib import Path

import httpx
import pytest

from viper.rag.attack import ATTACK_URL, fetch_attack, parse_attack
from viper.rag.types import IngestError

FIX = Path(__file__).parent / "fixtures" / "attack_sample.json"


def bundle() -> dict:  # type: ignore[type-arg]
    return json.loads(FIX.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _client(transport: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(transport=transport, follow_redirects=False)


def test_parse_keeps_techniques_and_subtechniques_only() -> None:
    docs = {d.id: d for d in parse_attack(bundle())}
    assert set(docs) == {"attack:T1059", "attack:T1059.001"}  # revoked/deprecated/malformed skipped


def test_record_format_matches_shared_contract() -> None:
    d = {x.id: x for x in parse_attack(bundle())}["attack:T1059.001"]
    assert d.source == "mitre-attack"
    assert d.title == "T1059.001 PowerShell"
    assert d.url == "https://attack.mitre.org/techniques/T1059/001"
    for part in ("T1059.001", "PowerShell", "execution", "Windows", "script block logging"):
        assert part in d.text
    assert d.meta["subtechnique"] is True


def test_citations_are_stripped_from_text() -> None:
    d = {x.id: x for x in parse_attack(bundle())}["attack:T1059"]
    assert "Citation" not in d.text and "Tactics: execution" in d.text
    assert "Linux, macOS, Windows" in d.text


def test_duplicates_collapse_and_invalid_bundle_is_rejected() -> None:
    b = bundle()
    b["objects"] = b["objects"] + b["objects"]
    assert len(parse_attack(b)) == 2
    with pytest.raises(IngestError):
        parse_attack({"type": "bundle", "objects": [{"type": "intrusion-set"}]})
    with pytest.raises(IngestError):
        parse_attack({"nope": 1})


def test_fetch_uses_pinned_https_allowlisted_url() -> None:
    assert ATTACK_URL.startswith("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/")
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(200, json=bundle())

    assert fetch_attack(client=_client(httpx.MockTransport(handler)))["type"] == "bundle"
    assert seen == [ATTACK_URL]


@pytest.mark.parametrize("url", ["http://raw.githubusercontent.com/x.json",
                                 "https://evil.example.com/x.json",
                                 "https://github.com/x.json"])
def test_fetch_refuses_untrusted_urls(url: str) -> None:
    ok = httpx.MockTransport(lambda r: httpx.Response(200, json={}))
    with pytest.raises(IngestError):
        fetch_attack(url, client=_client(ok))


def test_fetch_refuses_redirects_http_errors_and_bad_json() -> None:
    redirect = httpx.MockTransport(
        lambda r: httpx.Response(302, headers={"location": "https://evil.example.com"}))
    with pytest.raises(IngestError):
        fetch_attack(client=_client(redirect))
    with pytest.raises(IngestError):
        fetch_attack(client=_client(httpx.MockTransport(lambda r: httpx.Response(500))))
    with pytest.raises(IngestError):
        fetch_attack(client=_client(httpx.MockTransport(
            lambda r: httpx.Response(200, content=b"not json"))))


def test_fetch_enforces_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("viper.rag.attack.MAX_BYTES", 100)
    big = httpx.MockTransport(lambda r: httpx.Response(200, content=b"{" + b" " * 500 + b"}"))
    with pytest.raises(IngestError, match="large|exceeded"):
        fetch_attack(client=_client(big))
