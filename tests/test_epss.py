
import httpx
import pytest

from viper.rag.epss import EPSS_URL, enrich_documents, fetch_epss_scores
from viper.rag.types import Document, IngestError


def _client(transport: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(transport=transport, follow_redirects=False)


def _kev_doc(cve: str) -> Document:
    return Document(id=f"cisa-kev:{cve}", text=f"{cve} - something.", source="CISA KEV",
                    url=f"https://nvd.nist.gov/vuln/detail/{cve}", title=cve, meta={})


def test_fetch_parses_scores_and_pins_host() -> None:
    assert EPSS_URL.startswith("https://api.first.org/")
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(200, json={"status": "OK", "data": [
            {"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99998"},
            {"cve": "CVE-2024-0001", "epss": "0.00042", "percentile": "0.1"}]})

    scores = fetch_epss_scores(["CVE-2021-44228", "CVE-2024-0001"],
                               client=_client(httpx.MockTransport(handler)))
    assert scores["CVE-2021-44228"][0] == pytest.approx(0.97565)
    assert scores["CVE-2024-0001"][1] == pytest.approx(0.1)
    assert len(seen) == 1 and "api.first.org" in seen[0]


def test_fetch_batches_large_cve_lists() -> None:
    calls = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"status": "OK", "data": []})

    fetch_epss_scores([f"CVE-2024-{i:04d}" for i in range(250)], batch=100,
                      client=_client(httpx.MockTransport(handler)))
    assert calls["n"] == 3  # 100 + 100 + 50


def test_enrich_decorates_only_matching_kev_records() -> None:
    docs = [_kev_doc("CVE-2021-44228"), _kev_doc("CVE-9999-0000"),
            Document(id="attack:T1059", text="x", source="mitre-attack", url="https://a", title="t")]
    scores = {"CVE-2021-44228": (0.97565, 0.99998)}
    out = {d.id: d for d in enrich_documents(docs, scores)}
    assert len(out) == 3  # no new records, no dropped records
    enriched = out["cisa-kev:CVE-2021-44228"]
    assert enriched.meta["epss"] == pytest.approx(0.97565)
    assert "EPSS" in enriched.text and "0.976" in enriched.text
    assert out["cisa-kev:CVE-9999-0000"].text == "CVE-9999-0000 - something."  # untouched
    assert out["attack:T1059"].meta == {}  # non-KEV untouched


def test_fetch_refuses_untrusted_host_and_bad_json() -> None:
    with pytest.raises(IngestError):
        fetch_epss_scores(["CVE-2024-0001"], url="https://evil.example/epss",
                          client=_client(httpx.MockTransport(lambda r: httpx.Response(200, json={}))))
    with pytest.raises(IngestError):
        fetch_epss_scores(["CVE-2024-0001"],
                          client=_client(httpx.MockTransport(
                              lambda r: httpx.Response(200, content=b"not json"))))
