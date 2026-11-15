import io
import zipfile
from pathlib import Path

import httpx
import pytest

from viper.rag.cwe import CWE_URL, fetch_cwe, parse_cwe
from viper.rag.types import IngestError

FIX = Path(__file__).parent / "fixtures" / "cwe_sample.xml"


def xml_text() -> str:
    return FIX.read_text(encoding="utf-8")


def _zip_of(xml: str, name: str = "cwec_v4.17.xml") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, xml)
    return buf.getvalue()


def _client(transport: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(transport=transport, follow_redirects=False)


def test_parse_keeps_active_weaknesses_only() -> None:
    docs = {d.id: d for d in parse_cwe(xml_text())}
    assert set(docs) == {"cwe:CWE-79", "cwe:CWE-89"}  # deprecated CWE-9999 skipped


def test_record_format_matches_shared_contract() -> None:
    d = {x.id: x for x in parse_cwe(xml_text())}["cwe:CWE-79"]
    assert d.source == "cwe"
    assert d.url == "https://cwe.mitre.org/data/definitions/79.html"
    assert "CWE-79" in d.text and "Cross-site Scripting" in d.title
    assert d.meta["abstraction"] == "Base"
    assert d.meta["license"]


def test_duplicates_collapse_and_invalid_catalog_is_rejected() -> None:
    with pytest.raises(IngestError):
        parse_cwe("<nope/>")
    with pytest.raises(IngestError):
        parse_cwe("<Weakness_Catalog xmlns='http://cwe.mitre.org/cwe-7'></Weakness_Catalog>")


def test_fetch_uses_pinned_https_allowlisted_url_and_unzips() -> None:
    assert CWE_URL.startswith("https://cwe.mitre.org/")
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(200, content=_zip_of(xml_text()))

    out = fetch_cwe(client=_client(httpx.MockTransport(handler)))
    assert "Weakness_Catalog" in out and seen == [CWE_URL]


@pytest.mark.parametrize("url", ["http://cwe.mitre.org/x.zip",
                                 "https://evil.example.com/x.zip"])
def test_fetch_refuses_untrusted_urls(url: str) -> None:
    ok = httpx.MockTransport(lambda r: httpx.Response(200, content=_zip_of(xml_text())))
    with pytest.raises(IngestError):
        fetch_cwe(url, client=_client(ok))


def test_fetch_refuses_redirects_errors_and_bad_zip() -> None:
    redirect = httpx.MockTransport(
        lambda r: httpx.Response(302, headers={"location": "https://evil.example.com"}))
    with pytest.raises(IngestError):
        fetch_cwe(client=_client(redirect))
    with pytest.raises(IngestError):
        fetch_cwe(client=_client(httpx.MockTransport(lambda r: httpx.Response(500))))
    with pytest.raises(IngestError):
        fetch_cwe(client=_client(httpx.MockTransport(
            lambda r: httpx.Response(200, content=b"not a zip"))))


def test_text_body_folds_in_extended_and_consequences() -> None:
    d = {x.id: x for x in parse_cwe(xml_text())}["cwe:CWE-79"]
    # definition leads, then extended prose, then a single compact consequences clause
    assert "does not neutralize" in d.text
    assert "Cross-site scripting (XSS) vulnerabilities occur" in d.text
    assert "Consequences -" in d.text and "Read Application Data" in d.text
    # CWE-89 has one consequence; CWE-9999 (deprecated) is absent
    d89 = {x.id: x for x in parse_cwe(xml_text())}["cwe:CWE-89"]
    assert d89.text.count("Consequences -") == 1
