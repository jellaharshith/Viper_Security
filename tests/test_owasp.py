from pathlib import Path

import httpx
import pytest

from viper.rag import owasp
from viper.rag.owasp import CATEGORY_FILES, fetch_owasp, parse_owasp
from viper.rag.types import IngestError

FIX = Path(__file__).parent / "fixtures" / "owasp_A05_sample.md"


def pages() -> dict[str, str]:
    return {"A05": FIX.read_text(encoding="utf-8")}


def test_chunks_by_heading_with_contract_ids() -> None:
    docs = {d.id: d for d in parse_owasp(pages(), "2025")}
    assert set(docs) == {f"owasp-top10:2025:A05:{c}"
                         for c in ("overview", "description", "prevention", "scenarios")}
    assert all(d.source == "owasp-top10" for d in docs.values())


def test_skips_score_table_references_and_cwe_sections() -> None:
    text = " ".join(d.text for d in parse_owasp(pages()))
    assert "CWEs Mapped" not in text and "Should not be indexed" not in text and "CWE-79" not in text


def test_code_fence_hashes_do_not_split_sections_and_markdown_is_cleaned() -> None:
    docs = {d.id.rsplit(":", 1)[1]: d for d in parse_owasp(pages())}
    assert "this comment-looking line" in docs["scenarios"].text
    assert "nor must this one" in docs["scenarios"].text
    assert "icon" not in docs["overview"].title and "icon" not in docs["overview"].text
    assert "OWASP LLM Top 10" in docs["description"].text
    assert "genai.owasp.org" not in docs["description"].text
    assert "**" not in docs["prevention"].text and "parameterized" in docs["prevention"].text


def test_attribution_license_and_url_kept() -> None:
    d = parse_owasp(pages())[0]
    assert d.meta["license"] == "CC BY-SA 4.0" and d.meta["attribution"].startswith("OWASP")
    assert d.url == "https://owasp.org/Top10/2025/A05_2025-Injection/"
    assert d.title.startswith("A05:2025 Injection")


def test_bad_pages_are_rejected() -> None:
    with pytest.raises(IngestError):
        parse_owasp({})
    with pytest.raises(IngestError):
        parse_owasp({"A05": "no headings at all"})


def test_fetch_requests_exactly_the_fixed_pinned_urls() -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(200, text=FIX.read_text(encoding="utf-8"))

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    got = fetch_owasp(client)
    assert list(got) == list(CATEGORY_FILES) and len(seen) == 10
    prefix = f"https://raw.githubusercontent.com/OWASP/Top10/{owasp.OWASP_REF}/"
    assert all(u.startswith(prefix) for u in seen)


def test_fetch_failure_raises_ingest_error() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    with pytest.raises(IngestError):
        fetch_owasp(client)
