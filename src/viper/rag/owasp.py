"""OWASP Top 10 connector: fetch the pinned markdown pages, chunk by heading, normalize.

Attribution: OWASP Top 10 (c) OWASP Foundation, licensed CC BY-SA 4.0
(https://creativecommons.org/licenses/by-sa/4.0/); source repository https://github.com/OWASP/Top10.
Records carry `source="owasp-top10"`, the canonical owasp.org URL and the license in `meta`.

The edition is chosen by the single constant OWASP_EDITION. OWASP/Top10 publishes no release tags
for these editions, so content is pinned to a commit SHA (OWASP_REF) instead.
"""

from __future__ import annotations

import re

import httpx

from viper.rag.sources import safe_get
from viper.rag.types import Document, IngestError

OWASP_EDITION = "2025"
OWASP_REF = "3a31f35346c3f4e90f350395124382fa53af2afe"  # pinned OWASP/Top10 commit
_RAW = f"https://raw.githubusercontent.com/OWASP/Top10/{OWASP_REF}/{OWASP_EDITION}/docs/en/"
_SITE = f"https://owasp.org/Top10/{OWASP_EDITION}/"
# Fixed list (no directory crawling): category id -> file stem. Update together with OWASP_EDITION.
CATEGORY_FILES: dict[str, str] = {
    "A01": "A01_2025-Broken_Access_Control",
    "A02": "A02_2025-Security_Misconfiguration",
    "A03": "A03_2025-Software_Supply_Chain_Failures",
    "A04": "A04_2025-Cryptographic_Failures",
    "A05": "A05_2025-Injection",
    "A06": "A06_2025-Insecure_Design",
    "A07": "A07_2025-Authentication_Failures",
    "A08": "A08_2025-Software_or_Data_Integrity_Failures",
    "A09": "A09_2025-Security_Logging_and_Alerting_Failures",
    "A10": "A10_2025-Mishandling_of_Exceptional_Conditions",
}
_ALLOWED_HOSTS = {"raw.githubusercontent.com"}
MAX_BYTES = 2 * 1024 * 1024  # per page; the largest is well under 100 KB
_LICENSE = "CC BY-SA 4.0"

# heading (lower-cased, trailing punctuation stripped) -> chunk name; other sections are dropped
_CHUNKS = {
    "background": "overview", "overview": "overview",
    "description": "description",
    "how to prevent": "prevention",
    "example attack scenarios": "scenarios",
}
_MAX_CHARS = 6000  # keeps a chunk well inside the embedder's context window


def fetch_owasp(client: httpx.Client | None = None) -> dict[str, str]:
    """Download each fixed category page: {category id: markdown}."""
    out: dict[str, str] = {}
    for cat, stem in CATEGORY_FILES.items():
        raw = safe_get(f"{_RAW}{stem}.md", _ALLOWED_HOSTS, MAX_BYTES, client, timeout=30.0)
        try:
            out[cat] = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IngestError(f"OWASP page {stem} is not UTF-8") from exc
    return out


def _clean(text: str) -> str:
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)(\{[^}]*\})?", "", text)  # images
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)  # links -> their text
    text = re.sub(r"<[^>]+>", " ", text)  # stray html
    return " ".join(text.replace("**", "").split())


def _sections(markdown: str) -> tuple[str, dict[str, list[str]]]:
    """(title, {chunk name: lines}) split on `##` headings, ignoring `#` lines inside code fences."""
    title, current, fenced = "", "", False
    sections: dict[str, list[str]] = {}
    for line in markdown.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced and line.startswith("# ") and not title:
            title = line[2:]
            continue
        elif not fenced and line.startswith("## "):
            key = line[3:].strip().rstrip(".:").strip().lower()
            current = _CHUNKS.get(key, "")
            continue
        if current:
            sections.setdefault(current, []).append(line)
    return title, sections


def parse_owasp(pages: dict[str, str], edition: str = OWASP_EDITION) -> list[Document]:
    """Chunk each category page by heading (overview / description / prevention / scenarios)."""
    if not pages:
        raise IngestError("no OWASP pages supplied")
    docs: dict[str, Document] = {}
    for cat, markdown in pages.items():
        title, sections = _sections(markdown)
        name = _clean(re.sub(r"\{:.*", "", title))
        if not re.match(r"^A\d{2}$", cat) or not name or not sections:
            raise IngestError(f"OWASP page {cat} has no recognizable title/sections")
        slug = CATEGORY_FILES.get(cat, "")
        url = f"{_SITE}{slug}/" if slug else _SITE
        for chunk, lines in sections.items():
            body = _clean("\n".join(lines))[:_MAX_CHARS]
            if not body:
                continue
            doc_id = f"owasp-top10:{edition}:{cat}:{chunk}"
            docs[doc_id] = Document(
                id=doc_id,
                text=f"OWASP Top 10 {edition} {name} - {chunk}. {body}",
                source="owasp-top10",
                url=url,
                title=f"{name} ({chunk})",
                meta={"edition": edition, "category": cat, "chunk": chunk,
                      "license": _LICENSE, "attribution": "OWASP Foundation, OWASP Top 10"},
            )
    if not docs:
        raise IngestError("OWASP pages contained no usable chunks")
    return list(docs.values())


class OwaspSource:
    name = "owasp-top10"

    def fetch(self) -> list[Document]:
        return parse_owasp(fetch_owasp())
