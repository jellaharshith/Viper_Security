"""Knowledge sources: a common protocol plus a hardened HTTP helper shared by the connectors.

Every source's record ids start with `<name>:` so a failed source can be carried over from the
live collection by prefix (see `viper.rag.update.collect`).
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from urllib.parse import urlparse

import httpx

from viper.rag.cisa_kev import fetch_kev, parse_kev
from viper.rag.types import Document, IngestError


class Source(Protocol):
    name: str  # also the id prefix of every record this source produces

    def fetch(self) -> list[Document]: ...


class KevSource:
    """CISA Known Exploited Vulnerabilities (ids `cisa-kev:CVE-...`).

    KEV records are decorated with FIRST.org EPSS exploit-probability scores when reachable. EPSS is
    best-effort: if its API fails, the KEV records are returned unchanged (never block ingestion).
    """

    name = "cisa-kev"

    enrich_epss: bool = True

    def fetch(self) -> list[Document]:
        docs = parse_kev(fetch_kev())
        if not self.enrich_epss:
            return docs
        from viper.rag.epss import enrich_documents, fetch_epss_scores
        try:
            cves = [d.id.split(":", 1)[1] for d in docs]
            scores = fetch_epss_scores(cves)
            return enrich_documents(docs, scores)
        except IngestError:
            return docs  # EPSS unreachable/invalid: KEV stands on its own


def safe_get(
    url: str,
    allowed_hosts: Collection[str],
    max_bytes: int,
    client: httpx.Client | None = None,
    timeout: float = 120.0,
) -> bytes:
    """GET over https from an allow-listed host only: no redirects, hard size cap while streaming."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
        raise IngestError(f"Refusing to fetch from untrusted URL: {url}")
    http = client or httpx.Client(timeout=timeout, follow_redirects=False)
    try:
        with http.stream("GET", url) as resp:
            resp.raise_for_status()
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise IngestError(f"Download too large ({declared} bytes > {max_bytes}): {url}")
            buf = bytearray()
            for chunk in resp.iter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise IngestError(f"Download exceeded {max_bytes} bytes: {url}")
    except httpx.HTTPError as exc:
        raise IngestError(f"Could not fetch {url}: {exc}") from exc
    return bytes(buf)


def all_sources() -> list[Source]:
    """The sources a full `kb update` covers."""
    from viper.rag.attack import AttackSource
    from viper.rag.cwe import CweSource
    from viper.rag.owasp import OwaspSource

    return [KevSource(), AttackSource(), OwaspSource(), CweSource()]
