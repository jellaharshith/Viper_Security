"""CISA Known Exploited Vulnerabilities (KEV) connector: fetch, validate, normalize."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from viper.rag.types import Document, IngestError

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
_ALLOWED_HOSTS = {"www.cisa.gov"}


def fetch_kev(url: str = KEV_URL, client: httpx.Client | None = None) -> dict[str, Any]:
    """Download the KEV feed. Only https on the official CISA host is accepted."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS:
        raise IngestError(f"Refusing to fetch KEV from untrusted URL: {url}")
    http = client or httpx.Client(timeout=60.0, follow_redirects=False)
    try:
        resp = http.get(url)
        resp.raise_for_status()
        payload = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise IngestError(f"Could not fetch/parse KEV feed: {exc}") from exc
    if not isinstance(payload, dict):
        raise IngestError("KEV feed is not a JSON object")
    return payload


def parse_kev(payload: dict[str, Any]) -> list[Document]:
    """Validate the feed schema and convert entries to normalized Documents."""
    entries = payload.get("vulnerabilities")
    version = payload.get("catalogVersion")
    if not isinstance(entries, list) or not entries or not version:
        raise IngestError("KEV feed missing 'vulnerabilities' or 'catalogVersion'")

    docs: dict[str, Document] = {}  # dict keyed by id => duplicates collapse
    for e in entries:
        cve = str(e.get("cveID", "")).strip().upper()
        if not cve.startswith("CVE-"):
            continue  # skip malformed records instead of storing junk
        text = (
            f"{cve} - {e.get('vulnerabilityName', '')}. "
            f"Affected: {e.get('vendorProject', '')} {e.get('product', '')}. "
            f"{e.get('shortDescription', '')} "
            f"Required action: {e.get('requiredAction', '')} "
            f"Added to KEV: {e.get('dateAdded', '')}; due {e.get('dueDate', '')}. "
            f"Known ransomware use: {e.get('knownRansomwareCampaignUse', 'Unknown')}."
        )
        docs[f"cisa-kev:{cve}"] = Document(
            id=f"cisa-kev:{cve}",
            text=" ".join(text.split()),
            source="CISA KEV",
            url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            title=f"{cve} {e.get('vulnerabilityName', '')}".strip(),
            meta={"catalog_version": version, "date_added": e.get("dateAdded"),
                  "feed": KEV_PAGE},
        )
    if not docs:
        raise IngestError("KEV feed contained no valid CVE records")
    return list(docs.values())
