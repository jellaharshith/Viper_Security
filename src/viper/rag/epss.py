"""FIRST.org EPSS enrichment: decorate existing CISA KEV records with exploit-probability scores.

EPSS (Exploit Prediction Scoring System, https://www.first.org/epss/) is a free, no-key API. This
module adds no new documents: it looks up the EPSS score for CVEs already in the knowledge base and
folds the score into those records' text and meta, so retrieval stays clean (no record-count growth)
while answers gain an "how likely is this to be exploited" signal.
"""

from __future__ import annotations

import json
from dataclasses import replace

import httpx

from viper.rag.sources import safe_get
from viper.rag.types import Document, IngestError

EPSS_URL = "https://api.first.org/data/v1/epss"
_ALLOWED_HOSTS = {"api.first.org"}
MAX_BYTES = 8 * 1024 * 1024  # a 100-CVE batch response is a few KB; cap stops runaways
_BATCH = 100  # keep the ?cve= query string well under any URL length limit


def fetch_epss_scores(
    cves: list[str],
    url: str = EPSS_URL,
    client: httpx.Client | None = None,
    batch: int = _BATCH,
) -> dict[str, tuple[float, float]]:
    """Return {CVE: (epss, percentile)} for the given CVEs, batched. Best-effort per record."""
    out: dict[str, tuple[float, float]] = {}
    unique = sorted({c.strip().upper() for c in cves if c.strip()})
    for i in range(0, len(unique), max(1, batch)):
        chunk = unique[i : i + max(1, batch)]
        raw = safe_get(f"{url}?cve={','.join(chunk)}", _ALLOWED_HOSTS, MAX_BYTES, client, timeout=60.0)
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise IngestError(f"Could not parse EPSS response: {exc}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise IngestError("EPSS response missing 'data' list")
        for row in payload["data"]:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve", "")).strip().upper()
            try:
                epss = float(str(row.get("epss")))
                percentile = float(str(row.get("percentile")))
            except (TypeError, ValueError):
                continue  # skip malformed row, keep the rest
            if cve.startswith("CVE-"):
                out[cve] = (epss, percentile)
    return out


def _cve_of(doc: Document) -> str | None:
    if not doc.id.startswith("cisa-kev:"):
        return None
    return doc.id.split(":", 1)[1].upper()


def enrich_documents(docs: list[Document], scores: dict[str, tuple[float, float]]) -> list[Document]:
    """Return docs with EPSS folded into matching KEV records; every other record is unchanged."""
    out: list[Document] = []
    for doc in docs:
        cve = _cve_of(doc)
        score = scores.get(cve) if cve else None
        if score is None:
            out.append(doc)
            continue
        epss, percentile = score
        note = f"EPSS exploit probability: {epss:.3f} ({percentile:.1%} percentile)."
        out.append(replace(
            doc,
            text=f"{doc.text} {note}".strip(),
            meta={**doc.meta, "epss": epss, "epss_percentile": percentile},
        ))
    return out
