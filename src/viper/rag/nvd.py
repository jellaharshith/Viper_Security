"""National Vulnerability Database (NVD) CVE API 2.0 connector.

Bounded by design: the full NVD corpus is 250k+ records and would add retrieval noise (see
docs/v1-scope.md 3.5), so this connector is meant for high-signal slices -- CVEs already in CISA KEV,
or a recent high-severity window -- never a full dump. Callers pass an NVD query via `params`.

Exploit availability is derived from NVD's own reference tags ("Exploit"), which fold in the
ExploitDB/PoC signal without indexing a second, noisier corpus. An optional NVD API key (read from
the user's own env, no VIPER_ prefix) raises the rate limit; the connector works without one.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import httpx

from viper.rag.types import Document, IngestError

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"
_ALLOWED_HOSTS = {"services.nvd.nist.gov"}
_RESULTS_PER_PAGE = 2000  # NVD's maximum page size
_MAX_PAGES = 200  # hard stop so a bad totalResults can never loop forever
_MAX_CHARS = 6000


def _english(items: list[dict[str, Any]]) -> str:
    for item in items:
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value", "")).strip()
    return ""


def fetch_nvd(
    params: dict[str, str],
    url: str = NVD_URL,
    api_key: str | None = None,
    client: httpx.Client | None = None,
) -> list[dict[str, Any]]:
    """Fetch every page of an NVD query and return the combined `vulnerabilities` list."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS:
        raise IngestError(f"Refusing to fetch NVD from untrusted URL: {url}")
    http = client or httpx.Client(timeout=60.0, follow_redirects=False)
    headers = {"apiKey": api_key} if api_key else {}
    vulns: list[dict[str, Any]] = []
    start = 0
    for _ in range(_MAX_PAGES):
        query = {**params, "resultsPerPage": str(_RESULTS_PER_PAGE), "startIndex": str(start)}
        try:
            resp = http.get(url, params=query, headers=headers)
            resp.raise_for_status()
            payload = json.loads(resp.content)
        except (httpx.HTTPError, ValueError) as exc:
            raise IngestError(f"Could not fetch/parse NVD feed: {exc}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise IngestError("NVD response missing 'vulnerabilities' list")
        page = payload["vulnerabilities"]
        vulns.extend(v for v in page if isinstance(v, dict))
        total = int(payload.get("totalResults", 0))
        per = int(payload.get("resultsPerPage", 0)) or len(page)
        start += per
        if start >= total or not page:
            break
    return vulns


def _cvss(metrics: dict[str, Any]) -> tuple[float | None, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            data = entries[0].get("cvssData", {}) if isinstance(entries[0], dict) else {}
            try:
                score = float(str(data.get("baseScore")))
            except (TypeError, ValueError):
                score = None
            severity = str(data.get("baseSeverity", "")).strip().upper()
            return score, severity
    return None, ""


def parse_nvd(vulnerabilities: list[dict[str, Any]]) -> list[Document]:
    """Convert NVD `vulnerabilities` entries to Documents (ids `nvd:CVE-...`)."""
    docs: dict[str, Document] = {}
    for item in vulnerabilities:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("id", "")).strip().upper()
        description = _english(cve.get("descriptions", []) or [])
        if not cve_id.startswith("CVE-") or not description:
            continue  # skip malformed instead of storing junk
        score, severity = _cvss(cve.get("metrics", {}) or {})
        cwes = sorted({
            v.strip().upper()
            for w in cve.get("weaknesses", []) or []
            for d in (w.get("description", []) if isinstance(w, dict) else [])
            if isinstance(d, dict) and (v := str(d.get("value", ""))).upper().startswith("CWE-")
        })
        exploit_refs = [
            str(r.get("url", ""))
            for r in cve.get("references", []) or []
            if isinstance(r, dict) and "Exploit" in (r.get("tags") or [])
        ]
        cvss_phrase = f" CVSS {score:.1f} {severity}." if score is not None else ""
        cwe_phrase = f" Weaknesses: {', '.join(cwes)}." if cwes else ""
        text = f"{cve_id} - {description}{cvss_phrase}{cwe_phrase}"
        docs[f"nvd:{cve_id}"] = Document(
            id=f"nvd:{cve_id}",
            text=" ".join(text.split())[:_MAX_CHARS],
            source="nvd",
            url=f"{NVD_DETAIL}{cve_id}",
            title=f"{cve_id} (NVD)",
            meta={
                "cvss_score": score,
                "cvss_severity": severity,
                "cwe": cwes,
                "exploit_refs": exploit_refs,
                "license": "NVD / NIST (U.S. government work, public domain)",
            },
        )
    if not docs:
        raise IngestError("NVD feed contained no valid CVE records")
    return list(docs.values())


class NvdSource:
    """Bounded NVD source. Default: recent high/critical CVEs. NOT in the default `all_sources()`
    (NVD is slow and rate-limited); wire it in deliberately via `kb update --with-nvd`.
    """

    name = "nvd"

    def __init__(self, params: dict[str, str] | None = None, api_key: str | None = None) -> None:
        self.params = params or {"cvssV3Severity": "CRITICAL"}
        self.api_key = api_key

    def fetch(self) -> list[Document]:
        return parse_nvd(fetch_nvd(self.params, api_key=self.api_key))
