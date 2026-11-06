"""MITRE ATT&CK (Enterprise) connector: fetch the pinned STIX bundle, validate, normalize.

Attribution: MITRE ATT&CK(R) content (c) The MITRE Corporation, used under the ATT&CK Terms of Use
(https://attack.mitre.org/resources/terms-of-use/). Records keep the ATT&CK page URL.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

import httpx

from viper.rag.sources import safe_get
from viper.rag.types import Document, IngestError

ATTACK_TAG = "v20.1"  # pinned release of mitre-attack/attack-stix-data; bump deliberately
ATTACK_VERSION = "20.1"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"{quote(ATTACK_TAG)}/enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
_ALLOWED_HOSTS = {"raw.githubusercontent.com"}
MAX_BYTES = 70 * 1024 * 1024  # the 20.1 file is ~55 MB; cap leaves headroom but stops runaways
_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_CITATION_RE = re.compile(r"\(Citation: [^)]*\)")


def fetch_attack(url: str = ATTACK_URL, client: httpx.Client | None = None) -> dict[str, Any]:
    """Download the STIX bundle. Only https on raw.githubusercontent.com, size-capped."""
    raw = safe_get(url, _ALLOWED_HOSTS, MAX_BYTES, client)
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise IngestError(f"Could not parse ATT&CK bundle: {exc}") from exc
    if not isinstance(payload, dict):
        raise IngestError("ATT&CK bundle is not a JSON object")
    return payload


def _clean(text: object) -> str:
    return " ".join(_CITATION_RE.sub("", str(text or "")).split())


def parse_attack(payload: dict[str, Any]) -> list[Document]:
    """Validate the bundle and convert active techniques/sub-techniques to Documents."""
    objects = payload.get("objects")
    if payload.get("type") != "bundle" or not isinstance(objects, list) or not objects:
        raise IngestError("ATT&CK payload is not a STIX bundle with objects")

    docs: dict[str, Document] = {}  # keyed by id => duplicates collapse
    for o in objects:
        if not isinstance(o, dict) or o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in o.get("external_references", [])
                    if isinstance(r, dict) and r.get("source_name") == "mitre-attack"), None)
        tid = str((ref or {}).get("external_id", "")).strip().upper()
        url = str((ref or {}).get("url", ""))
        name = _clean(o.get("name"))
        if not _ID_RE.match(tid) or not url.startswith("https://") or not name:
            continue  # skip malformed records instead of storing junk
        tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                   if isinstance(p, dict) and p.get("kill_chain_name") == "mitre-attack"
                   and p.get("phase_name")]
        platforms = [str(p) for p in o.get("x_mitre_platforms", [])]
        text = (
            f"{tid} - {name}. Tactics: {', '.join(tactics) or 'n/a'}. "
            f"Platforms: {', '.join(platforms) or 'n/a'}. {_clean(o.get('description'))} "
            f"Detection: {_clean(o.get('x_mitre_detection')) or 'n/a'}"
        )
        docs[f"attack:{tid}"] = Document(
            id=f"attack:{tid}",
            text=" ".join(text.split()),
            source="mitre-attack",
            url=url,
            title=f"{tid} {name}",
            meta={"attack_version": o.get("x_mitre_version"), "tactics": tactics,
                  "subtechnique": "." in tid, "license": "MITRE ATT&CK Terms of Use"},
        )
    if not docs:
        raise IngestError("ATT&CK bundle contained no valid techniques")
    return list(docs.values())


class AttackSource:
    name = "attack"

    def fetch(self) -> list[Document]:
        return parse_attack(fetch_attack())
