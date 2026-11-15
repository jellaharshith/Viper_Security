"""MITRE CWE (Common Weakness Enumeration) connector: fetch the pinned XML zip, validate, normalize.

Attribution: CWE(TM) content (c) The MITRE Corporation, used under the CWE Terms of Use
(https://cwe.mitre.org/about/termsofuse.html). Records keep the canonical CWE definition URL.

CWE is a bounded taxonomy (~960 active weaknesses), unlike NVD, so the whole active catalog is
high-signal and safe to index. The release is pinned by CWE_VERSION; bump it deliberately.
"""

from __future__ import annotations

import io
import zipfile
from xml.etree.ElementTree import Element  # type only; parsing uses defusedxml

import defusedxml.ElementTree as DET
import httpx

from viper.rag.sources import safe_get
from viper.rag.types import Document, IngestError

CWE_VERSION = "4.17"  # pinned CWE release; bump deliberately
CWE_URL = f"https://cwe.mitre.org/data/xml/cwec_v{CWE_VERSION}.xml.zip"
_ALLOWED_HOSTS = {"cwe.mitre.org"}
MAX_BYTES = 20 * 1024 * 1024  # the zip is ~3 MB; cap leaves headroom but stops runaways
_LICENSE = "CWE Terms of Use (MITRE)"
_SKIP_STATUS = {"deprecated", "obsolete"}
_MAX_CHARS = 6000  # keep a record well inside the embedder's context window


def _local(tag: str) -> str:
    """Strip the XML namespace so we can match on local element names."""
    return tag.rsplit("}", 1)[-1]


def fetch_cwe(url: str = CWE_URL, client: httpx.Client | None = None) -> str:
    """Download the pinned CWE zip (https + cwe.mitre.org only, size-capped) and return its XML."""
    raw = safe_get(url, _ALLOWED_HOSTS, MAX_BYTES, client)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
            if not names:
                raise IngestError("CWE zip contains no .xml entry")
            data = zf.read(names[0])
    except (zipfile.BadZipFile, OSError) as exc:
        raise IngestError(f"Could not open CWE zip: {exc}") from exc
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IngestError("CWE XML is not UTF-8") from exc


def _text_of(weakness: Element, local_name: str) -> str:
    child = next((c for c in weakness if _local(c.tag) == local_name), None)
    if child is None:
        return ""
    return " ".join("".join(child.itertext()).split())


def _consequences(weakness: Element) -> list[str]:
    block = next((c for c in weakness if _local(c.tag) == "Common_Consequences"), None)
    if block is None:
        return []
    out: list[str] = []
    for cons in block:
        scopes = [" ".join(e.itertext()).strip() for e in cons if _local(e.tag) == "Scope"]
        impacts = [" ".join(e.itertext()).strip() for e in cons if _local(e.tag) == "Impact"]
        if scopes or impacts:
            out.append(f"{'/'.join(scopes) or 'n/a'}: {', '.join(impacts) or 'n/a'}")
    return out


def _weakness_text(name: str, description: str, extended: str, consequences: list[str]) -> str:
    """Compose the retrievable passage body for one CWE weakness.

    Design decision (retrieval quality): the embedded text is what similarity search matches on.
    Folding in more fields (extended description, consequences) adds recall for nuanced queries but
    can dilute the vector for short definition queries like "what is XSS". Decide the balance.

    `description` is the short definition; `extended` is the long-form prose (may be ""); each entry
    of `consequences` is already formatted "Scope: Impact1, Impact2". Return one clean string
    (the caller prefixes "CWE-<n> - <name>." and truncates to _MAX_CHARS).

    Composition: lead with the short definition so a bare "what is X" query matches strongly, then
    append the extended prose and a single compact consequences clause. Each later field adds recall
    for nuanced queries without displacing the definition signal that sits first in the vector.
    """
    parts = [description.strip()]
    if extended.strip():
        parts.append(extended.strip())
    if consequences:
        parts.append("Consequences - " + "; ".join(consequences) + ".")
    return " ".join(p for p in parts if p)


def parse_cwe(xml_text: str) -> list[Document]:
    """Validate the catalog and convert active weaknesses to Documents (one per CWE)."""
    try:
        root = DET.fromstring(xml_text)
    except DET.ParseError as exc:
        raise IngestError(f"Could not parse CWE XML: {exc}") from exc
    if _local(root.tag) != "Weakness_Catalog":
        raise IngestError("CWE payload is not a Weakness_Catalog")

    docs: dict[str, Document] = {}  # keyed by id => duplicates collapse
    for container in root:
        if _local(container.tag) != "Weaknesses":
            continue
        for w in container:
            if _local(w.tag) != "Weakness":
                continue
            num = (w.get("ID") or "").strip()
            name = (w.get("Name") or "").strip()
            status = (w.get("Status") or "").strip().lower()
            if not num.isdigit() or not name or status in _SKIP_STATUS:
                continue  # skip malformed / deprecated instead of storing junk
            abstraction = (w.get("Abstraction") or "").strip()
            description = _text_of(w, "Description")
            extended = _text_of(w, "Extended_Description")
            consequences = _consequences(w)
            body = _weakness_text(name, description, extended, consequences)
            text = f"CWE-{num} - {name}. {body}".strip()
            doc_id = f"cwe:CWE-{num}"
            docs[doc_id] = Document(
                id=doc_id,
                text=" ".join(text.split())[:_MAX_CHARS],
                source="cwe",
                url=f"https://cwe.mitre.org/data/definitions/{num}.html",
                title=f"CWE-{num}: {name}",
                meta={
                    "cwe_version": CWE_VERSION,
                    "abstraction": abstraction,
                    "status": status,
                    "license": _LICENSE,
                    "attribution": "The MITRE Corporation, CWE",
                },
            )
    if not docs:
        raise IngestError("CWE catalog contained no active weaknesses")
    return list(docs.values())


class CweSource:
    name = "cwe"

    def fetch(self) -> list[Document]:
        return parse_cwe(fetch_cwe())

