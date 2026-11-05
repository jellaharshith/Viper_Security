"""Ingest + retrieve + grounded answer. Grounding is enforced in code, not trusted to the LLM."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from viper.rag.store import VectorStore
from viper.rag.types import Document, Embedder, Hit

UNVERIFIED_PREFIX = (
    "[No relevant knowledge-base sources found - the answer below comes from the model's own "
    "memory and is UNVERIFIED.]\n\n"
)

UNCITED_PREFIX = (
    "[Sources were retrieved but the answer cites none of them - treat the answer below as "
    "UNVERIFIED (model memory).]\n\n"
)

_NOT_IN_KEV = (
    "{ids} is not in the CISA KEV knowledge base. That does not mean it is safe or not exploited; "
    "KEV only lists vulnerabilities CISA has confirmed as exploited. Check NVD or the vendor advisory."
)

SYSTEM_GROUNDED = (
    "You are a cybersecurity assistant for authorized security work. Answer ONLY using the "
    "numbered sources provided. Cite each claim with its source number like [1]. If the sources "
    "do not contain the answer, say so. Never invent CVE details, versions, or sources."
)
SYSTEM_UNGROUNDED = (
    "You are a cybersecurity assistant for authorized security work. No reference sources are "
    "available for this question. Answer briefly, say when you are unsure, and do not cite "
    "sources or invent CVE details."
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


class ChatModel(Protocol):
    def chat(self, messages: list[dict[str, str]], temperature: float = ...) -> str: ...


@dataclass
class Answer:
    text: str
    grounded: bool
    sources: list[Hit] = field(default_factory=list)
    invalid_citations: list[int] = field(default_factory=list)


def ingest(docs: list[Document], embedder: Embedder, store: VectorStore, batch: int = 32) -> int:
    """Embed and store documents. Safe to re-run: ids are deterministic."""
    for i in range(0, len(docs), batch):
        chunk = docs[i : i + batch]
        store.upsert(chunk, embedder.embed([d.text for d in chunk]))
    return len(docs)


def _format_sources(hits: list[Hit]) -> str:
    return "\n".join(f"[{i}] ({h.document.source}) {h.document.text}" for i, h in enumerate(hits, 1))


def extract_cves(question: str) -> list[str]:
    """Distinct CVE ids mentioned in the question, upper-cased, in order."""
    return list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(question)))


def cited_numbers(text: str) -> set[int]:
    """Source numbers the answer cites, e.g. [1] or [Source: 2]."""
    return {int(m) for m in re.findall(r"\[(?:source:?\s*)?(\d+)\]", text, re.IGNORECASE)}


def check_citations(text: str, n_sources: int) -> list[int]:
    """Return cited numbers that do not correspond to a provided source."""
    return sorted(c for c in cited_numbers(text) if not 1 <= c <= n_sources)


def is_unverified(text: str) -> bool:
    """True when the answer carries one of the explicit UNVERIFIED labels."""
    return text.startswith((UNVERIFIED_PREFIX, UNCITED_PREFIX))


def answer(
    question: str,
    embedder: Embedder,
    store: VectorStore,
    llm: ChatModel,
    top_k: int = 4,
    min_score: float = 0.55,
) -> Answer:
    # Exact CVE ids are looked up directly: embeddings match meaning, not identifiers.
    cves = extract_cves(question)
    exact = store.get_many([f"cisa-kev:{c}" for c in cves])
    found = {d.id for d in exact}
    missing = [c for c in cves if f"cisa-kev:{c}" not in found]

    if cves and not exact:
        # Named CVE(s), none in the KB: say so deterministically; similar-sounding records are noise.
        return Answer(text=_NOT_IN_KEV.format(ids=", ".join(missing)), grounded=False)

    if cves:
        hits = [Hit(document=d, score=1.0) for d in exact]  # answer from the named records only
    else:
        qvec = embedder.embed([question])[0]
        hits = [h for h in store.search(qvec, top_k) if h.score >= min_score]

    if not hits:
        text = llm.chat([{"role": "system", "content": SYSTEM_UNGROUNDED},
                         {"role": "user", "content": question}])
        return Answer(text=UNVERIFIED_PREFIX + text, grounded=False)

    note = f"\nNote: {', '.join(missing)} is NOT in the CISA KEV catalog; say so.\n" if missing else ""
    prompt = f"Sources:\n{_format_sources(hits)}\n{note}\nQuestion: {question}"
    text = llm.chat([{"role": "system", "content": SYSTEM_GROUNDED},
                     {"role": "user", "content": prompt}])
    invalid = check_citations(text, len(hits))
    if not cves and not cited_numbers(text) - set(invalid):
        # Semantic hits only prove topical similarity, not that the model used them. If the answer
        # cites none, it is not grounded. (A named CVE is grounded by construction: the answer is
        # built from that exact record, and structured replies such as JSON have no room for [n].)
        return Answer(text=UNCITED_PREFIX + text, grounded=False, invalid_citations=invalid)
    return Answer(text=text, grounded=True, sources=hits, invalid_citations=invalid)
