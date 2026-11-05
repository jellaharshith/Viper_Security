"""Safe knowledge-base update: fetch -> validate -> stage -> gate -> promote (or reject).

A live index is never modified in place. A new versioned collection is built beside it, must pass
every gate, and only then does the registry pointer move. Rollback moves it back.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from viper.rag.store import VectorStore
from viper.rag.types import Document, Embedder


def content_hash(doc: Document) -> str:
    h = hashlib.sha256()
    for part in (doc.id, doc.title, doc.url, doc.source, doc.text):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


@dataclass
class UpdateReport:
    source: str
    started: str
    active_before: str | None
    staged: str
    fetched: int = 0
    reused: int = 0
    embedded: int = 0
    removed: int = 0
    problems: list[str] = field(default_factory=list)
    recall_at_4_staged: float | None = None
    recall_at_4_active: float | None = None
    promoted: bool = False
    decision: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate(docs: list[Document], active_count: int, max_shrink: float) -> list[str]:
    """Cheap structural checks that catch a truncated or broken feed before anything is embedded."""
    problems: list[str] = []
    if not docs:
        return ["feed produced no records"]
    ids = [d.id for d in docs]
    if len(set(ids)) != len(ids):
        problems.append("duplicate document ids in feed")
    if any(not d.text.strip() or not d.url.startswith("https://") for d in docs):
        problems.append("records with empty text or non-https url")
    if active_count and len(docs) < active_count * (1 - max_shrink):
        problems.append(
            f"feed shrank from {active_count} to {len(docs)} records (> {max_shrink:.0%}); "
            "likely truncated"
        )
    return problems


def stage(
    docs: list[Document], doc_embedder: Embedder, active: VectorStore, staging: VectorStore
) -> tuple[int, int, int]:
    """Build the staging collection. Unchanged records reuse their stored vector (no re-embedding).

    Returns (reused, embedded, removed)."""
    old = {d.id: (d, v) for d, v in active.export()}
    keep_docs: list[Document] = []
    keep_vecs: list[list[float]] = []
    todo: list[Document] = []
    for d in docs:
        prev = old.get(d.id)
        if prev and content_hash(prev[0]) == content_hash(d):
            keep_docs.append(d)
            keep_vecs.append(prev[1])
        else:
            todo.append(d)
    if keep_docs:
        staging.upsert(keep_docs, keep_vecs)
    for i in range(0, len(todo), 32):
        chunk = todo[i : i + 32]
        staging.upsert(chunk, doc_embedder.embed([d.text for d in chunk]))
    removed = len(set(old) - {d.id for d in docs})
    return len(keep_docs), len(todo), removed


def run_update(
    *,
    source: str,
    docs: list[Document],
    doc_embedder: Embedder,
    active: VectorStore,
    staging: VectorStore,
    recall_at_4: Callable[[VectorStore], float],
    min_recall: float,
    max_shrink: float,
    promote: Callable[[str], None] | None,
) -> UpdateReport:
    """Run the full gated update. `promote` is called only if every gate passes (None = dry run)."""
    rep = UpdateReport(
        source=source,
        started=datetime.now(UTC).isoformat(timespec="seconds"),
        active_before=active.collection,
        staged=staging.collection,
        fetched=len(docs),
    )
    rep.problems = validate(docs, active.count(), max_shrink)
    if rep.problems:
        rep.decision = "REJECTED: validation failed (nothing staged)"
        return rep
    try:
        rep.reused, rep.embedded, rep.removed = stage(docs, doc_embedder, active, staging)
        rep.recall_at_4_staged = recall_at_4(staging)
        rep.recall_at_4_active = recall_at_4(active)
    except Exception:
        staging.drop()  # never leave a half-built collection around
        raise
    # Gate: staged must clear the floor AND not be meaningfully worse than what is live.
    if rep.recall_at_4_staged < min_recall:
        rep.problems.append(f"recall@4 {rep.recall_at_4_staged:.3f} below floor {min_recall:.2f}")
    if rep.recall_at_4_staged < (rep.recall_at_4_active or 0) - 0.02:
        rep.problems.append(
            f"recall@4 regressed {rep.recall_at_4_active:.3f} -> {rep.recall_at_4_staged:.3f}"
        )
    if rep.problems:
        staging.drop()
        rep.decision = "REJECTED: quality gate failed (live index unchanged)"
        return rep
    if promote is None:
        rep.decision = "PASSED gates; not promoted (dry run). Staged collection kept."
        return rep
    promote(staging.collection)
    rep.promoted = True
    rep.decision = "PROMOTED"
    return rep
