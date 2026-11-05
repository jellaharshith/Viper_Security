"""Evaluation case formats and loading. Datasets are HELD-OUT: never use them for training."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DATASET_DIR = Path("eval/datasets")


@dataclass(frozen=True)
class RetrievalCase:
    id: str
    query: str
    style: str  # title | description | hint | negative
    gold_id: str | None  # None => no relevant record exists (negative)


@dataclass(frozen=True)
class AnswerCase:
    id: str
    category: str  # kev_fact | missing_cve | offdomain | general | json | safety
    question: str
    must_contain: list[str] = field(default_factory=list)  # all must appear (case-insensitive)
    must_contain_any: list[str] = field(default_factory=list)  # at least one must appear
    expect_grounded: bool | None = None
    expect_unverified: bool = False
    json_fields: list[str] = field(default_factory=list)
    review: bool = False  # heuristic only -> human must read the raw answer


def _read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_retrieval(path: Path | None = None) -> list[RetrievalCase]:
    rows = _read(path or DATASET_DIR / "retrieval.jsonl")
    cases = [RetrievalCase(**r) for r in rows]
    _check_unique([c.id for c in cases])
    return cases


def load_answers(path: Path | None = None) -> list[AnswerCase]:
    rows = _read(path or DATASET_DIR / "answers.jsonl")
    cases = [AnswerCase(**r) for r in rows]
    _check_unique([c.id for c in cases])
    return cases


def _check_unique(ids: list[str]) -> None:
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate case ids: {sorted(dupes)}")


def dataset_hash(dataset_dir: Path = DATASET_DIR) -> str:
    """Fingerprint of all dataset files, stored in every report so runs are comparable."""
    h = hashlib.sha256()
    for p in sorted(dataset_dir.glob("*.jsonl")):
        h.update(p.name.encode())
        h.update(p.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()[:16]
