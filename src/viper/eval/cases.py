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
    style: str  # title | description | hint | negative | technique | category | prevention | scenarios
    gold_id: str | None  # None => no relevant record exists (negative)


@dataclass(frozen=True)
class AnswerCase:
    id: str
    category: str  # kev_fact | missing_cve | offdomain | general | json | safety | kev_natural | definition
    question: str
    must_contain: list[str] = field(default_factory=list)  # all must appear (case-insensitive)
    must_contain_any: list[str] = field(default_factory=list)  # at least one must appear
    expect_grounded: bool | None = None
    expect_unverified: bool = False
    json_fields: list[str] = field(default_factory=list)
    review: bool = False  # heuristic only -> human must read the raw answer
    review_reason: str | None = None


def _read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _parse_answer_case(r: dict[str, Any]) -> AnswerCase:
    d = dict(r)
    rev = d.get("review", False)
    if isinstance(rev, str):
        d["review"] = True
        d["review_reason"] = rev
    elif rev:
        d["review"] = True
    else:
        d["review"] = False
    return AnswerCase(**d)


def load_retrieval(path: Path | None = None) -> list[RetrievalCase]:
    rows = _read(path or DATASET_DIR / "retrieval.jsonl")
    cases = [RetrievalCase(**r) for r in rows]
    _check_unique([c.id for c in cases])
    return cases


def load_retrieval_attack_owasp(path: Path | None = None) -> list[RetrievalCase]:
    rows = _read(path or DATASET_DIR / "retrieval_attack_owasp.jsonl")
    cases = [RetrievalCase(**r) for r in rows]
    _check_unique([c.id for c in cases])
    return cases


def load_retrieval_all(dataset_dir: Path = DATASET_DIR) -> list[RetrievalCase]:
    """Load both v1 retrieval.jsonl and retrieval_attack_owasp.jsonl into a unified collection."""
    cases: list[RetrievalCase] = []
    for name in ("retrieval.jsonl", "retrieval_attack_owasp.jsonl"):
        p = dataset_dir / name
        if p.exists():
            cases.extend([RetrievalCase(**r) for r in _read(p)])
    _check_unique([c.id for c in cases])
    return cases


def load_answers(path: Path | None = None) -> list[AnswerCase]:
    rows = _read(path or DATASET_DIR / "answers.jsonl")
    cases = [_parse_answer_case(r) for r in rows]
    _check_unique([c.id for c in cases])
    return cases


def load_answers_v2(path: Path | None = None) -> list[AnswerCase]:
    rows = _read(path or DATASET_DIR / "answers_v2.jsonl")
    cases = [_parse_answer_case(r) for r in rows]
    _check_unique([c.id for c in cases])
    return cases


def case_source(case: RetrievalCase) -> str | None:
    """Identify the source (cisa-kev, mitre-attack, owasp-top10) from the gold_id."""
    if not case.gold_id:
        return None
    prefix = case.gold_id.split(":", 1)[0]
    if prefix in ("attack", "mitre-attack"):
        return "mitre-attack"
    if prefix in ("owasp", "owasp-top10"):
        return "owasp-top10"
    if prefix in ("cisa", "cisa-kev"):
        return "cisa-kev"
    return prefix


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
