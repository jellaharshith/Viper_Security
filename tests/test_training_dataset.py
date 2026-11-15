import json
from pathlib import Path

import pytest

from viper.rag.types import Document
from viper.training.dataset import (
    HeldOutGuard,
    TrainingDataError,
    build_examples,
    write_dataset,
)


def _docs() -> list[Document]:
    return [
        Document(id="cwe:CWE-79", text="CWE-79 - XSS. Neutralize input.", source="cwe",
                 url="https://cwe.mitre.org/data/definitions/79.html", title="CWE-79: XSS"),
        Document(id="attack:T1059", text="T1059 - Command interpreter.", source="mitre-attack",
                 url="https://attack.mitre.org/techniques/T1059", title="T1059 Command"),
    ]


def _eval_dir(tmp_path: Path) -> Path:
    d = tmp_path / "datasets"
    d.mkdir()
    (d / "retrieval.jsonl").write_text(
        json.dumps({"id": "r0", "query": "What is XSS?", "style": "title", "gold_id": "cwe:CWE-79"})
        + "\n", encoding="utf-8")
    (d / "answers.jsonl").write_text(
        json.dumps({"id": "a0", "category": "general", "question": "What does SQL stand for?"})
        + "\n", encoding="utf-8")
    return d


def test_guard_excludes_docs_that_are_eval_gold_records(tmp_path: Path) -> None:
    guard = HeldOutGuard.from_dir(_eval_dir(tmp_path))
    assert "cwe:CWE-79" in guard.gold_ids  # it is a retrieval gold record
    examples = build_examples(_docs(), guard=guard)
    used_ids = {e["source_id"] for e in examples}
    assert "cwe:CWE-79" not in used_ids  # excluded from training
    assert "attack:T1059" in used_ids  # safe to train on


def test_write_dataset_refuses_an_eval_question_verbatim(tmp_path: Path) -> None:
    guard = HeldOutGuard.from_dir(_eval_dir(tmp_path))
    poisoned = [{"instruction": "What does SQL stand for?", "input": "", "output": "SQL.",
                 "source_id": "x:1"}]
    with pytest.raises(TrainingDataError):
        write_dataset(poisoned, tmp_path / "train.jsonl", guard=guard)


def test_write_dataset_happy_path(tmp_path: Path) -> None:
    guard = HeldOutGuard.from_dir(_eval_dir(tmp_path))
    examples = build_examples(_docs(), guard=guard)
    n = write_dataset(examples, tmp_path / "train.jsonl", guard=guard)
    assert n == len(examples) >= 1
    rows = [json.loads(ln) for ln in (tmp_path / "train.jsonl").read_text().splitlines() if ln.strip()]
    assert all({"instruction", "output"} <= set(r) for r in rows)
