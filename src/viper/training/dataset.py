"""Build a QLoRA instruction-tuning dataset from permission-cleared public KB sources.

Safety invariant (M4 gate, docs/plans/m4-qlora-gate.md and docs/model-evaluation-plan.md): training
data is drawn ONLY from the knowledge-base corpus and NEVER from the held-out evaluation datasets.
``HeldOutGuard`` enforces this two ways: it drops any KB document that is a retrieval gold record,
and ``write_dataset`` refuses to emit any example whose instruction matches an eval question or
retrieval query verbatim. A training run that cannot prove this disjointness must not happen.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from viper.eval.cases import DATASET_DIR
from viper.rag.types import Document


class TrainingDataError(RuntimeError):
    """A training example overlapped the held-out eval set, or the dataset failed validation."""


def _norm(text: str) -> str:
    return " ".join(text.split()).strip().lower()


@dataclass(frozen=True)
class HeldOutGuard:
    """The eval content training must never touch: gold record ids and verbatim questions."""

    gold_ids: frozenset[str] = field(default_factory=frozenset)
    questions: frozenset[str] = field(default_factory=frozenset)  # normalized

    @classmethod
    def from_dir(cls, dataset_dir: Path = DATASET_DIR) -> HeldOutGuard:
        gold: set[str] = set()
        questions: set[str] = set()
        for path in sorted(Path(dataset_dir).glob("*.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    continue
                gid = row.get("gold_id")
                if isinstance(gid, str) and gid:
                    gold.add(gid)
                for key in ("query", "question"):
                    val = row.get(key)
                    if isinstance(val, str) and val.strip():
                        questions.add(_norm(val))
        return cls(gold_ids=frozenset(gold), questions=frozenset(questions))

    def forbids_doc(self, doc: Document) -> bool:
        return doc.id in self.gold_ids

    def forbids_instruction(self, instruction: str) -> bool:
        return _norm(instruction) in self.questions


def build_examples(
    docs: list[Document], *, guard: HeldOutGuard | None = None
) -> list[dict[str, str]]:
    """Turn KB documents into instruction/output pairs, skipping any held-out gold record.

    Each example is grounded in one source record, so the model learns to answer from the corpus
    it will also retrieve at inference time. ``source_id`` is kept for traceability/auditing.
    """
    guard = guard or HeldOutGuard()
    examples: list[dict[str, str]] = []
    for doc in docs:
        if guard.forbids_doc(doc):
            continue  # this record is a held-out retrieval gold answer: never train on it
        title = doc.title.strip() or doc.id
        instruction = f"Explain the following security topic: {title}"
        output = doc.text.strip()
        if not output or guard.forbids_instruction(instruction):
            continue
        examples.append({
            "instruction": instruction,
            "input": "",
            "output": output,
            "source_id": doc.id,
            "source_url": doc.url,
        })
    return examples


def write_dataset(
    examples: list[dict[str, str]], out_path: Path, *, guard: HeldOutGuard | None = None
) -> int:
    """Validate disjointness from the held-out set, then write JSONL. Returns rows written."""
    guard = guard or HeldOutGuard()
    for ex in examples:
        instruction = ex.get("instruction", "")
        if guard.forbids_instruction(instruction):
            raise TrainingDataError(
                f"training example reproduces a held-out eval question: {instruction!r}")
        if ex.get("source_id") in guard.gold_ids:
            raise TrainingDataError(
                f"training example uses a held-out gold record: {ex.get('source_id')!r}")
        if not ex.get("output", "").strip():
            raise TrainingDataError("training example has empty output")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        "\n".join(json.dumps(ex, ensure_ascii=False) for ex in examples) + ("\n" if examples else ""),
        encoding="utf-8", newline="\n")
    return len(examples)
