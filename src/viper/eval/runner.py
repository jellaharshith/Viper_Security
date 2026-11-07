"""Run the evaluation, save a comparable JSON report, and compare two reports."""

from __future__ import annotations

import json
import re
import subprocess  # noqa: S404 (fixed git command, no user input)
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from viper.config import Settings
from viper.eval.answers import CaseResult, check_case, summarize, timed
from viper.eval.cases import (
    RetrievalCase,
    case_source,
    dataset_hash,
    load_answers,
    load_answers_v2,
    load_retrieval,
    load_retrieval_all,
)
from viper.eval.retrieval import evaluate_retrieval
from viper.llm import OllamaClient
from viper.rag import answer
from viper.rag.backend import active_collection, open_store
from viper.rag.embedding import PrefixEmbedder
from viper.rag.types import Embedder, Store

RESULTS_DIR = Path("eval/results")


def _git_commit() -> str:
    try:
        out = subprocess.run(  # noqa: S603
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def evaluate_retrieval_per_source(
    cases: list[RetrievalCase],
    embedder: Embedder,
    store: Store,
    top_k: int = 10,
    batch: int = 16,
) -> dict[str, dict[str, float]]:
    """Partition retrieval cases by source and compute per-source recall metrics."""
    by_src: dict[str, list[RetrievalCase]] = defaultdict(list)
    for c in cases:
        src = case_source(c)
        if src is not None:
            by_src[src].append(c)

    out: dict[str, dict[str, float]] = {}
    for src, src_cases in sorted(by_src.items()):
        ranks: list[int | None] = []
        for i in range(0, len(src_cases), batch):
            chunk = src_cases[i : i + batch]
            vectors = embedder.embed([c.query for c in chunk])
            for case, vec in zip(chunk, vectors, strict=True):
                hits = store.search(vec, top_k)
                rank = next((r for r, h in enumerate(hits, 1) if h.document.id == case.gold_id), None)
                ranks.append(rank)
        n = len(ranks) or 1
        out[src] = {
            "n": float(len(ranks)),
            "recall@1": sum(1 for r in ranks if r == 1) / n,
            "recall@4": sum(1 for r in ranks if r and r <= 4) / n,
            "recall@10": sum(1 for r in ranks if r) / n,
            "mrr": sum(1 / r for r in ranks if r) / n,
        }
    return out


def check_recall_gate(
    store: Store,
    embedder: Embedder,
    cases: list[RetrievalCase] | None = None,
    min_recall: float = 0.95,
    per_source_floors: dict[str, float] | None = None,
) -> tuple[bool, dict[str, float], list[str]]:
    """Quality gate for KB update: verifies overall and per-source recall@4 clear specified floors.

    Returns (passed, scores_dict, problems_list).
    """
    eval_cases = cases if cases is not None else load_retrieval_all()
    by_src = evaluate_retrieval_per_source(eval_cases, embedder, store)
    scores: dict[str, float] = {}
    problems: list[str] = []

    pos_cases = [c for c in eval_cases if c.gold_id is not None]
    if pos_cases:
        hit_count = 0
        for i in range(0, len(pos_cases), 16):
            chunk = pos_cases[i : i + 16]
            vectors = embedder.embed([c.query for c in chunk])
            for c, vec in zip(chunk, vectors, strict=True):
                hits = store.search(vec, 4)
                if any(h.document.id == c.gold_id for h in hits):
                    hit_count += 1
        overall_recall = hit_count / len(pos_cases)
        scores["overall"] = round(overall_recall, 4)
        if overall_recall < min_recall:
            problems.append(f"overall recall@4 {overall_recall:.3f} below floor {min_recall:.2f}")

    floors = per_source_floors or {}
    for src, metrics in by_src.items():
        r4 = round(metrics.get("recall@4", 0.0), 4)
        scores[src] = r4
        floor = floors.get(src, min_recall)
        if r4 < floor:
            problems.append(f"{src} recall@4 {r4:.3f} below floor {floor:.2f}")

    return (len(problems) == 0, scores, problems)


def make_recall_gate(
    embedder: Embedder,
    cases: list[RetrievalCase] | None = None,
    min_recall: float = 0.95,
    per_source_floors: dict[str, float] | None = None,
) -> Callable[[Store], float]:
    """Callable for run_update's recall_at_4 argument that checks per-source recall floors."""
    def _gate(store: Store) -> float:
        passed, scores, _ = check_recall_gate(
            store, embedder, cases=cases, min_recall=min_recall, per_source_floors=per_source_floors
        )
        if not passed:
            return min(scores.values()) if scores else 0.0
        return scores.get("overall", 1.0)
    return _gate


def run_eval(
    settings: Settings,
    tag: str,
    skip_llm: bool = False,
    only: set[str] | None = None,
    dataset_version: str = "v1",
) -> dict[str, Any]:
    llm = OllamaClient(settings.ollama_host, settings.ollama_model, settings.embed_model)
    qembed = PrefixEmbedder(llm, settings.embed_query_prefix)
    store = open_store(settings, active_collection(settings))
    if dataset_version == "v2":
        ret_cases = load_retrieval_all()
        ans_cases = load_answers_v2()
    else:
        ret_cases = load_retrieval()
        ans_cases = load_answers()

    try:
        ret_report = evaluate_retrieval(ret_cases, qembed, store)
        ret_report["by_source"] = evaluate_retrieval_per_source(ret_cases, qembed, store)

        report: dict[str, Any] = {
            "meta": {
                "tag": tag,
                "created": datetime.now(UTC).isoformat(timespec="seconds"),
                "chat_model": settings.ollama_model,
                "embed_model": settings.embed_model,
                "embed_query_prefix": settings.embed_query_prefix,
                "embed_doc_prefix": settings.embed_doc_prefix,
                "kb_version": settings.kb_version,
                "kb_records": store.count(),
                "min_score": settings.min_score,
                "top_k": settings.retrieval_top_k,
                "dataset_version": dataset_version,
                "dataset_hash": dataset_hash(),
                "git_commit": _git_commit(),
            },
            "retrieval": ret_report,
        }
        if not skip_llm:
            results: list[CaseResult] = []
            for case in ans_cases:
                if only and case.id not in only and case.category not in only:
                    continue
                ans, secs = timed(
                    answer, case.question, qembed, store, llm, settings.retrieval_top_k, settings.min_score
                )
                results.append(check_case(case, ans, secs))
            report["answers"] = {"summary": summarize(results), "cases": [r.to_dict() for r in results]}
        return report
    finally:
        store.close()


def save_report(report: dict[str, Any], out_dir: Path = RESULTS_DIR) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", report["meta"]["tag"].lower()).strip("-")
    path = out_dir / f"{slug}-{report['meta']['created'][:10]}.json"
    path.write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8", newline="\n")
    return path


def _metrics(report: dict[str, Any]) -> dict[str, float]:
    m: dict[str, float] = {}
    ov = report.get("retrieval", {}).get("overall", {})
    for k in ("recall@1", "recall@4", "mrr"):
        if k in ov:
            m[f"retrieval.{k}"] = ov[k]
    by_src = report.get("retrieval", {}).get("by_source", {})
    for src_name, metrics in by_src.items():
        if "recall@4" in metrics:
            m[f"retrieval.{src_name}.recall@4"] = metrics["recall@4"]
    cal = report.get("retrieval", {}).get("calibration", {})
    if "balanced_accuracy" in cal:
        m["calibration.balanced_accuracy"] = cal["balanced_accuracy"]
    summ = report.get("answers", {}).get("summary")
    if summ:
        m["answers.pass_rate"] = summ["pass_rate"]
        m["answers.invalid_citation_rate"] = summ["invalid_citation_rate"]
        for cat, c in summ["by_category"].items():
            m[f"answers.{cat}"] = c["pass_rate"]
    return m


def compare(a: dict[str, Any], b: dict[str, Any]) -> list[str]:
    """Human-readable delta table. Warns if the datasets differ (scores not comparable)."""
    lines = []
    if a["meta"]["dataset_hash"] != b["meta"]["dataset_hash"]:
        lines.append("WARNING: dataset hashes differ - scores are NOT directly comparable.")
    ma, mb = _metrics(a), _metrics(b)
    lines.append(f"{'metric':36} {a['meta']['tag'][:14]:>14} {b['meta']['tag'][:14]:>14} {'delta':>8}")
    for k in sorted(set(ma) | set(mb)):
        va, vb = ma.get(k), mb.get(k)
        delta = f"{vb - va:+.3f}" if va is not None and vb is not None else "n/a"
        sa = f"{va:.3f}" if va is not None else "-"
        sb = f"{vb:.3f}" if vb is not None else "-"
        lines.append(f"{k:36} {sa:>14} {sb:>14} {delta:>8}")
    return lines
