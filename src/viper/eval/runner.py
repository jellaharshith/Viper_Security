"""Run the evaluation, save a comparable JSON report, and compare two reports."""

from __future__ import annotations

import json
import re
import subprocess  # noqa: S404 (fixed git command, no user input)
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from viper.config import Settings
from viper.eval.answers import CaseResult, check_case, summarize, timed
from viper.eval.cases import dataset_hash, load_answers, load_retrieval
from viper.eval.retrieval import evaluate_retrieval
from viper.llm import OllamaClient
from viper.rag import VectorStore, answer
from viper.rag.embedding import PrefixEmbedder
from viper.rag.registry import resolve_collection

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


def run_eval(
    settings: Settings, tag: str, skip_llm: bool = False, only: set[str] | None = None
) -> dict[str, Any]:
    llm = OllamaClient(settings.ollama_host, settings.ollama_model, settings.embed_model)
    qembed = PrefixEmbedder(llm, settings.embed_query_prefix)
    store = VectorStore(
        settings.qdrant_path,
        resolve_collection(settings.kb_registry_path, f"kb_{settings.kb_version}"),
    )
    try:
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
                "dataset_hash": dataset_hash(),
                "git_commit": _git_commit(),
            },
            "retrieval": evaluate_retrieval(load_retrieval(), qembed, store),
        }
        if not skip_llm:
            results: list[CaseResult] = []
            for case in load_answers():
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
