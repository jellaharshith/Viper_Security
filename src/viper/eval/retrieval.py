"""Retrieval metrics and similarity-threshold calibration (no LLM involved)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from viper.eval.cases import RetrievalCase
from viper.rag.types import Embedder, Store

TOP_K = 10


def evaluate_retrieval(
    cases: list[RetrievalCase], embedder: Embedder, store: Store, batch: int = 16
) -> dict[str, Any]:
    ranks: dict[str, list[int | None]] = defaultdict(list)  # style -> rank of gold (1-based)
    gold_scores: list[float] = []  # score of the gold doc (0 when not retrieved)
    neg_top1: list[float] = []

    for i in range(0, len(cases), batch):
        chunk = cases[i : i + batch]
        vectors = embedder.embed([c.query for c in chunk])
        for case, vec in zip(chunk, vectors, strict=True):
            hits = store.search(vec, TOP_K)
            if case.gold_id is None:
                neg_top1.append(hits[0].score if hits else 0.0)
                continue
            rank = next((r for r, h in enumerate(hits, 1) if h.document.id == case.gold_id), None)
            ranks[case.style].append(rank)
            gold_scores.append(hits[rank - 1].score if rank else 0.0)

    def summarize(rs: list[int | None]) -> dict[str, float]:
        n = len(rs) or 1
        return {
            "n": len(rs),
            "recall@1": sum(1 for r in rs if r == 1) / n,
            "recall@4": sum(1 for r in rs if r and r <= 4) / n,
            "recall@10": sum(1 for r in rs if r) / n,
            "mrr": sum(1 / r for r in rs if r) / n,
        }

    all_ranks = [r for rs in ranks.values() for r in rs]
    return {
        "overall": summarize(all_ranks),
        "by_style": {s: summarize(rs) for s, rs in sorted(ranks.items())},
        "calibration": calibrate(gold_scores, neg_top1),
    }


def calibrate(pos: list[float], neg: list[float]) -> dict[str, Any]:
    """Pick the score cutoff maximizing balanced accuracy.

    pos: score of the correct record for answerable queries (0 if missed).
    neg: top-1 score for queries that have no relevant record.
    A good cutoff keeps most pos (>= t) and rejects most neg (< t).
    """
    if not pos or not neg:
        return {"note": "need both positive and negative cases"}
    best = {"threshold": 0.0, "balanced_accuracy": 0.0, "tpr": 0.0, "tnr": 0.0}
    for t in sorted(set(pos + neg)):
        tpr = sum(1 for s in pos if s >= t) / len(pos)
        tnr = sum(1 for s in neg if s < t) / len(neg)
        ba = (tpr + tnr) / 2
        if ba > best["balanced_accuracy"]:
            best = {"threshold": round(t, 4), "balanced_accuracy": round(ba, 4),
                    "tpr": round(tpr, 4), "tnr": round(tnr, 4)}
    best["pos_mean"] = round(sum(pos) / len(pos), 4)
    best["neg_mean"] = round(sum(neg) / len(neg), 4)
    best["neg_max"] = round(max(neg), 4)
    return best
