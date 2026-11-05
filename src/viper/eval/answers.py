"""Deterministic checks for end-to-end answers. No LLM-as-judge: every check is code."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from viper.eval.cases import AnswerCase
from viper.rag.pipeline import Answer, is_unverified


@dataclass
class CaseResult:
    id: str
    category: str
    passed: bool
    checks: dict[str, bool]
    needs_review: bool
    seconds: float
    text: str
    invalid_citations: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def extract_json(text: str) -> dict[str, Any] | None:
    """Parse the first JSON object found in text (models often wrap it in prose or code fences)."""
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def check_case(case: AnswerCase, ans: Answer, seconds: float = 0.0) -> CaseResult:
    low = ans.text.lower()
    checks: dict[str, bool] = {}
    if case.must_contain:
        checks["contains_all"] = all(s.lower() in low for s in case.must_contain)
    if case.must_contain_any:
        checks["contains_any"] = any(s.lower() in low for s in case.must_contain_any)
    if case.expect_grounded is not None:
        checks["grounded_as_expected"] = ans.grounded == case.expect_grounded
    if case.expect_unverified:
        checks["labelled_unverified"] = is_unverified(ans.text)
    if case.json_fields:
        obj = extract_json(ans.text)
        checks["valid_json"] = obj is not None
        checks["json_has_fields"] = obj is not None and all(f in obj for f in case.json_fields)
    if ans.sources or ans.invalid_citations:
        checks["no_invalid_citations"] = not ans.invalid_citations
    return CaseResult(
        id=case.id,
        category=case.category,
        passed=all(checks.values()),
        checks=checks,
        needs_review=case.review,
        seconds=round(seconds, 1),
        text=ans.text,
        invalid_citations=list(ans.invalid_citations),
    )


def timed(fn: Callable[..., Answer], *args: Any) -> tuple[Answer, float]:
    t0 = time.monotonic()
    out = fn(*args)
    return out, time.monotonic() - t0


def summarize(results: list[CaseResult]) -> dict[str, Any]:
    by_cat: dict[str, dict[str, Any]] = {}
    for r in results:
        c = by_cat.setdefault(r.category, {"n": 0, "passed": 0})
        c["n"] += 1
        c["passed"] += int(r.passed)
    for c in by_cat.values():
        c["pass_rate"] = round(c["passed"] / c["n"], 3)
    graded = [r for r in results if "no_invalid_citations" in r.checks]
    n = len(results) or 1
    return {
        "n": len(results),
        "pass_rate": round(sum(r.passed for r in results) / n, 3),
        "by_category": by_cat,
        "invalid_citation_rate": round(
            sum(1 for r in graded if not r.checks["no_invalid_citations"]) / (len(graded) or 1), 3
        ),
        "needs_human_review": [r.id for r in results if r.needs_review],
        "mean_seconds": round(sum(r.seconds for r in results) / n, 1),
    }
