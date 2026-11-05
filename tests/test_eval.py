import json
from pathlib import Path

import pytest

from viper.eval.answers import check_case, extract_json, summarize
from viper.eval.cases import AnswerCase, dataset_hash, load_answers, load_retrieval
from viper.eval.retrieval import calibrate
from viper.eval.runner import compare, save_report
from viper.rag.pipeline import UNVERIFIED_PREFIX, Answer


def _ans(text: str, grounded: bool = True, invalid: list[int] | None = None) -> Answer:
    return Answer(text=text, grounded=grounded, invalid_citations=invalid or [])


def test_extract_json_handles_prose_and_fences() -> None:
    assert extract_json('Sure! ```json\n{"a": 1}\n``` done') == {"a": 1}
    assert extract_json("no json here") is None
    assert extract_json("{broken") is None
    assert extract_json("[1, 2]") is None


def test_contains_all_is_case_insensitive_and_strict() -> None:
    case = AnswerCase("c", "kev_fact", "q", must_contain=["2021-12-24", "Apache"])
    assert check_case(case, _ans("Apache, due 2021-12-24")).passed
    assert not check_case(case, _ans("Apache only")).passed


def test_grounding_and_unverified_expectations() -> None:
    case = AnswerCase("c", "offdomain", "q", expect_grounded=False, expect_unverified=True)
    assert check_case(case, _ans(UNVERIFIED_PREFIX + "x", grounded=False)).passed
    assert not check_case(case, _ans("x", grounded=False)).passed  # missing label
    assert not check_case(case, _ans(UNVERIFIED_PREFIX + "x", grounded=True)).passed


def test_json_fields_required() -> None:
    case = AnswerCase("c", "json", "q", json_fields=["cve", "due_date"])
    assert check_case(case, _ans('{"cve": "x", "due_date": "y"}')).passed
    r = check_case(case, _ans('{"cve": "x"}'))
    assert not r.passed and r.checks["valid_json"] and not r.checks["json_has_fields"]


def test_invalid_citation_fails_case() -> None:
    case = AnswerCase("c", "kev_fact", "q", must_contain=["x"])
    assert not check_case(case, _ans("x [9]", invalid=[9])).passed


def test_summary_counts_and_flags_review() -> None:
    review_case = AnswerCase("a", "safety", "q", must_contain_any=["cannot"], review=True)
    ok = check_case(review_case, _ans("I cannot"))
    bad = check_case(AnswerCase("b", "safety", "q", must_contain_any=["cannot"]), _ans("sure!"))
    s = summarize([ok, bad])
    assert s["pass_rate"] == 0.5 and s["by_category"]["safety"]["n"] == 2
    assert s["needs_human_review"] == ["a"]


def test_calibrate_finds_separating_threshold() -> None:
    out = calibrate(pos=[0.8, 0.85, 0.9], neg=[0.3, 0.4, 0.5])
    assert out["balanced_accuracy"] == 1.0 and 0.5 < out["threshold"] <= 0.8


def test_calibrate_reports_overlap_honestly() -> None:
    out = calibrate(pos=[0.6, 0.7, 0.9], neg=[0.65, 0.7, 0.8])
    assert out["balanced_accuracy"] < 1.0


def test_calibrate_needs_both_classes() -> None:
    assert "note" in calibrate([0.5], [])


def test_committed_datasets_are_valid_and_unambiguous() -> None:
    ret, ans = load_retrieval(), load_answers()
    gold = [c.gold_id for c in ret if c.gold_id]
    assert len(gold) == len(set(gold)), "each record is the gold answer for at most one query"
    assert sum(1 for c in ret if c.gold_id is None) >= 20, "enough negatives to calibrate"
    assert len({c.category for c in ans}) >= 5
    assert all(c.must_contain or c.must_contain_any or c.json_fields or c.expect_unverified for c in ans)


def test_dataset_hash_is_stable_and_detects_change(tmp_path: Path) -> None:
    (tmp_path / "a.jsonl").write_text('{"x": 1}\n', encoding="utf-8")
    h1 = dataset_hash(tmp_path)
    assert h1 == dataset_hash(tmp_path)
    (tmp_path / "a.jsonl").write_text('{"x": 2}\n', encoding="utf-8")
    assert dataset_hash(tmp_path) != h1


def test_compare_warns_when_datasets_differ_and_shows_delta() -> None:
    def rep(tag: str, h: str, r1: float) -> dict:  # type: ignore[type-arg]
        return {"meta": {"tag": tag, "dataset_hash": h, "created": "2026-11-05T00:00:00"},
                "retrieval": {"overall": {"recall@1": r1}}}

    lines = compare(rep("old", "h1", 0.5), rep("new", "h1", 0.75))
    assert not lines[0].startswith("WARNING") and "+0.250" in "\n".join(lines)
    assert compare(rep("old", "h1", 0.5), rep("new", "h2", 0.5))[0].startswith("WARNING")


def test_save_report_roundtrip(tmp_path: Path) -> None:
    report = {"meta": {"tag": "My Run!", "created": "2026-11-05T01:02:03"}}
    path = save_report(report, tmp_path)
    assert path.name == "my-run-2026-11-05.json"
    assert json.loads(path.read_text(encoding="utf-8")) == report


@pytest.mark.parametrize("name", ["retrieval.jsonl", "answers.jsonl"])
def test_dataset_files_are_lf_json_lines(name: str) -> None:
    raw = Path("eval/datasets", name).read_bytes()
    assert b"\r\n" not in raw
    for line in raw.decode("utf-8").splitlines():
        json.loads(line)
