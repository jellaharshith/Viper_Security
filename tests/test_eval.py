import hashlib
import json
from pathlib import Path

import pytest

from viper.eval.answers import check_case, extract_json, summarize
from viper.eval.build import build_answers_v2, build_attack_owasp
from viper.eval.cases import (
    AnswerCase,
    RetrievalCase,
    case_source,
    dataset_hash,
    load_answers,
    load_answers_v2,
    load_retrieval,
    load_retrieval_all,
    load_retrieval_attack_owasp,
)
from viper.eval.retrieval import calibrate
from viper.eval.runner import (
    check_recall_gate,
    compare,
    evaluate_retrieval_per_source,
    make_recall_gate,
    save_report,
)
from viper.rag.pipeline import UNVERIFIED_PREFIX, Answer
from viper.rag.store import VectorStore
from viper.rag.types import Document


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


@pytest.mark.parametrize("name", [
    "retrieval.jsonl",
    "answers.jsonl",
    "retrieval_attack_owasp.jsonl",
    "answers_v2.jsonl",
])
def test_dataset_files_are_lf_json_lines(name: str) -> None:
    raw = Path("eval/datasets", name).read_bytes()
    assert b"\r\n" not in raw
    for line in raw.decode("utf-8").splitlines():
        json.loads(line)


# =========================================================================
# M3c Tests: hash pin, dataset v2, flipped expectations, per-source recall
# =========================================================================

def test_v1_datasets_are_unchanged_hash_pinned() -> None:
    """Hard constraint: v1 retrieval.jsonl and answers.jsonl are immutable."""
    ans_bytes = Path("eval/datasets/answers.jsonl").read_bytes().replace(b"\r\n", b"\n")
    ret_bytes = Path("eval/datasets/retrieval.jsonl").read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(ans_bytes).hexdigest() == (
        "7852c74d7ba2cef8d6df0b55ac903a756be637ff14234c0b925795f6361f4cb2"
    )
    assert hashlib.sha256(ret_bytes).hexdigest() == (
        "0cd900da18191e64f0b512661665804660738dba1bfbe7a819ab16646b248852"
    )


def test_v2_datasets_load_and_have_unique_ids() -> None:
    v2_ans = load_answers_v2()
    ao_ret = load_retrieval_attack_owasp()
    assert len(v2_ans) >= 40
    assert len(ao_ret) >= 20
    gold = [c.gold_id for c in ao_ret if c.gold_id]
    assert len(gold) == len(set(gold)), "each ATT&CK / OWASP query targets a distinct gold_id"


def test_v2_flipped_expectations_marked_needs_human() -> None:
    """SQL injection / XSS questions expect to be grounded by OWASP and flagged needs-human."""
    ans = load_answers_v2()
    by_id = {c.id: c for c in ans}

    # SQL injection definition
    sql_case = by_id["def-12"]
    assert "SQL injection" in sql_case.question
    assert sql_case.expect_grounded is True
    assert sql_case.review is True
    assert sql_case.review_reason == "needs-human"

    # XSS definition
    xss_cases = [c for c in ans if "XSS" in c.question or "cross-site scripting" in c.question.lower()]
    assert len(xss_cases) >= 1
    for c in xss_cases:
        assert c.expect_grounded is True
        assert c.review is True
        assert c.review_reason == "needs-human"


def test_case_source_classification() -> None:
    c_kev = RetrievalCase("1", "q", "title", "cisa-kev:CVE-2021-44228")
    c_atk = RetrievalCase("2", "q", "technique", "attack:T1059.001")
    c_owasp = RetrievalCase("3", "q", "category", "owasp-top10:2025:A05:overview")
    c_neg = RetrievalCase("4", "q", "negative", None)

    assert case_source(c_kev) == "cisa-kev"
    assert case_source(c_atk) == "mitre-attack"
    assert case_source(c_owasp) == "owasp-top10"
    assert case_source(c_neg) is None


def test_load_retrieval_all_combines_datasets() -> None:
    all_cases = load_retrieval_all()
    v1_count = len(load_retrieval())
    v2_count = len(load_retrieval_attack_owasp())
    assert len(all_cases) == v1_count + v2_count


class SimpleVectorStoreEmbedder:
    """Test helper embedder that returns one-hot orthogonal vectors."""

    def __init__(self, mapping: dict[str, list[float]]) -> None:
        self.mapping = mapping
        self.default = [0.0, 0.0, 0.0, 1.0]

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self.mapping.get(t, self.default) for t in texts]


def test_evaluate_retrieval_per_source_partitions_metrics() -> None:
    store = VectorStore(None, "test_per_source")
    docs = [
        Document("cisa-kev:CVE-1", "KEV doc", "cisa-kev", "https://x/1", "CVE-1"),
        Document("attack:T1059", "ATT&CK doc", "mitre-attack", "https://x/2", "T1059"),
        Document("owasp-top10:2025:A05:overview", "OWASP doc", "owasp-top10", "https://x/3", "A05"),
    ]
    # Orthogonal unit vectors in 4 dims
    vecs = [
        [1.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
    ]
    store.upsert(docs, vecs)

    embedder = SimpleVectorStoreEmbedder({
        "q-kev": [1.0, 0.0, 0.0, 0.0],
        "q-atk": [0.0, 1.0, 0.0, 0.0],
        "q-owasp": [0.0, 0.0, 1.0, 0.0],
    })
    cases = [
        RetrievalCase("k1", "q-kev", "title", "cisa-kev:CVE-1"),
        RetrievalCase("a1", "q-atk", "technique", "attack:T1059"),
        RetrievalCase("o1", "q-owasp", "category", "owasp-top10:2025:A05:overview"),
    ]

    by_src = evaluate_retrieval_per_source(cases, embedder, store)
    assert set(by_src.keys()) == {"cisa-kev", "mitre-attack", "owasp-top10"}
    for src in ("cisa-kev", "mitre-attack", "owasp-top10"):
        assert by_src[src]["recall@1"] == 1.0
        assert by_src[src]["recall@4"] == 1.0
        assert by_src[src]["mrr"] == 1.0


def test_check_recall_gate_passes_and_fails_appropriately() -> None:
    store = VectorStore(None, "test_gate")
    docs = [
        Document("cisa-kev:CVE-1", "KEV", "cisa-kev", "https://x/1", "CVE-1"),
        Document("attack:T1059", "ATTACK", "mitre-attack", "https://x/2", "T1059"),
        Document("noise:1", "Noise 1", "noise", "https://x/n1", "N1"),
        Document("noise:2", "Noise 2", "noise", "https://x/n2", "N2"),
        Document("noise:3", "Noise 3", "noise", "https://x/n3", "N3"),
        Document("noise:4", "Noise 4", "noise", "https://x/n4", "N4"),
    ]
    vecs = [
        [1.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
    ]
    store.upsert(docs, vecs)

    # Perfect embedder: passes gate
    pass_emb = SimpleVectorStoreEmbedder({
        "q-kev": [1.0, 0.0, 0.0, 0.0],
        "q-atk": [0.0, 1.0, 0.0, 0.0],
    })
    cases = [
        RetrievalCase("k1", "q-kev", "title", "cisa-kev:CVE-1"),
        RetrievalCase("a1", "q-atk", "technique", "attack:T1059"),
    ]
    ok, scores, problems = check_recall_gate(store, pass_emb, cases=cases, min_recall=0.90)
    assert ok is True
    assert scores["cisa-kev"] == 1.0 and scores["mitre-attack"] == 1.0
    assert not problems

    # Failing embedder for ATT&CK (matches noise documents instead of gold target)
    fail_emb = SimpleVectorStoreEmbedder({
        "q-kev": [1.0, 0.0, 0.0, 0.0],
        "q-atk": [0.0, 0.0, 1.0, 0.0],  # 4 noise docs will rank 1-4, pushing gold to rank 5
    })
    ok2, scores2, problems2 = check_recall_gate(store, fail_emb, cases=cases, min_recall=0.90)
    assert ok2 is False
    assert scores2["mitre-attack"] == 0.0
    assert any("mitre-attack" in p for p in problems2)

    # make_recall_gate callable
    gate_fn = make_recall_gate(pass_emb, cases=cases, min_recall=0.90)
    assert gate_fn(store) == 1.0
    fail_gate = make_recall_gate(fail_emb, cases=cases, min_recall=0.90)
    assert fail_gate(store) == 0.0


def test_compare_includes_per_source_recall_deltas() -> None:
    rep_a = {
        "meta": {"tag": "run-a", "dataset_hash": "same", "created": "2026-11-06T00:00:00"},
        "retrieval": {
            "overall": {"recall@4": 0.90},
            "by_source": {
                "cisa-kev": {"recall@4": 0.95},
                "mitre-attack": {"recall@4": 0.85},
            },
        },
    }
    rep_b = {
        "meta": {"tag": "run-b", "dataset_hash": "same", "created": "2026-11-06T01:00:00"},
        "retrieval": {
            "overall": {"recall@4": 0.95},
            "by_source": {
                "cisa-kev": {"recall@4": 0.98},
                "mitre-attack": {"recall@4": 0.92},
            },
        },
    }
    lines = compare(rep_a, rep_b)
    table_text = "\n".join(lines)
    assert "retrieval.cisa-kev.recall@4" in table_text
    assert "retrieval.mitre-attack.recall@4" in table_text
    assert "+0.030" in table_text
    assert "+0.070" in table_text


def test_build_attack_owasp_and_answers_v2_are_deterministic(tmp_path: Path) -> None:
    res1 = build_attack_owasp(out_dir=tmp_path)
    ans1 = build_answers_v2(out_dir=tmp_path)
    assert res1["retrieval_attack_owasp"] > 0
    assert ans1["answers_v2"] > 0

    content_ret1 = (tmp_path / "retrieval_attack_owasp.jsonl").read_text(encoding="utf-8")
    content_ans1 = (tmp_path / "answers_v2.jsonl").read_text(encoding="utf-8")

    # Re-run: must be byte-for-byte identical
    build_attack_owasp(out_dir=tmp_path)
    build_answers_v2(out_dir=tmp_path)
    assert (tmp_path / "retrieval_attack_owasp.jsonl").read_text(encoding="utf-8") == content_ret1
    assert (tmp_path / "answers_v2.jsonl").read_text(encoding="utf-8") == content_ans1
