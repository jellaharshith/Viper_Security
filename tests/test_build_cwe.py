from pathlib import Path

from viper.eval.build import build_cwe
from viper.eval.cases import case_source, load_retrieval_all
from viper.rag.cwe import parse_cwe

FIXTURE = Path("tests/fixtures/cwe_sample.xml")


def _cwe_docs() -> list:  # type: ignore[type-arg]
    return parse_cwe(FIXTURE.read_text(encoding="utf-8"))


def test_build_cwe_writes_definition_queries(tmp_path: Path) -> None:
    res = build_cwe(docs=_cwe_docs(), out_dir=tmp_path)
    assert res["cwe_records"] == 2
    out = (tmp_path / "retrieval_cwe.jsonl").read_text(encoding="utf-8")
    assert "cwe:CWE-79" in out and "Cross-site Scripting" in out
    assert "cwe:CWE-89" in out


def test_build_cwe_gold_ids_map_to_cwe_source(tmp_path: Path) -> None:
    build_cwe(docs=_cwe_docs(), out_dir=tmp_path)
    cases = load_retrieval_all(dataset_dir=tmp_path)
    cwe_cases = [c for c in cases if c.gold_id and c.gold_id.startswith("cwe:")]
    assert cwe_cases and all(case_source(c) == "cwe" for c in cwe_cases)
    # negatives carry no gold id
    assert any(c.gold_id is None for c in cases)
