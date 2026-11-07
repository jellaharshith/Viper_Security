from pathlib import Path

import pytest

from viper.rag.registry import KBRegistry, resolve_collection
from viper.rag.store import VectorStore
from viper.rag.types import Document, IngestError
from viper.rag.update import UpdateReport, collect, run_update, stage, validate


def doc(i: int, text: str = "") -> Document:
    return Document(id=f"d{i}", text=text or f"text {i}", source="s", url=f"https://x/{i}", title=f"t{i}")


class Counting:
    def __init__(self) -> None:
        self.calls = 0

    def embed(self, texts: list[str]) -> list[list[float]]:
        self.calls += len(texts)
        return [[float(len(t)), 1.0] for t in texts]


def make_active(n: int = 10) -> VectorStore:
    base = VectorStore(None, "live")
    emb = Counting()
    docs = [doc(i) for i in range(n)]
    base.upsert(docs, emb.embed([d.text for d in docs]))
    return base


def test_registry_promote_rollback_and_atomic_file(tmp_path: Path) -> None:
    p = tmp_path / "reg.json"
    reg = KBRegistry.load(p)
    reg.bootstrap("a")
    reg.promote("b")
    again = KBRegistry.load(p)
    assert (again.active, again.previous) == ("b", "a")
    assert again.rollback() == "a"
    assert KBRegistry.load(p).active == "a"
    assert resolve_collection(p, "fallback") == "a"
    assert resolve_collection(tmp_path / "none.json", "fallback") == "fallback"
    with pytest.raises(ValueError):
        KBRegistry(tmp_path / "x.json").rollback()


def test_validate_flags_truncated_and_empty_feeds() -> None:
    assert validate([], 10, 0.1)
    assert any("shrank" in p for p in validate([doc(1)], 10, 0.1))
    assert validate([doc(i) for i in range(10)], 10, 0.1) == []


def test_stage_reuses_unchanged_vectors_and_embeds_only_changes() -> None:
    base = make_active(5)
    emb = Counting()
    new = [doc(0), doc(1), doc(2, "changed text"), doc(3), doc(99)]  # d4 removed, d2 changed, d99 new
    reused, embedded, removed = stage(new, emb, base, base.view("stg"))
    assert (reused, embedded, removed) == (3, 2, 1)
    assert emb.calls == 2
    assert base.view("stg").count() == 5
    assert base.count() == 5  # live collection untouched


def test_failed_gate_leaves_live_index_and_drops_staging() -> None:
    base = make_active(10)
    promoted: list[str] = []
    rep = run_update(
        source="t", docs=[doc(i) for i in range(10)], doc_embedder=Counting(),
        active=base, staging=base.view("stg"), recall_at_4=lambda s: 0.5 if s.collection == "stg" else 0.99,
        min_recall=0.95, max_shrink=0.1, promote=promoted.append,
    )
    assert not rep.promoted and promoted == []
    assert "quality gate" in rep.decision
    assert not base.view("stg").exists()
    assert base.count() == 10


def test_regression_against_live_blocks_even_above_floor() -> None:
    base = make_active(10)
    rep = run_update(
        source="t", docs=[doc(i) for i in range(10)], doc_embedder=Counting(),
        active=base, staging=base.view("stg"), recall_at_4=lambda s: 0.96 if s.collection == "stg" else 1.0,
        min_recall=0.95, max_shrink=0.1, promote=lambda _c: None,
    )
    assert not rep.promoted and any("regressed" in p for p in rep.problems)


def test_passing_update_promotes_and_dry_run_does_not() -> None:
    base = make_active(10)
    docs = [doc(i) for i in range(10)] + [doc(50)]
    promoted: list[str] = []
    ok = run_update(
        source="t", docs=docs, doc_embedder=Counting(), active=base, staging=base.view("stg"),
        recall_at_4=lambda _s: 0.99, min_recall=0.95, max_shrink=0.1, promote=promoted.append,
    )
    assert ok.promoted and promoted == ["stg"] and base.view("stg").count() == 11
    dry = run_update(
        source="t", docs=docs, doc_embedder=Counting(), active=base, staging=base.view("stg2"),
        recall_at_4=lambda _s: 0.99, min_recall=0.95, max_shrink=0.1, promote=None,
    )
    assert not dry.promoted and "dry run" in dry.decision


def test_invalid_feed_never_stages() -> None:
    base = make_active(10)
    emb = Counting()
    rep = run_update(
        source="t", docs=[doc(1)], doc_embedder=emb, active=base, staging=base.view("stg"),
        recall_at_4=lambda _s: 1.0, min_recall=0.95, max_shrink=0.1, promote=lambda _c: None,
    )
    assert rep.decision.startswith("REJECTED: validation") and emb.calls == 0
    assert not base.view("stg").exists()


# ---- multi-source: per-source validation and carry-over -------------------------------------


class FakeSource:
    def __init__(self, name: str, docs: list[Document] | None = None, error: str | None = None) -> None:
        self.name, self._docs, self._error = name, docs or [], error

    def fetch(self) -> list[Document]:
        if self._error:
            raise IngestError(self._error)
        return self._docs


def sdoc(prefix: str, i: int, text: str = "") -> Document:
    return Document(id=f"{prefix}:{i}", text=text or f"{prefix} text {i}", source=prefix,
                    url=f"https://x/{prefix}/{i}", title=f"{prefix} {i}")


def make_live(spec: dict[str, int]) -> VectorStore:
    base = VectorStore(None, "live")
    docs = [sdoc(p, i) for p, n in spec.items() for i in range(n)]
    base.upsert(docs, Counting().embed([d.text for d in docs]))
    return base


def multi(base: VectorStore, sources: list[FakeSource], promote: list[str] | None = None) -> UpdateReport:
    docs, outcomes = collect(list(sources), base)  # type: ignore[arg-type]
    return run_update(
        source="multi", docs=docs, outcomes=outcomes, doc_embedder=Counting(), active=base,
        staging=base.view("stg"), recall_at_4=lambda _s: 0.99, min_recall=0.95, max_shrink=0.1,
        promote=promote.append if promote is not None else None,
    )


def test_failed_source_is_carried_over_from_live_and_flagged() -> None:
    base = make_live({"kev": 10, "attack": 20})
    promoted: list[str] = []
    rep = multi(base, [FakeSource("kev", [sdoc("kev", i) for i in range(10)] + [sdoc("kev", 99)]),
                       FakeSource("attack", error="download failed")], promoted)
    assert rep.promoted and promoted == ["stg"]
    assert rep.per_source == {"kev": 11, "attack": 20}
    assert len(rep.carried_over) == 1 and "attack" in rep.carried_over[0] and "20" in rep.carried_over[0]
    staged = base.view("stg")
    assert staged.count() == 31
    assert len(staged.get_many([f"attack:{i}" for i in range(20)])) == 20  # nothing dropped


def test_carried_over_records_reuse_vectors_without_reembedding() -> None:
    base = make_live({"kev": 5, "attack": 5})
    docs, outcomes = collect([FakeSource("kev", [sdoc("kev", i) for i in range(5)]),  # type: ignore[list-item]
                              FakeSource("attack", error="boom")], base)
    emb = Counting()
    reused, embedded, removed = stage(docs, emb, base, base.view("stg"))
    assert (reused, embedded, removed) == (10, 0, 0) and emb.calls == 0


def test_shrink_check_is_per_source() -> None:
    base = make_live({"kev": 100, "attack": 10})
    # kev fine, attack truncated to 2 of 10: whole update rejected, even though the union (102 of 110)
    # would have passed a single global check at 10% shrink... (7% < 10%)
    rep = multi(base, [FakeSource("kev", [sdoc("kev", i) for i in range(100)]),
                       FakeSource("attack", [sdoc("attack", i) for i in range(2)])])
    assert rep.decision.startswith("REJECTED: validation")
    assert any(p.startswith("attack:") and "shrank" in p for p in rep.problems)
    assert not any(p.startswith("kev:") for p in rep.problems)
    assert not base.view("stg").exists()


def test_new_source_with_no_live_records_has_no_shrink_baseline() -> None:
    base = make_live({"kev": 10})
    rep = multi(base, [FakeSource("kev", [sdoc("kev", i) for i in range(10)]),
                       FakeSource("attack", [sdoc("attack", i) for i in range(3)])], [])
    assert rep.promoted and rep.per_source == {"kev": 10, "attack": 3} and rep.carried_over == []


def test_all_sources_failing_rejects_the_update() -> None:
    base = make_live({"kev": 10})
    rep = multi(base, [FakeSource("kev", error="a"), FakeSource("attack", error="b")], [])
    assert not rep.promoted and any("no source could be fetched" in p for p in rep.problems)


def test_failed_source_with_nothing_live_is_flagged_not_fatal() -> None:
    base = make_live({"kev": 10})
    rep = multi(base, [FakeSource("kev", [sdoc("kev", i) for i in range(10)]),
                       FakeSource("attack", error="down")], [])
    assert rep.promoted and rep.per_source["attack"] == 0 and "0 live records" in rep.carried_over[0]
