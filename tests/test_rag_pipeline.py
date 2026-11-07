import hashlib
import math

import pytest

from viper.rag import Document, VectorStore, answer, ingest
from viper.rag.pipeline import UNVERIFIED_PREFIX, check_citations


class FakeEmbedder:
    """Hashes words into a 64-dim unit vector: texts sharing words are similar."""

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for t in texts:
            v = [0.0] * 64
            for w in t.lower().replace(".", " ").split():
                v[int(hashlib.md5(w.encode()).hexdigest(), 16) % 64] += 1.0  # noqa: S324
            n = math.sqrt(sum(x * x for x in v)) or 1.0
            out.append([x / n for x in v])
        return out


class FakeLLM:
    def __init__(self, reply: str) -> None:
        self.reply, self.calls = reply, []  # type: ignore[var-annotated]

    def chat(self, messages: list[dict[str, str]], temperature: float = 0.2) -> str:
        self.calls.append(messages)
        return self.reply


def _docs() -> list[Document]:
    mk = lambda i, t: Document(f"d:{i}", t, "CISA KEV", f"https://x/{i}", f"T{i}")  # noqa: E731
    return [mk(1, "Acme Widget remote code execution exploited ransomware"),
            mk(2, "Contoso Gadget authentication bypass patch available")]


@pytest.fixture()
def store() -> VectorStore:
    s = VectorStore(None, "kb_test")
    ingest(_docs(), FakeEmbedder(), s)
    return s


def test_ingest_is_idempotent(store: VectorStore) -> None:
    assert store.count() == 2
    ingest(_docs(), FakeEmbedder(), store)
    assert store.count() == 2  # same ids overwrite, never duplicate


def test_grounded_answer_includes_sources(store: VectorStore) -> None:
    llm = FakeLLM("It is RCE [1].")
    a = answer("Acme Widget remote code execution", FakeEmbedder(), store, llm, min_score=0.3)
    assert a.grounded and a.sources[0].document.id == "d:1" and not a.invalid_citations
    assert "Sources:" in llm.calls[0][1]["content"]


def test_no_relevant_source_is_marked_unverified(store: VectorStore) -> None:
    a = answer("quantum banana smoothie", FakeEmbedder(), store, FakeLLM("dunno"), min_score=0.9)
    assert not a.grounded and a.text.startswith(UNVERIFIED_PREFIX) and not a.sources


def test_invented_citation_is_flagged(store: VectorStore) -> None:
    a = answer("Acme Widget remote code execution", FakeEmbedder(), store,
               FakeLLM("See [1] and [7]."), min_score=0.3)
    assert a.invalid_citations == [7]


def test_check_citations() -> None:
    assert check_citations("a [1] b [2] c [3]", 2) == [3]
    assert check_citations("no cites", 2) == []


def test_empty_store_returns_no_hits() -> None:
    assert VectorStore(None, "empty").search([0.0] * 4, 3) == []


def test_extract_cves() -> None:
    from viper.rag.pipeline import extract_cves

    assert extract_cves("is cve-2021-44228 and CVE-2021-44228 and CVE-2024-3400 bad?") == [
        "CVE-2021-44228", "CVE-2024-3400"]
    assert extract_cves("no ids here") == []


def test_exact_cve_lookup_beats_semantic_miss() -> None:
    s = VectorStore(None, "kb_exact")
    emb = FakeEmbedder()
    ingest([Document("cisa-kev:CVE-2021-44228", "Apache Log4j2 RCE", "CISA KEV", "u", "T"),
            Document("cisa-kev:CVE-2099-0001", "Totally unrelated words here", "CISA KEV", "u", "U")],
           emb, s)
    # question shares no words with the target doc, so semantic search alone would miss it
    a = answer("tell me about CVE-2021-44228 zzz", emb, s, FakeLLM("RCE [1]"), min_score=0.99)
    assert a.grounded and a.sources[0].document.id == "cisa-kev:CVE-2021-44228"


def test_unknown_cve_is_reported_without_calling_the_llm(store: VectorStore) -> None:
    llm = FakeLLM("should not be used")
    a = answer("What about CVE-2010-0001?", FakeEmbedder(), store, llm, min_score=0.99)
    assert "not in the CISA KEV" in a.text and not a.grounded and llm.calls == []


def test_named_cve_uses_only_its_own_record_and_notes_missing_one() -> None:
    s = VectorStore(None, "kb_mixed")
    emb = FakeEmbedder()
    ingest([Document("cisa-kev:CVE-2021-44228", "Apache Log4j2 RCE", "CISA KEV", "u", "T"),
            Document("cisa-kev:CVE-2099-0001", "Apache Log4j2 RCE similar words", "CISA KEV", "u", "U")],
           emb, s)
    llm = FakeLLM("ok [1]")
    a = answer("Compare CVE-2021-44228 with CVE-2010-0001", emb, s, llm, min_score=0.0)
    assert [h.document.id for h in a.sources] == ["cisa-kev:CVE-2021-44228"]
    assert "CVE-2010-0001 is NOT in the CISA KEV" in llm.calls[0][1]["content"]


def test_unknown_cve_skips_llm_even_with_permissive_threshold(store: VectorStore) -> None:
    llm = FakeLLM("unused")
    a = answer("What about CVE-2010-0001?", FakeEmbedder(), store, llm, min_score=0.0)
    assert "not in the CISA KEV" in a.text and llm.calls == []


def test_check_citations_catches_source_label_format() -> None:
    assert check_citations("claim [Source: 3] and [source 1]", 2) == [3]


def test_answer_that_cites_nothing_is_not_grounded(store: VectorStore) -> None:
    from viper.rag.pipeline import UNCITED_PREFIX, is_unverified

    a = answer("Acme Widget remote code execution", FakeEmbedder(), store,
               FakeLLM("It is a bug, from memory."), min_score=0.3)
    assert not a.grounded and a.text.startswith(UNCITED_PREFIX) and is_unverified(a.text)
    assert a.sources == []  # do not display sources the answer did not use


def test_answer_citing_only_a_nonexistent_source_is_not_grounded(store: VectorStore) -> None:
    a = answer("Acme Widget remote code execution", FakeEmbedder(), store,
               FakeLLM("Per [9] it is bad."), min_score=0.3)
    assert not a.grounded and a.invalid_citations == [9]


def test_is_unverified_recognises_both_labels() -> None:
    from viper.rag.pipeline import UNCITED_PREFIX, is_unverified

    assert is_unverified(UNVERIFIED_PREFIX + "x") and is_unverified(UNCITED_PREFIX + "x")
    assert not is_unverified("plain answer [1]")


def test_named_cve_answer_stays_grounded_without_inline_citations() -> None:
    s = VectorStore(None, "kb_json")
    emb = FakeEmbedder()
    ingest([Document("cisa-kev:CVE-2021-44228", "Apache Log4j2 RCE", "CISA KEV", "u", "T")], emb, s)
    a = answer("Reply with ONLY JSON for CVE-2021-44228", emb, s, FakeLLM('{"cve": "CVE-2021-44228"}'))
    assert a.grounded and a.sources[0].document.id == "cisa-kev:CVE-2021-44228"


def test_extract_attack_ids() -> None:
    from viper.rag.pipeline import extract_attack_ids

    assert extract_attack_ids("is t1059.001 and T1059 and T1059.001 used? not T12345 or T105") == [
        "T1059.001", "T1059"]
    assert extract_attack_ids("CVE-2021-44228 only") == []


def _attack_store() -> VectorStore:
    s = VectorStore(None, "kb_attack")
    ingest([Document("attack:T1059.001", "PowerShell abuse for execution", "mitre-attack", "u", "T"),
            Document("attack:T1059", "Command and scripting interpreter", "mitre-attack", "u", "U"),
            Document("cisa-kev:CVE-2021-44228", "Apache Log4j2 RCE", "CISA KEV", "u", "V")],
           FakeEmbedder(), s)
    return s


def test_exact_attack_lookup_beats_semantic_miss() -> None:
    llm = FakeLLM("PowerShell [1]")
    a = answer("What is T1059.001 qqq?", FakeEmbedder(), _attack_store(), llm, min_score=0.99)
    assert a.grounded and [h.document.id for h in a.sources] == ["attack:T1059.001"]


def test_unknown_attack_id_is_reported_without_calling_the_llm() -> None:
    llm = FakeLLM("unused")
    a = answer("What is T9999?", FakeEmbedder(), _attack_store(), llm, min_score=0.0)
    assert "T9999 is not in the MITRE ATT&CK" in a.text and not a.grounded and llm.calls == []


def test_mixed_cve_and_attack_ids_use_only_named_records_and_note_missing() -> None:
    llm = FakeLLM("ok [1][2]")
    a = answer("Relate CVE-2021-44228 to T1059 and T9999", FakeEmbedder(), _attack_store(), llm,
               min_score=0.0)
    assert {h.document.id for h in a.sources} == {"cisa-kev:CVE-2021-44228", "attack:T1059"}
    assert "T9999 is NOT in the MITRE ATT&CK" in llm.calls[0][1]["content"]
    assert a.grounded


def test_model_can_declare_sources_irrelevant_and_answer_is_unverified(store: VectorStore) -> None:
    from viper.rag.pipeline import NOT_IN_SOURCES, is_unverified

    llm = FakeLLM(f"{NOT_IN_SOURCES} A buffer overflow writes past a buffer's end.")
    a = answer("Acme Widget remote code execution", FakeEmbedder(), store, llm, min_score=0.3)
    assert not a.grounded and is_unverified(a.text) and a.sources == []
    assert NOT_IN_SOURCES not in a.text and "buffer overflow writes" in a.text


def test_not_in_sources_marker_is_ignored_for_named_records() -> None:
    from viper.rag.pipeline import NOT_IN_SOURCES

    s = VectorStore(None, "kb_named")
    ingest([Document("cisa-kev:CVE-2021-44228", "Log4j RCE", "CISA KEV", "https://x", "Log4Shell")],
           FakeEmbedder(), s)
    a = answer("Tell me about CVE-2021-44228", FakeEmbedder(), s, FakeLLM(f"{NOT_IN_SOURCES} x"))
    assert a.grounded  # a named record is the answer by construction


def test_grounded_prompt_asks_for_the_marker() -> None:
    from viper.rag.pipeline import NOT_IN_SOURCES, SYSTEM_GROUNDED

    assert NOT_IN_SOURCES in SYSTEM_GROUNDED and "directly" in SYSTEM_GROUNDED
