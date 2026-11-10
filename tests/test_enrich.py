"""F1: deterministic finding enrichment (curated table) + parser pass-through of structured fields."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from viper.findings import enrich as enrich_mod
from viper.findings.enrich import GENERIC_REMEDIATION_PREFIXES, enrich
from viper.findings.models import Finding
from viper.findings.parsers import parse_nmap, parse_nuclei

FIX = Path(__file__).parent / "fixtures" / "findings"
KW = {"action_id": "a1", "target": "scanme.nmap.org", "audit_refs": ["h1"]}


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def _nuclei(name: str = "nuclei_real.jsonl") -> dict[str, Finding]:
    out: dict[str, Finding] = {}
    for f in parse_nuclei(_read(name), **KW):  # type: ignore[arg-type]
        out[f.title.rsplit("(", 1)[-1].rstrip(")")] = f
    return out


def _nmap(text: str) -> list[Finding]:
    return parse_nmap(text, **KW)  # type: ignore[arg-type]


def _frozen(f: Finding) -> tuple[object, ...]:
    return (f.id, f.title, f.affected_asset, f.source_tool, f.source_action_id, f.evidence,
            f.severity, f.severity_rationale, f.confidence, f.reproducibility, tuple(f.audit_refs))


# ------------------------------------------------------------------ parser pass-through
def test_nuclei_parser_keeps_description_remediation_references_and_cwe() -> None:
    f = _nuclei("nuclei_classified.jsonl")["http-missing-security-headers"]
    assert f.description == "Template-supplied description."
    assert f.remediation == "Template-supplied remediation."
    assert f.references == ["https://owasp.org/www-project-secure-headers/"]
    assert f.cwe == ["CWE-693", "CWE-1021"]


def test_nuclei_cwe_accepts_a_string_and_drops_malformed_values() -> None:
    fs = _nuclei("nuclei_classified.jsonl")
    assert fs["tech-detect"].cwe == ["CWE-200"]
    assert fs["custom-unknown-template"].cwe == ["CWE-20"]  # junk and injection attempts dropped


def test_nuclei_without_classification_has_empty_cwe_and_keeps_description() -> None:
    f = _nuclei()["apache-detect"]
    assert f.cwe == [] and f.description.startswith("Detects the Apache")


def test_nuclei_description_is_neutralised_and_bounded() -> None:
    rec = {"template-id": "t-x", "info": {"name": "N", "severity": "info",
           "description": "ok\x1b[31m red\x00" + "A" * 5000}, "matched-at": "http://scanme.nmap.org/"}
    (f,) = parse_nuclei(json.dumps(rec), **KW)  # type: ignore[arg-type]
    assert "\x1b" not in f.description and "\x00" not in f.description
    assert len(f.description) <= 1000


# ------------------------------------------------------------------ enrichment
def test_known_nuclei_template_gets_description_references_and_remediation() -> None:
    f = _nuclei()["apache-detect"].model_copy(update={"description": ""})
    g = enrich(f)
    assert g.description and g.remediation != f.remediation
    assert g.references and not g.references[0].startswith("nuclei-template:")
    assert not g.remediation.startswith(GENERIC_REMEDIATION_PREFIXES)
    assert _frozen(g) == _frozen(f)


def test_curated_cwe_fills_only_when_parser_gave_none() -> None:
    f = _nuclei()["http-missing-security-headers"]
    assert f.cwe == []
    assert enrich(f).cwe == ["CWE-693"]


def test_parser_supplied_specific_data_always_wins() -> None:
    f = _nuclei("nuclei_classified.jsonl")["http-missing-security-headers"]
    g = enrich(f)
    assert (g.description, g.remediation, g.references, g.cwe) == (
        f.description, f.remediation, f.references, f.cwe)


def test_curated_text_fills_gaps_for_a_known_template_without_template_data() -> None:
    g = enrich(_nuclei("nuclei_classified.jsonl")["tech-detect"])
    assert g.description and g.remediation
    assert g.cwe == ["CWE-200"]  # the parser's CWE wins over the table


def test_unknown_template_passes_through_unchanged() -> None:
    f = _nuclei("nuclei_classified.jsonl")["custom-unknown-template"]
    assert enrich(f) == f


def test_nmap_open_ports_are_enriched_by_service() -> None:
    fs = {f.title: f for f in _nmap(_read("nmap_scanme.txt"))}
    ssh = fs["Open port 22/tcp (ssh)"]
    g = enrich(ssh)
    assert g.description and g.remediation != ssh.remediation and g.references
    assert _frozen(g) == _frozen(ssh)
    unknown = fs["Open port 9929/tcp (nping-echo)"]
    assert enrich(unknown) == unknown


@pytest.mark.parametrize("service", ["ssh", "http", "https", "ftp", "telnet", "smtp",
                                     "ms-wbt-server", "mysql", "microsoft-ds", "domain"])
def test_common_services_are_covered(service: str) -> None:
    (f,) = _nmap(f"22/tcp open {service} something\n")
    assert enrich(f).description


def test_service_names_with_a_question_mark_still_match() -> None:
    (f,) = _nmap("22/tcp open ssh? \n")
    assert enrich(f).description


def test_cleartext_services_carry_cwe_319_and_keep_severity() -> None:
    (f,) = _nmap("23/tcp open telnet Linux telnetd\n")
    g = enrich(f)
    assert "CWE-319" in g.cwe and g.severity == f.severity == "low"


def test_enrich_is_pure_idempotent_and_does_not_mutate_input() -> None:
    f = _nuclei()["apache-detect"]
    before = f.model_dump()
    g = enrich(f)
    assert f.model_dump() == before
    assert enrich(g) == g


def test_a_hostile_nmap_title_cannot_match_a_nuclei_table_entry() -> None:
    (f,) = _nmap("22/tcp open ssh x\n")
    hostile = f.model_copy(update={"title": "Open port 22/tcp (apache-detect)"})
    assert "apache" not in enrich(hostile).description.lower()


def test_a_template_name_containing_parentheses_does_not_confuse_lookup() -> None:
    f = _nuclei()["apache-detect"].model_copy(
        update={"title": "Apache (tech-detect) Detection (apache-detect)", "description": ""})
    assert "apache" in enrich(f).description.lower()


def test_titles_without_a_trailing_id_are_left_alone() -> None:
    f = _nuclei()["apache-detect"].model_copy(update={"title": "weird title", "description": ""})
    assert enrich(f) == f


def test_foreign_host_findings_are_enriched_but_stay_hypotheses() -> None:
    f = _nuclei()["cdn-redirect-detect"]
    g = enrich(f)
    assert g.confidence == "hypothesis" and g.severity == "info"
    assert g.audit_refs == f.audit_refs and g.evidence == f.evidence


def test_curated_table_entries_are_well_formed() -> None:
    for table in (enrich_mod.NUCLEI_TABLE, enrich_mod.NMAP_SERVICE_TABLE):
        for key, entry in table.items():
            assert re.fullmatch(r"[a-z0-9][a-z0-9_.\-]*", key)
            assert entry.description and entry.remediation
            assert all(re.fullmatch(r"CWE-\d{1,5}", c) for c in entry.cwe)
            assert all(r.startswith("https://") for r in entry.references)
            assert not entry.remediation.startswith(GENERIC_REMEDIATION_PREFIXES)
    for must in ("http-missing-security-headers", "tech-detect", "waf-detect", "apache-detect"):
        assert must in enrich_mod.NUCLEI_TABLE


def test_generic_remediation_prefixes_match_what_the_parsers_emit() -> None:
    (n,) = _nmap("22/tcp open ssh x\n")
    (u,) = parse_nuclei(
        '{"template-id":"zz","info":{"name":"Z","severity":"info"},"matched-at":"http://scanme.nmap.org/"}',
        **KW)  # type: ignore[arg-type]
    assert n.remediation.startswith(GENERIC_REMEDIATION_PREFIXES)
    assert u.remediation.startswith(GENERIC_REMEDIATION_PREFIXES)
