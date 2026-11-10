"""Machine-readable reports share the Markdown renderer's evidence and citation boundary."""

import json

import pytest

from test_report import CONTROLS, HEAD, finding, result_event
from viper.report.formats import render_json, render_sarif


def test_json_schema_counts_fields_and_resolved_unresolved_citations():
    findings = [finding(description="SSH service", cwe=["CWE-200"]),
                finding(id="F2", confidence="hypothesis", severity="medium", audit_refs=["b" * 64])]
    data = json.loads(render_json(findings, [result_event()], project_id="lab", thread_id="t1"))
    assert data["schema"] == "viper-report/1"
    assert data["counts"]["total"] == 2
    assert data["counts"]["by_severity_and_confidence"]["medium"]["hypothesis"] == 1
    assert data["findings"][0]["description"] == "SSH service"
    assert data["findings"][0]["cwe"] == ["CWE-200"]
    assert [c["status"] for c in data["audit_citations"]] == ["resolved", "unresolved"]
    assert data["audit_citations"][0]["reference"] == HEAD


def test_sarif_rule_deduplication_levels_locations_and_fingerprints():
    findings = [finding(id="F1", evidence="22/tcp open ssh", severity="low"),
                finding(id="F2", evidence="22/tcp open ssh", severity="high"),
                finding(id="F3", source_tool="nuclei", title="Headers (http-missing-security-headers)",
                        evidence='{"template-id":"http-missing-security-headers"}', severity="medium")]
    data = json.loads(render_sarif(findings, [], project_id="lab", thread_id="t1"))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "Viper"
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert [r["level"] for r in run["results"]] == ["note", "error", "warning"]
    result = run["results"][0]
    assert result["message"]["text"] == findings[0].title
    assert result["properties"]["confidence"] == "confirmed"
    assert result["properties"]["audit_refs"] == [HEAD]
    assert result["locations"][0]["logicalLocations"][0]["name"] == "scanme.nmap.org"
    assert result["partialFingerprints"]["viperFindingId/v1"] == "F1"


@pytest.mark.parametrize("renderer", [render_json, render_sarif])
def test_every_export_neutralizes_hostile_strings_without_leaking_event_payloads(renderer):
    bad = "hostile" + CONTROLS + "<script>```&"
    value = finding(id=bad, title=bad, affected_asset=bad, source_action_id=bad,
                    evidence=bad, description=bad, cwe=[bad], references=[bad], audit_refs=[bad],
                    remediation=bad, reproducibility=bad, severity_rationale=bad)
    event = result_event()
    event["detail"]["secret"] = "must-never-appear"  # noqa: S105 -- sentinel, not a credential
    text = renderer([value], [event], project_id=bad, thread_id=bad)
    data = json.loads(text)
    for char in CONTROLS:
        assert char not in str(data)
    assert "must-never-appear" not in text
    assert "\\\\x1b" in text and "\\\\u202e" in text


@pytest.mark.parametrize("events", [[], [result_event(), result_event()],
                                   [{**result_event(), "event": "tool_dispatch"}]])
def test_export_citations_do_not_resolve_missing_duplicate_or_intent_events(events):
    data = json.loads(render_json([finding()], events, project_id="p", thread_id="t1"))
    assert data["audit_citations"][0]["status"] == "unresolved"


@pytest.mark.parametrize("severity,level", [("info", "note"), ("low", "note"),
                                           ("medium", "warning"), ("high", "error"),
                                           ("critical", "error")])
def test_sarif_severity_mapping(severity, level):
    data = json.loads(render_sarif([finding(severity=severity)], [], project_id="p", thread_id="t"))
    assert data["runs"][0]["results"][0]["level"] == level


@pytest.mark.parametrize("renderer", [render_json, render_sarif])
def test_empty_exports_and_foreign_citations_stay_honest(renderer):
    empty = json.loads(renderer([], [], project_id="p", thread_id="t"))
    if renderer is render_json:
        assert empty["findings"] == [] and empty["counts"]["total"] == 0
    else:
        assert empty["runs"][0]["results"] == []
        assert empty["runs"][0]["tool"]["driver"]["rules"] == []
    event = result_event()
    event["thread_id"] = "foreign"
    data = json.loads(renderer([finding()], [event], project_id="p", thread_id="t1"))
    citations = (data["audit_citations"] if renderer is render_json else
                 data["runs"][0]["results"][0]["properties"]["audit_citations"])
    assert citations[0]["status"] == "unresolved"
