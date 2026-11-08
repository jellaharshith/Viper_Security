"""Report evidence must remain traceable and cannot inject Markdown sections."""

from viper.findings.models import Finding
from viper.report.generator import render_report

HEAD = "a" * 64


def finding(**changes: object) -> Finding:
    data = dict(
        id="F1", title="Open SSH", affected_asset="scanme.nmap.org", source_tool="nmap",
        source_action_id="scan1", evidence="22/tcp open ssh", severity="info",
        severity_rationale="Exposure alone is not a vulnerability", confidence="confirmed",
        reproducibility="nmap -p22 scanme.nmap.org", remediation="Restrict access if unnecessary",
        references=["https://nmap.org/"], audit_refs=[HEAD],
    )
    data.update(changes)
    return Finding.model_validate(data)


def test_report_fields_and_resolved_audit_citation() -> None:
    report = render_report([finding()], [dict(
        hash=HEAD, thread_id="t1", event="tool_executed", seq=4,
        detail={"action_id": "scan1"},
    )], project_id="lab", thread_id="t1")
    for value in ["Open SSH", "scanme.nmap.org", "22/tcp open ssh", "info", "Exposure alone",
                  "confirmed", "nmap -p22", "Restrict access", "https://nmap.org/", HEAD,
                  r"tool\_executed", "scan1", "lab", "t1"]:
        assert value in report
    assert "[audit-1]" in report
    assert "Unresolved" not in report


def test_hypotheses_separated_and_nothing_confirmed_is_explicit() -> None:
    report = render_report([finding(confidence="hypothesis")], [], project_id="p", thread_id="t")
    assert "No confirmed findings" in report
    assert report.index("## Confirmed findings") < report.index("## Hypotheses") < report.index("### F1")
    assert "Unresolved" in report


def test_empty_report_and_foreign_or_wrong_action_events_never_resolve() -> None:
    assert "No confirmed findings" in render_report([], [], project_id="p", thread_id="t")
    for event in [dict(hash=HEAD, thread_id="other", detail={"action_id": "scan1"}),
                  dict(hash=HEAD, thread_id="t", detail={"action_id": "other"})]:
        report = render_report([finding()], [event], project_id="p", thread_id="t")
        assert "Unresolved" in report


def test_evidence_cannot_break_out_or_inject_html() -> None:
    report = render_report([finding(evidence="```\n# forged\n<script>x</script>",
                                    title="<img src=x>\n## forged")], [], project_id="p", thread_id="t")
    assert "\n# forged" not in report
    assert "<script>" not in report
    assert "<img" not in report
    assert "    ```" in report
