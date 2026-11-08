"""Report evidence must remain traceable and cannot inject Markdown sections."""

import pytest

from viper.findings.models import Finding
from viper.report.generator import render_report

HEAD = "a" * 64


def result_event() -> dict:
    return dict(hash=HEAD, thread_id="t1", event="tool_result", seq=4, detail={
        "action_id": "scan1", "tool": "nmap", "digest": "b" * 64, "simulated": False,
    })


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
    report = render_report([finding()], [result_event()], project_id="lab", thread_id="t1")
    for value in ["Open SSH", "scanme.nmap.org", "22/tcp open ssh", "info", "Exposure alone",
                  "confirmed", "nmap -p22", "Restrict access", "https://nmap.org/", HEAD,
                  r"tool\_result", "scan1", "lab", "t1"]:
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
    foreign = result_event()
    foreign["thread_id"] = "other"
    wrong_action = result_event()
    wrong_action["detail"]["action_id"] = "other"
    for event in [foreign, wrong_action]:
        report = render_report([finding()], [event], project_id="p", thread_id="t1")
        assert "Unresolved" in report


@pytest.mark.parametrize("kind", ["policy_decision", "tool_dispatch", "tool_dry_run", "tool_executed", None])
def test_only_result_events_can_back_citations(kind: str | None) -> None:
    event = result_event()
    event["event"] = kind
    report = render_report([finding()], [event], project_id="p", thread_id="t1")
    assert "Unresolved audit reference" in report
    assert "[audit-1](#audit-1)" not in report


@pytest.mark.parametrize("field,value", [
    ("tool", "nuclei"), ("tool", None), ("action_id", "other"),
    ("simulated", True), ("simulated", None), ("simulated", 0), ("simulated", "false"),
])
def test_result_citations_require_exact_tool_action_and_false_simulation(field: str, value: object) -> None:
    event = result_event()
    event["detail"][field] = value
    report = render_report([finding()], [event], project_id="p", thread_id="t1")
    assert "Unresolved audit reference" in report
    assert "[audit-1](#audit-1)" not in report


def test_missing_or_ambiguous_result_hashes_stay_unresolved() -> None:
    for events in [[], [result_event(), result_event()]]:
        report = render_report([finding()], events, project_id="p", thread_id="t1")
        assert "Unresolved audit reference" in report
        assert "[audit-1](#audit-1)" not in report


@pytest.mark.parametrize("field", ["tool", "action_id", "simulated"])
def test_missing_result_binding_is_unresolved(field: str) -> None:
    event = result_event()
    del event["detail"][field]
    report = render_report([finding()], [event], project_id="p", thread_id="t1")
    assert "Unresolved audit reference" in report


CONTROLS = "".join(chr(n) for n in [*range(32), *range(127, 160), 0x061C, 0x200E, 0x200F,
                                    *range(0x202A, 0x202F), *range(0x2066, 0x206A)])


@pytest.mark.parametrize("field", [
    "id", "title", "affected_asset", "source_action_id", "evidence", "severity_rationale",
    "reproducibility", "remediation", "references", "audit_refs", "project_id", "thread_id", "seq",
])
def test_controls_are_visible_in_every_unrestricted_printed_field(field: str) -> None:
    value = "start" + CONTROLS + "end"
    project, thread = "lab", "t1"
    event = result_event()
    changes: dict[str, object] = {}
    if field == "project_id":
        project = value
    elif field == "thread_id":
        thread = value
        event["thread_id"] = thread
    elif field == "seq":
        event["seq"] = value
    else:
        changes[field] = [value] if field in {"references", "audit_refs"} else value
        if field == "source_action_id":
            event["detail"]["action_id"] = value
    report = render_report([finding(**changes)], [event], project_id=project, thread_id=thread)
    for char in CONTROLS:
        if char != "\n":  # the renderer's own layout still uses newlines
            assert char not in report
        code = ord(char)
        escape = f"\\x{code:02x}" if code < 256 else f"\\u{code:04x}"
        assert escape in report


def test_osc_clipboard_and_hyperlink_sequences_are_inert_printable_evidence() -> None:
    evidence = "\x1b]52;c;YXR0YWNr\x07\x1b]8;;https://evil.example/\x1b\\click\x1b]8;;\x1b\\"
    report = render_report([finding(evidence=evidence)], [], project_id="p", thread_id="t")
    assert "\x1b" not in report and "\x07" not in report
    assert r"\x1b]52;c;YXR0YWNr\x07" in report
    assert r"\x1b]8;;https://evil.example/" in report


def test_evidence_cannot_break_out_or_inject_html() -> None:
    report = render_report([finding(evidence="```\n# forged\n<script>x</script>",
                                    title="<img src=x>\n## forged")], [], project_id="p", thread_id="t")
    assert "\n# forged" not in report
    assert "<script>" not in report
    assert "<img" not in report
    assert "    ```" in report
