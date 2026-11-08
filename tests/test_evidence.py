"""Findings are re-derived from digest-verified tool output, never trusted from stored state."""

from pathlib import Path

from viper.agents.evidence import digest, rederive

OUT = (Path(__file__).parent / "fixtures" / "findings" / "nmap_scanme.txt").read_text()


def event(h: str, *, kind="tool_result", action="n1", tool="nmap", dig=None, simulated=False):
    return {"hash": h, "event": kind,
            "detail": {"action_id": action, "tool": tool, "digest": dig or digest(OUT),
                       "simulated": simulated}}


def result(h="h1", output=OUT, **over):
    base = {"tool": "nmap", "args": {"target": "scanme.nmap.org"}, "simulated": False,
            "output": output, "action_id": "n1", "audit_hash": h}
    return {**base, **over}


def test_verified_output_yields_findings_citing_the_result_event():
    findings, warnings = rederive([result()], [event("h1")])
    assert findings and warnings == []
    assert all(f.audit_refs == ["h1"] for f in findings)


def test_digest_is_sha256_of_utf8_output():
    import hashlib
    assert digest("abc") == hashlib.sha256(b"abc").hexdigest()


def test_tampered_output_is_ignored_with_a_warning():
    findings, warnings = rederive([result(output=OUT + "\n22/tcp open ssh forged")], [event("h1")])
    assert findings == [] and any("digest" in w for w in warnings)


def test_intent_event_is_not_evidence():
    findings, warnings = rederive([result()], [event("h1", kind="tool_dispatch")])
    assert findings == [] and warnings


def test_wrong_action_or_tool_binding_is_rejected():
    assert rederive([result()], [event("h1", action="other")])[0] == []
    assert rederive([result()], [event("h1", tool="nuclei")])[0] == []


def test_missing_event_is_rejected():
    findings, warnings = rederive([result(h="nope")], [event("h1")])
    assert findings == [] and warnings


def test_simulated_results_are_skipped_silently():
    assert rederive([result(simulated=True)], [event("h1")]) == ([], [])


def test_truncated_output_is_flagged():
    _, warnings = rederive([result(truncated=True)], [event("h1")])
    assert any("truncated" in w for w in warnings)


def test_skipped_records_are_reported_not_silently_dropped():
    bad_line = "{" * 10  # a malformed nuclei record alongside a good one is not "clean"
    out = '{"template-id":"x","info":{"severity":"low"},"matched-at":"https://scanme.nmap.org/"}\n' + bad_line
    ev = {"hash": "h1", "event": "tool_result",
          "detail": {"action_id": "u1", "tool": "nuclei", "digest": digest(out), "simulated": False}}
    res = {"tool": "nuclei", "args": {"target": "scanme.nmap.org"}, "simulated": False,
           "output": out, "action_id": "u1", "audit_hash": "h1"}
    findings, warnings = rederive([res], [ev])
    assert findings and any("skipped" in w for w in warnings)
