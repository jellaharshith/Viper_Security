"""Findings are re-derived from the AUDITED tool results; the checkpoint is only a cache.

The verified audit log is the authority: every real ``tool_result`` event must be matched by
exactly one checkpoint result with the same binding, digest and arguments.
"""

import hashlib
from pathlib import Path

from viper.agents.evidence import digest, rederive

OUT = (Path(__file__).parent / "fixtures" / "findings" / "nmap_scanme.txt").read_text()
ARGS = {"target": "scanme.nmap.org", "ports": "22,80"}
ACTION = {"action_id": "n1", "tool_name": "nmap", "args": ARGS}


def bind(action: dict) -> str:
    """Stand-in for policy.approvals.action_hash: any stable function of the action."""
    return hashlib.sha256(repr((action["tool_name"], sorted(action["args"].items()))).encode()).hexdigest()


def event(h="h1", *, kind="tool_result", action="n1", tool="nmap", dig=None, simulated=False,
          truncated=False, ahash=None):
    return {"hash": h, "event": kind, "action_hash": ahash or bind(ACTION),
            "detail": {"action_id": action, "tool": tool, "digest": dig or digest(OUT),
                       "simulated": simulated, "truncated": truncated}}


def result(h="h1", output=OUT, **over):
    base = {"tool": "nmap", "args": dict(ARGS), "simulated": False, "output": output,
            "action_id": "n1", "audit_hash": h, "truncated": False}
    return {**base, **over}


def run(results, events, actions=None):
    return rederive(results, events, actions=actions if actions is not None else [ACTION], bind=bind)


def test_verified_output_yields_findings_citing_the_result_event():
    findings, warnings = run([result()], [event()])
    assert findings and warnings == []
    assert all(f.audit_refs == ["h1"] for f in findings)


def test_digest_is_sha256_of_utf8_output():
    assert digest("abc") == hashlib.sha256(b"abc").hexdigest()


def test_tampered_output_is_ignored_with_a_warning():
    findings, warnings = run([result(output=OUT + "\n22/tcp open ssh forged")], [event()])
    assert findings == [] and any("digest" in w for w in warnings)


def test_intent_event_is_not_evidence():
    findings, warnings = run([result()], [event(kind="tool_dispatch")])
    assert findings == [] and any("no audited" in w or "without" in w for w in warnings)


def test_edited_target_in_checkpoint_args_is_rejected():  # codex R1
    forged = result(args={**ARGS, "target": "evil.example"})
    findings, warnings = run([forged], [event()])
    assert findings == [] and warnings


def test_edited_action_in_checkpoint_is_rejected():
    other = {**ACTION, "args": {**ARGS, "ports": "1-65535"}}
    findings, warnings = run([result()], [event()], actions=[other])
    assert findings == [] and warnings


def test_flipping_simulated_in_checkpoint_does_not_create_findings():  # codex R1
    findings, warnings = run([result(simulated=True)], [event()])
    assert findings == [] and warnings


def test_clearing_truncated_in_checkpoint_cannot_hide_the_warning():  # codex R1
    _, warnings = run([result(truncated=False)], [event(truncated=True)])
    assert any("truncated" in w for w in warnings)


def test_removing_a_checkpoint_result_is_detected_not_clean():  # codex R2
    findings, warnings = run([], [event()])
    assert findings == [] and any("missing" in w for w in warnings)


def test_duplicate_checkpoint_results_for_one_event_are_rejected():
    findings, warnings = run([result(), result()], [event()])
    assert findings == [] and warnings


def test_result_without_any_audit_event_is_ignored_with_a_warning():
    findings, warnings = run([result(h="ghost")], [])
    assert findings == [] and any("no audit event" in w or "ignored" in w for w in warnings)


def test_simulated_runs_with_no_real_events_are_silent():
    assert run([result(simulated=True, h="d1")], []) == ([], [])


def test_skipped_records_are_reported_not_silently_dropped():
    bad_line = "{" * 10
    out = '{"template-id":"x","info":{"severity":"low"},"matched-at":"https://scanme.nmap.org/"}\n' + bad_line
    nuclei = {"action_id": "u1", "tool_name": "nuclei", "args": {"target": "scanme.nmap.org"}}
    ev = {"hash": "h1", "event": "tool_result", "action_hash": bind(nuclei),
          "detail": {"action_id": "u1", "tool": "nuclei", "digest": digest(out),
                     "simulated": False, "truncated": False}}
    res = {"tool": "nuclei", "args": {"target": "scanme.nmap.org"}, "simulated": False,
           "output": out, "action_id": "u1", "audit_hash": "h1", "truncated": False}
    findings, warnings = run([res], [ev], actions=[nuclei])
    assert findings and any("skipped" in w for w in warnings)
