"""M7: execute -> analyze -> report. Real parsers + report on fake executor output; offline."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from viper.agents.audit import AuditError, AuditLog
from viper.agents.graph import Deps, build_graph
from viper.config import Settings
from viper.policy.models import Action, Scope
from viper.tools.registry import DryRunResult, default_registry

FIX = Path(__file__).parent / "fixtures" / "findings"
NOW = datetime(2026, 1, 1, tzinfo=UTC)
SCOPE = Scope(project_id="lab", in_scope=("scanme.nmap.org",))
NMAP = Action(action_id="n1", tool_name="nmap",
              args={"target": "scanme.nmap.org", "ports": "22,80", "service_detection": True})


class FakeExec:
    def __init__(self, output: str, simulated: bool = False) -> None:
        self.output, self.simulated = output, simulated

    def run(self, action: Action) -> DryRunResult:
        return DryRunResult(tool=action.tool_name, args=dict(action.args), summary="ok",
                            simulated=self.simulated, output=self.output)


def build(tmp_path: Path, executor=None, actions=(NMAP,)):
    settings = Settings(_env_file=None, audit_dir=tmp_path, allow_active_testing=True)
    deps = Deps(planner=lambda _r: list(actions), settings=settings, scope_provider=lambda: SCOPE,
                audit=AuditLog(settings, "lab"), registry=default_registry, executor=executor,
                now=lambda: NOW)
    return build_graph(deps, InMemorySaver()), deps


def run_approved(graph, tid="t1"):
    cfg = {"configurable": {"thread_id": tid}}
    graph.invoke({"project_id": "lab", "thread_id": tid, "request": "scan"}, cfg)
    pend = graph.get_state(cfg).tasks[0].interrupts[0].value["pending"]
    answers = [{"pending_approval_id": p["id"], "decision": "ALLOW", "approver": "alice",
                "action_hash": p["action_hash"], "timestamp": NOW.isoformat()} for p in pend]
    return graph.invoke(Command(resume=answers), cfg)


def events(deps: Deps) -> list[str]:
    return [e["event"] for e in deps.audit.events("t1")]


def test_real_output_becomes_findings_and_a_traceable_report(tmp_path):
    graph, deps = build(tmp_path, FakeExec((FIX / "nmap_scanme.txt").read_text()))
    out = run_approved(graph)
    assert out["status"] == "COMPLETED"
    confirmed = [f for f in out["findings"] if f["confidence"] == "confirmed"]
    assert confirmed and all(f["source_action_id"] == "n1" for f in out["findings"])
    # every finding cites the audit event that backs it, and that event really exists
    hashes = {e["hash"] for e in deps.audit.events("t1")}
    assert all(f["audit_refs"] and set(f["audit_refs"]) <= hashes for f in out["findings"])
    assert "# Viper assessment report" in out["report"]
    assert all(h in out["report"] for f in out["findings"] for h in f["audit_refs"])


def test_real_dispatch_is_audited_as_tool_executed_not_dry_run(tmp_path):
    graph, deps = build(tmp_path, FakeExec((FIX / "nmap_scanme.txt").read_text()))
    run_approved(graph)
    seen = events(deps)
    assert "tool_executed" in seen and "tool_dry_run" not in seen
    assert seen.index("tool_executed") < seen.index("findings_generated") < seen.index("report_generated")


def test_dry_run_plane_yields_no_findings_and_keeps_dry_run_event(tmp_path):
    graph, deps = build(tmp_path, executor=None)  # default DryRunExecutor
    out = run_approved(graph)
    assert out["status"] == "COMPLETED" and out["findings"] == []
    assert "tool_dry_run" in events(deps) and "tool_executed" not in events(deps)
    assert "No confirmed findings" in out["report"] or "no confirmed" in out["report"].lower()


def test_unparseable_output_does_not_invent_findings(tmp_path):
    graph, _ = build(tmp_path, FakeExec("garbage \x00 not nmap output"))
    out = run_approved(graph)
    assert out["status"] == "COMPLETED" and out["findings"] == []


def test_tampered_audit_log_refuses_to_produce_a_report(tmp_path):
    graph, deps = build(tmp_path, FakeExec((FIX / "nmap_scanme.txt").read_text()))
    cfg = {"configurable": {"thread_id": "t1"}}
    graph.invoke({"project_id": "lab", "thread_id": "t1", "request": "scan"}, cfg)
    raw = deps.audit.path.read_bytes().replace(b'"actor":"agent"', b'"actor":"human"', 1)
    deps.audit.path.write_bytes(raw)
    pend = graph.get_state(cfg).tasks[0].interrupts[0].value["pending"]
    answers = [{"pending_approval_id": p["id"], "decision": "ALLOW", "approver": "alice",
                "action_hash": p["action_hash"], "timestamp": NOW.isoformat()} for p in pend]
    with pytest.raises(AuditError):  # the approval audit append already trips on the broken chain
        graph.invoke(Command(resume=answers), cfg)
