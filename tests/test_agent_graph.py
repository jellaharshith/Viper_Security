import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from viper.agents.audit import AuditLog, verify
from viper.agents.graph import Deps, build_graph
from viper.config import Settings
from viper.policy.approvals import action_hash
from viper.policy.models import Action, Scope
from viper.tools.registry import default_registry

NOW = datetime(2026, 1, 1, tzinfo=UTC)
SCOPE = Scope(project_id="p1", in_scope=("example.com",))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network/subprocess used")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket.socket, "sendto", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)


def make(tmp_path: Path, actions, scope=SCOPE, clock=None):
    settings = Settings(_env_file=None, audit_dir=tmp_path)
    holder = {"scope": scope, "now": NOW}
    deps = Deps(planner=lambda _r: actions, settings=settings,
                scope_provider=lambda: holder["scope"], audit=AuditLog(settings, "p1"),
                now=lambda: holder["now"])
    graph = build_graph(deps, InMemorySaver())
    return graph, holder, deps


def run(graph, tid="t1"):
    cfg = {"configurable": {"thread_id": tid}}
    out = graph.invoke({"project_id": "p1", "thread_id": tid, "request": "go"}, cfg)
    return cfg, out


def answer(graph, cfg, decision="ALLOW", **over):
    snap = graph.get_state(cfg)
    pend = snap.tasks[0].interrupts[0].value["pending"][0]
    item = {"pending_approval_id": pend["id"], "decision": decision, "approver": "alice",
            "action_hash": pend["action_hash"], "timestamp": NOW.isoformat()}
    item.update(over)
    return graph.invoke(Command(resume=[item]), cfg)


READ = Action(action_id="r", tool_name="scope_check", args={"target": "example.com"})
BADARGS = Action(action_id="b", tool_name="plan_scan", args={"target": "example.com", "extra": 1})
PASSIVE = Action(action_id="p", tool_name="plan_scan", args={"target": "example.com"})
ACTIVE = Action(action_id="a", tool_name="active_probe_stub", args={"target": "example.com"})
OUT = Action(action_id="o", tool_name="plan_scan", args={"target": "evil.com"})
UNKNOWN = Action(action_id="u", tool_name="rm_rf", args={})


def events(path):
    import json
    return [json.loads(x)["event"] for x in path.read_text().splitlines()]


def test_read_and_passive_run_without_approval(tmp_path):
    graph, _, deps = make(tmp_path, [READ, PASSIVE])
    _, out = run(graph)
    assert out["status"] == "COMPLETED" and len(out["results"]) == 2
    assert all(r["simulated"] for r in out["results"])
    assert verify(deps.audit.path) is None


def test_denied_actions_never_execute(tmp_path):
    graph, _, deps = make(tmp_path, [OUT, UNKNOWN, PASSIVE])
    _, out = run(graph)
    assert [r["tool"] for r in out["results"]] == ["plan_scan"]
    assert out["decisions"]["o"]["type"] == "DENY" and out["decisions"]["u"]["type"] == "DENY"


def test_active_pauses_then_runs_after_approval_and_log_verifies(tmp_path):
    graph, _, deps = make(tmp_path, [PASSIVE, ACTIVE])
    cfg, out = run(graph)
    assert "__interrupt__" in out and "results" not in out
    final = answer(graph, cfg)
    assert [r["tool"] for r in final["results"]] == ["plan_scan", "active_probe_stub"]
    ev = events(deps.audit.path)
    assert "approval_requested" in ev and "approval_granted" in ev and "approval_consumed" in ev
    assert verify(deps.audit.path) is None


def test_human_deny_blocks_execution(tmp_path):
    graph, _, deps = make(tmp_path, [ACTIVE])
    cfg, _ = run(graph)
    final = answer(graph, cfg, decision="DENY")
    assert final["results"] == [] and "approval_denied" in events(deps.audit.path)


def test_tampered_action_hash_blocks_execution(tmp_path):
    graph, _, _ = make(tmp_path, [ACTIVE])
    cfg, _ = run(graph)
    final = answer(graph, cfg, action_hash=action_hash(PASSIVE, default_registry.get_info("plan_scan")))
    assert final["results"] == []


def test_expired_approval_blocks_execution(tmp_path):
    graph, holder, _ = make(tmp_path, [ACTIVE])
    cfg, _ = run(graph)
    holder["now"] = NOW + timedelta(hours=1)
    assert answer(graph, cfg)["results"] == []


def test_scope_change_during_pause_blocks_execution(tmp_path):
    graph, holder, _ = make(tmp_path, [ACTIVE])
    cfg, _ = run(graph)
    holder["scope"] = Scope(project_id="p1", in_scope=("other.com",))
    assert answer(graph, cfg)["results"] == []


def test_missing_or_garbage_answer_grants_nothing(tmp_path):
    graph, _, _ = make(tmp_path, [ACTIVE])
    cfg, _ = run(graph)
    final = graph.invoke(Command(resume=[{"bogus": 1}]), cfg)
    assert final["results"] == []


def test_audit_failure_fails_closed(tmp_path):
    graph, _, deps = make(tmp_path, [PASSIVE])
    deps.audit.path.write_text("not json\n")
    with pytest.raises(Exception):  # noqa: B017 - AuditError surfaces before any dispatch
        run(graph)


def test_invalid_args_are_denied_not_crashed(tmp_path):
    graph, _, _ = make(tmp_path, [BADARGS, PASSIVE])
    _, out = run(graph)
    assert out["decisions"]["b"]["type"] == "DENY" and len(out["results"]) == 1
