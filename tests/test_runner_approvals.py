"""Expired checkpoint approvals finish safely and explain recovery through the CLI."""

import argparse
from datetime import UTC, datetime, timedelta

import pytest
from langgraph.checkpoint.sqlite import SqliteSaver

from viper import cli
from viper.agents import runner
from viper.agents.audit import AuditLog, verify
from viper.agents.graph import Deps
from viper.config import Settings
from viper.policy.models import Action


@pytest.mark.parametrize("decision", ["ALLOW", "DENY"])
@pytest.mark.parametrize("minutes,overdue", [(15, 0), (16, 60)])
def test_expired_resume_reports_recovery_and_finishes_checkpoint(
    tmp_path, monkeypatch, capsys, decision, minutes, overdue,
):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    clock = [now]
    monkeypatch.setattr(runner, "Deps", lambda **kw: Deps(**kw, now=lambda: clock[0]))
    settings = Settings(_env_file=None, audit_dir=tmp_path / "audit",
                        checkpoint_db=tmp_path / "cp.db", report_dir=tmp_path / "reports")
    scope = tmp_path / "scope.yaml"
    scope.write_text("project_id: lab\nin_scope: [example.com]\n", encoding="utf-8")
    actions = [Action(action_id="passive", tool_name="plan_scan",
                      args={"target": "example.com"}),
               Action(action_id="probe", tool_name="active_probe_stub",
                      args={"target": "example.com"})]
    assert runner.run(settings, scope, actions, "scan", "old")["__interrupt__"]
    clock[0] = now + timedelta(minutes=minutes)
    args = argparse.Namespace(agent_cmd="resume", scope=str(scope), thread="old", decision=decision)
    cli.cmd_agent(settings, args)
    output = capsys.readouterr().out
    assert "approval expired" in output and "probe" in output
    assert f"{overdue} seconds" in output and "re-request approval" in output
    assert "viper agent run" in output and "new --thread" in output
    assert "agent error:" not in output
    with runner._connect(settings) as conn:
        snap = SqliteSaver(conn).get_tuple({"configurable": {"thread_id": "old"}})
        state = snap.checkpoint["channel_values"]
        assert state["status"] == "REJECTED"
        assert not state.get("results")
        assert all(p["consumed"] for p in state["pending"].values())
    events = AuditLog(settings, "lab").events("old")
    assert "approval_expired" in [e["event"] for e in events]
    assert not {"tool_dispatch", "tool_dry_run", "approval_granted"} & {e["event"] for e in events}
    assert verify(settings.audit_dir / "lab.jsonl") is None
    assert runner.pending_details(settings, scope, "old") == []
    with pytest.raises(ValueError, match="no pending approval"):
        runner.resume(settings, scope, "old", "ALLOW")
    assert runner.run(settings, scope, actions, "scan", "fresh")["__interrupt__"]
