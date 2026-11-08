"""`viper exec` verbs: human take-over blocks agent dispatch end-to-end; VM verbs need config."""

from __future__ import annotations

import json

import pytest

from viper import cli

SCOPE = "project_id: demo\nin_scope: [example.com]\nexclusions: []\n"
PLAN = [{"action_id": "p", "tool_name": "plan_scan", "args": {"target": "example.com"}}]


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.setenv("VIPER_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("VIPER_CHECKPOINT_DB", str(tmp_path / "cp.db"))
    monkeypatch.delenv("VIPER_EXEC_API_URL", raising=False)
    (tmp_path / "scope.yaml").write_text(SCOPE)
    (tmp_path / "plan.json").write_text(json.dumps(PLAN))
    return ["--scope", str(tmp_path / "scope.yaml"), "--plan", str(tmp_path / "plan.json"),
            "--thread", "t1"]


def test_passive_action_runs_when_no_one_has_taken_over(files, capsys):
    assert cli.main(["agent", "run", *files]) == 0
    assert "status=COMPLETED executed=1" in capsys.readouterr().out


def test_human_takeover_blocks_agent_dispatch(files, capsys):
    assert cli.main(["exec", "takeover", "--project", "demo"]) == 0
    capsys.readouterr()
    assert cli.main(["agent", "run", *files]) == 0
    assert "status=REJECTED executed=0" in capsys.readouterr().out


def test_release_restores_agent_dispatch(files, capsys):
    cli.main(["exec", "takeover", "--project", "demo"])
    assert cli.main(["exec", "release", "--project", "demo"]) == 0
    capsys.readouterr()
    assert cli.main(["agent", "run", *files]) == 0
    assert "status=COMPLETED executed=1" in capsys.readouterr().out


def test_vm_verb_errors_cleanly_when_exec_api_is_not_configured(files, capsys):
    assert cli.main(["exec", "watch", "--job", "j1"]) == 1
    assert "not configured" in capsys.readouterr().out
