import json

import pytest

from viper import cli

SCOPE = "project_id: demo\nin_scope: [example.com]\nexclusions: [admin.example.com]\n"
PLAN = [
    {"action_id": "p", "tool_name": "plan_scan", "args": {"target": "example.com"}},
    {"action_id": "a", "tool_name": "active_probe_stub", "args": {"target": "example.com"}},
    {"action_id": "x", "tool_name": "plan_scan", "args": {"target": "evil.com"}},
]


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.setenv("VIPER_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("VIPER_CHECKPOINT_DB", str(tmp_path / "cp.db"))
    scope = tmp_path / "scope.yaml"
    scope.write_text(SCOPE)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN))
    yield ["--scope", str(scope), "--plan", str(plan), "--thread", "t1"]


def test_run_pause_resume_verify(files, capsys, tmp_path):
    assert cli.main(["agent", "run", *files]) == 0
    assert "PAUSED" in capsys.readouterr().out
    assert cli.main(["agent", "resume", *files, "--decision", "ALLOW"]) == 0
    assert "executed=2 denied=1" in capsys.readouterr().out
    assert cli.main(["audit", "verify", "--project", "demo"]) == 0
    assert "OK" in capsys.readouterr().out
    log = tmp_path / "audit" / "demo.jsonl"
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:1] + [lines[1].replace("ALLOW", "DENY")] + lines[2:]) + "\n")
    assert cli.main(["audit", "verify", "--project", "demo"]) == 2


def test_unknown_key_in_scope_is_rejected(files, tmp_path, capsys):
    (tmp_path / "scope.yaml").write_text(SCOPE + "typo_key: 1\n")
    with pytest.raises(Exception):  # noqa: B017 - strict scope schema rejects unknown keys
        cli.main(["agent", "run", *files])


def test_resume_denied_executes_only_safe_action(files, capsys):
    cli.main(["agent", "run", *files])
    capsys.readouterr()
    cli.main(["agent", "resume", *files, "--decision", "DENY"])
    assert "executed=1" in capsys.readouterr().out
