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
    resume_args = [files[0], files[1], files[4], files[5]]
    assert cli.main(["agent", "run", *files]) == 0
    assert "PAUSED" in capsys.readouterr().out
    assert cli.main(["agent", "resume", *resume_args, "--decision", "ALLOW"]) == 0
    assert "executed=2 denied=1" in capsys.readouterr().out
    assert cli.main(["audit", "verify", "--project", "demo"]) == 0
    assert "OK" in capsys.readouterr().out
    log = tmp_path / "audit" / "demo.jsonl"
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:1] + [lines[1].replace("ALLOW", "DENY")] + lines[2:]) + "\n")
    assert cli.main(["audit", "verify", "--project", "demo"]) == 2


def test_unknown_key_in_scope_is_rejected(files, tmp_path, capsys):
    (tmp_path / "scope.yaml").write_text(SCOPE + "typo_key: 1\n")
    assert cli.main(["agent", "run", *files]) == 1
    assert "ValidationError" in capsys.readouterr().out


def test_resume_denied_halts_the_whole_run(files, capsys):
    resume_args = [files[0], files[1], files[4], files[5]]
    cli.main(["agent", "run", *files])
    capsys.readouterr()
    cli.main(["agent", "resume", *resume_args, "--decision", "DENY"])
    assert "status=REJECTED executed=0" in capsys.readouterr().out


def test_resume_ignores_a_swapped_plan_and_shows_saved_action(files, capsys, tmp_path):
    cli.main(["agent", "run", *files])
    capsys.readouterr()
    resume_args = [files[0], files[1], files[4], files[5]]
    cli.main(["agent", "resume", *resume_args, "--decision", "ALLOW"])
    out = capsys.readouterr().out
    assert "tool=active_probe_stub" in out and "example.com" in out
    # there is no --plan option on resume any more
    with pytest.raises(SystemExit):
        cli.main(["agent", "resume", *files, "--decision", "ALLOW"])


def test_scope_edit_during_pause_blocks_execution(files, capsys, tmp_path):
    cli.main(["agent", "run", *files])
    capsys.readouterr()
    (tmp_path / "scope.yaml").write_text(SCOPE.replace("example.com]", "example.com, extra.test]"))
    resume_args = [files[0], files[1], files[4], files[5]]
    cli.main(["agent", "resume", *resume_args, "--decision", "ALLOW"])
    assert "executed=" in capsys.readouterr().out
    assert cli.main(["audit", "verify", "--project", "demo"]) == 0
