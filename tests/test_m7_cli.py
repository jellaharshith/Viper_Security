"""M7 CLI: saved reports, safe thread ids, opt-in LLM planner, mock audit anchoring. Offline."""

import json

import pytest

from viper import cli

SCOPE = "project_id: demo\nin_scope: [example.com]\n"
PLAN = [{"action_id": "p", "tool_name": "plan_scan", "args": {"target": "example.com"}}]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("VIPER_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("VIPER_CHECKPOINT_DB", str(tmp_path / "cp.db"))
    monkeypatch.setenv("VIPER_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("VIPER_OLLAMA_MODEL", "")  # never reach a real model
    scope = tmp_path / "scope.yaml"
    scope.write_text(SCOPE)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN))
    return {"scope": str(scope), "plan": str(plan), "tmp": tmp_path}


def run_plan(env, thread="t1"):
    return cli.main(["agent", "run", "--scope", env["scope"], "--plan", env["plan"], "--thread", thread])


def test_run_saves_report_and_report_command_prints_it(env, capsys):
    assert run_plan(env) == 0
    saved = env["tmp"] / "reports" / "t1.md"
    assert saved.exists() and "# Viper assessment report" in saved.read_text(encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["report", "--thread", "t1"]) == 0
    assert "# Viper assessment report" in capsys.readouterr().out


def test_report_for_unknown_thread_fails_cleanly(env, capsys):
    assert cli.main(["report", "--thread", "nope"]) == 1
    assert "report error" in capsys.readouterr().out


@pytest.mark.parametrize("thread", ["../evil", "a/b", "..", "a b", ""])
def test_unsafe_thread_ids_are_rejected_everywhere(env, capsys, thread):
    assert run_plan(env, thread) == 1
    assert cli.main(["report", "--thread", thread]) == 1
    assert not (env["tmp"].parent / "evil.md").exists()


def test_llm_planner_is_opt_in_and_fails_closed_without_a_model(env, capsys):
    rc = cli.main(["agent", "run", "--scope", env["scope"], "--llm", "--request", "scan it",
                   "--thread", "t2"])
    assert rc == 1 and "PlannerError" in capsys.readouterr().out
    assert not (env["tmp"] / "reports" / "t2.md").exists()


def test_plan_and_llm_are_mutually_exclusive(env):
    with pytest.raises(SystemExit):
        cli.main(["agent", "run", "--scope", env["scope"], "--plan", env["plan"], "--llm",
                  "--thread", "t3"])


def test_audit_anchor_records_a_receipt_and_verify_reports_it(env, capsys):
    assert run_plan(env) == 0
    capsys.readouterr()
    assert cli.main(["audit", "anchor", "--project", "demo"]) == 0
    anchors = env["tmp"] / "audit" / "demo.anchors.jsonl"
    assert anchors.exists() and json.loads(anchors.read_text().splitlines()[0])["provider"] == "mock"
    capsys.readouterr()
    assert cli.main(["audit", "verify", "--project", "demo"]) == 0
    out = capsys.readouterr().out
    assert "audit log OK" in out and "anchor" in out.lower()


def test_anchor_for_a_head_not_in_the_chain_is_flagged(env, capsys):
    assert run_plan(env) == 0
    assert cli.main(["audit", "anchor", "--project", "demo"]) == 0
    anchors = env["tmp"] / "audit" / "demo.anchors.jsonl"
    rec = json.loads(anchors.read_text().splitlines()[0])
    rec["head_hash"] = "0" * 63 + "1"
    anchors.write_text(json.dumps(rec) + "\n")
    capsys.readouterr()
    rc = cli.main(["audit", "verify", "--project", "demo"])
    assert rc == 2 and "MISMATCH" in capsys.readouterr().out


def test_a_finished_thread_cannot_be_reused_or_overwritten(env, capsys):
    assert run_plan(env) == 0
    saved = env["tmp"] / "reports" / "t1.md"
    first = saved.read_text(encoding="utf-8")
    capsys.readouterr()
    assert run_plan(env) == 1  # same thread id again
    assert "agent error" in capsys.readouterr().out
    assert saved.read_text(encoding="utf-8") == first


def test_existing_report_file_blocks_a_new_run_before_anything_executes(env, capsys):
    (env["tmp"] / "reports").mkdir()
    (env["tmp"] / "reports" / "t9.md").write_text("planted", encoding="utf-8")
    assert run_plan(env, "t9") == 1
    assert not (env["tmp"] / "audit" / "demo.jsonl").exists()


def test_terminal_output_has_control_and_bidi_characters_stripped(env, capsys):
    (env["tmp"] / "reports").mkdir()
    nasty = "ok" + chr(27) + "]52;c;SGVsbG8=" + chr(7) + chr(0x202E) + "tail" + chr(10)
    (env["tmp"] / "reports" / "t8.md").write_text(nasty, encoding="utf-8")
    assert cli.main(["report", "--thread", "t8"]) == 0
    out = capsys.readouterr().out
    assert chr(27) not in out and chr(7) not in out and chr(0x202E) not in out
    assert "ok" in out and "tail" in out
