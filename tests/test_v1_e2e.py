"""V1 offline rehearsal: scope draft -> approve -> agent run (nmap + nuclei) -> approve -> report.

Real code paths end to end; the only fakes are the model (``llm_chat``) and the VM executor
(``make_executor``), so there is no network and no scan. Fixtures are the recorded tool outputs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from viper import cli
from viper.agents import runner
from viper.agents.audit import AuditLog
from viper.config import Settings
from viper.policy.models import Action
from viper.tools.registry import DryRunResult

FIX = Path(__file__).parent / "fixtures" / "findings"
HOST = "scanme.nmap.org"
PROJECT = "lab-scanme"
PROGRAM = f"Lab program. In scope: {HOST} only. No DoS, no brute force."
REPLY = json.dumps({
    "evidence_ref": "https://nmap.org/book/legal-issues.html",
    "in_scope": [HOST],
    "exclusions": [],
    "forbidden_techniques": ["dos", "bruteforce"],
    "ambiguities": [],
})
PLAN = [
    {"action_id": "n1", "tool_name": "nmap", "args": {"target": HOST, "ports": "22,80"}},
    {"action_id": "u1", "tool_name": "nuclei", "args": {"target": HOST}},
]


class FakeExecutor:
    """Stands in for the VM: returns recorded tool output, records what was asked of it."""

    def __init__(self) -> None:
        self.ran: list[str] = []

    def run(self, action: Action) -> DryRunResult:
        self.ran.append(action.action_id)
        name = {"nmap": "nmap_scanme.txt", "nuclei": "nuclei_real.jsonl"}[action.tool_name]
        return DryRunResult(tool=action.tool_name, args=dict(action.args),
                            summary=f"fixture {name}", simulated=False,
                            output=(FIX / name).read_text(encoding="utf-8"))


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("VIPER_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("VIPER_CHECKPOINT_DB", str(tmp_path / "cp.db"))
    monkeypatch.setenv("VIPER_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("VIPER_OLLAMA_MODEL", "fake")
    monkeypatch.setenv("VIPER_ALLOW_ACTIVE_TESTING", "true")
    monkeypatch.setattr(runner, "llm_chat", lambda _settings: (lambda _messages: REPLY))
    executor = FakeExecutor()
    monkeypatch.setattr(runner, "make_executor", lambda *_a, **_k: executor)
    text = tmp_path / "program.txt"
    text.write_text(PROGRAM, encoding="utf-8")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN), encoding="utf-8")
    return {"tmp": tmp_path, "text": str(text), "plan": str(plan), "executor": executor,
            "scopes": tmp_path / "scopes"}


def _draft(env: dict[str, Any]) -> int:
    return cli.main(["scope", "draft", "--text-file", env["text"], "--project", PROJECT,
                     "--program-url", "https://example.test/p", "--out", str(env["scopes"])])


def _approve(env: dict[str, Any], confirm: str | None = PROJECT) -> int:
    args = ["scope", "approve", "--draft", str(env["scopes"] / f"{PROJECT}.draft.yaml")]
    if confirm is not None:
        args += ["--confirm", confirm]
    return cli.main(args)


def _events(env: dict[str, Any], thread: str) -> list[dict[str, Any]]:
    settings = Settings(_env_file=None, audit_dir=env["tmp"] / "audit")
    return AuditLog(settings, PROJECT).events(thread)


def _run(env: dict[str, Any], scope: Path, thread: str = "t1", plan: str | None = None) -> int:
    return cli.main(["agent", "run", "--scope", str(scope), "--plan", plan or env["plan"],
                     "--thread", thread])


def _resume(scope: Path, thread: str = "t1", decision: str = "ALLOW") -> int:
    return cli.main(["agent", "resume", "--scope", str(scope), "--thread", thread,
                     "--decision", decision])


def test_full_rehearsal_draft_approve_run_resume_report(env, capsys):
    # 1. a model drafts, a human approves, and only then is there a loadable scope
    assert _draft(env) == 0
    assert _approve(env, confirm=None) == 1  # no --confirm: nothing happens
    assert not (env["scopes"] / f"{PROJECT}.scope.yaml").exists()
    assert _approve(env, confirm="wrong") == 1
    assert not (env["scopes"] / f"{PROJECT}.scope.yaml").exists()
    assert _approve(env, confirm=PROJECT) == 0
    scope_file = env["scopes"] / f"{PROJECT}.scope.yaml"
    scope = runner.load_scope(scope_file)
    assert scope.in_scope == (HOST,)
    approved = [e for e in _events(env, "scope") if e["event"] == "scope_approved"]
    assert len(approved) == 1 and approved[0]["actor"] == "human"
    assert approved[0]["detail"]["scope_revision"] == scope.revision

    # 2. run: both ACTIVE actions pause for approval and nothing has executed yet
    capsys.readouterr()
    assert _run(env, scope_file) == 0
    assert "PAUSED" in capsys.readouterr().out
    assert env["executor"].ran == []

    # 3. a human approves; both tools execute
    assert _resume(scope_file) == 0
    assert sorted(env["executor"].ran) == ["n1", "u1"]
    report = (env["tmp"] / "reports" / "t1.md").read_text(encoding="utf-8")
    assert "status=COMPLETED" in report

    events = _events(env, "t1")
    results = {e["detail"]["tool"]: e for e in events if e["event"] == "tool_result"}
    assert set(results) == {"nmap", "nuclei"}
    assert all(e["detail"]["simulated"] is False for e in results.values())

    # 4. findings from BOTH tools, each citing its own tool_result audit event
    from viper.agents.evidence import rederive
    from viper.policy.approvals import action_hash
    from viper.tools.registry import default_registry

    graph_state = _checkpoint_state(env, scope_file)
    findings, warnings = rederive(
        graph_state["results"], events, actions=graph_state["actions"],
        bind=lambda raw: action_hash(Action.model_validate(raw),
                                     default_registry.get_info(raw["tool_name"])))
    assert warnings == []
    by_tool: dict[str, list[Any]] = {"nmap": [], "nuclei": []}
    for f in findings:
        by_tool[f.source_tool].append(f)
    assert by_tool["nmap"] and by_tool["nuclei"]
    for tool, fs in by_tool.items():
        assert any(f.confidence == "confirmed" for f in fs)
        for f in fs:
            assert f.audit_refs == [results[tool]["hash"]]

    # 5. the nuclei finding carries name / remediation / references from the JSONL
    hdr = next(f for f in by_tool["nuclei"] if "http-missing-security-headers" in f.title)
    assert hdr.title.startswith("HTTP Missing Security Headers")
    assert hdr.remediation == "Set the recommended security headers on all responses."
    assert "https://owasp.org/www-project-secure-headers/" in hdr.references
    # the foreign-host record is not confirmed evidence about the approved asset
    cdn = next(f for f in by_tool["nuclei"] if "cdn-redirect-detect" in f.title)
    assert cdn.confidence == "hypothesis"

    # 6. the saved report cites those audit events; audit verifies; `viper report` prints it
    assert "nmap" in report.lower() and "nuclei" in report.lower()
    for tool in ("nmap", "nuclei"):
        assert results[tool]["hash"][:12] in report or results[tool]["hash"] in report
    capsys.readouterr()
    assert cli.main(["audit", "verify", "--project", PROJECT]) == 0
    assert "audit log OK" in capsys.readouterr().out
    assert cli.main(["report", "--thread", "t1"]) == 0
    assert "# Viper assessment report" in capsys.readouterr().out

    # 7. a finished thread id cannot be reused
    capsys.readouterr()
    assert _run(env, scope_file) == 1
    assert "agent error" in capsys.readouterr().out


def _checkpoint_state(env: dict[str, Any], scope_file: Path) -> dict[str, Any]:
    conn = runner._connect(Settings(_env_file=None, checkpoint_db=env["tmp"] / "cp.db"))
    try:
        settings = Settings(_env_file=None, checkpoint_db=env["tmp"] / "cp.db",
                            audit_dir=env["tmp"] / "audit")
        graph = runner._graph(settings, scope_file, PROJECT, runner._no_planner, conn)
        values: dict[str, Any] = graph.get_state({"configurable": {"thread_id": "t1"}}).values
        return values
    finally:
        conn.close()


# ------------------------------------------------------------------ negative cases
def _approved_scope(env: dict[str, Any]) -> Path:
    assert _draft(env) == 0 and _approve(env) == 0
    return env["scopes"] / f"{PROJECT}.scope.yaml"


def test_an_out_of_scope_target_is_denied_and_nothing_executes(env, capsys):
    scope_file = _approved_scope(env)
    plan = env["tmp"] / "bad.json"
    plan.write_text(json.dumps([{"action_id": "x1", "tool_name": "nmap",
                                 "args": {"target": "evil.example"}},
                                {"action_id": "x2", "tool_name": "nuclei",
                                 "args": {"target": "evil.example"}}]), encoding="utf-8")
    capsys.readouterr()
    rc = _run(env, scope_file, thread="neg1", plan=str(plan))
    out = capsys.readouterr().out
    assert rc == 0 and "PAUSED" not in out  # denied outright: no approval is ever requested
    assert env["executor"].ran == []
    assert "Denied actions" in out and "x1" in out and "x2" in out
    events = _events(env, "neg1")
    assert not any(e["event"] in ("tool_dispatch", "tool_result") for e in events)


def test_a_draft_scope_file_cannot_be_used_by_agent_run(env, capsys):
    assert _draft(env) == 0
    draft_file = env["scopes"] / f"{PROJECT}.draft.yaml"
    capsys.readouterr()
    assert _run(env, draft_file, thread="neg2") == 1
    assert "agent error" in capsys.readouterr().out
    assert env["executor"].ran == []
    assert not (env["tmp"] / "reports" / "neg2.md").exists()


def test_a_failed_audit_append_at_approve_time_leaves_no_scope_file(env, monkeypatch, capsys):
    assert _draft(env) == 0

    def boom(*_a: Any, **_k: Any) -> None:
        raise OSError("audit store unavailable")

    monkeypatch.setattr(AuditLog, "append", boom)
    capsys.readouterr()
    assert _approve(env) == 1
    assert "scope error" in capsys.readouterr().out
    assert not (env["scopes"] / f"{PROJECT}.scope.yaml").exists()
    assert list(env["scopes"].glob("*.scope.yaml")) == []
