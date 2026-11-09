"""v1.1 wiring: enrichment in the evidence path, md/json/sarif report files, real TSA anchoring in the CLI,
scope limits in the planner prompt, and the human takeover shell. Offline: no network, no real gcloud."""

import json
from pathlib import Path

import pytest

from viper import cli
from viper.agents import anchor
from viper.agents.audit import AuditLog
from viper.config import Settings

FIXTURES = Path(__file__).parent / "fixtures"
SCOPE = "project_id: demo\nin_scope: [example.com]\n"
PLAN = [{"action_id": "p", "tool_name": "plan_scan", "args": {"target": "example.com"}}]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("VIPER_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("VIPER_CHECKPOINT_DB", str(tmp_path / "cp.db"))
    monkeypatch.setenv("VIPER_REPORT_DIR", str(tmp_path / "reports"))
    scope = tmp_path / "scope.yaml"
    scope.write_text(SCOPE)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN))
    return {"scope": str(scope), "plan": str(plan), "tmp": tmp_path}


def run_plan(env, thread="t1"):
    return cli.main(["agent", "run", "--scope", env["scope"], "--plan", env["plan"], "--thread", thread])


# --- enrichment is part of the evidence path ----------------------------------------------------------

def test_findings_rederived_from_audited_output_are_enriched():
    from viper.agents.evidence import digest, rederive

    out = (FIXTURES / "findings" / "nmap_scanme.txt").read_text()
    args = {"target": "scanme.nmap.org", "ports": "22,80"}
    action = {"action_id": "n1", "tool_name": "nmap", "args": args}
    ev = {"hash": "h1", "event": "tool_result", "action_hash": "ah",
          "detail": {"action_id": "n1", "tool": "nmap", "digest": digest(out),
                     "simulated": False, "truncated": False}}
    res = {"tool": "nmap", "args": args, "simulated": False, "output": out, "action_id": "n1",
           "audit_hash": "h1", "truncated": False}
    findings, warnings = rederive([res], [ev], actions=[action], bind=lambda _a: "ah")
    assert findings and warnings == []
    assert any(f.description for f in findings), "known services get a curated description"


# --- report files in every format, one run ------------------------------------------------------------

def test_a_finished_run_saves_md_json_and_sarif_reports(env):
    assert run_plan(env) == 0
    reports = env["tmp"] / "reports"
    assert (reports / "t1.md").exists()
    data = json.loads((reports / "t1.json").read_text(encoding="utf-8"))
    assert data["schema"] == "viper-report/1"
    sarif = json.loads((reports / "t1.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["tool"]["driver"]["name"] == "Viper"


def test_report_command_prints_each_format_and_rejects_unknown_ones(env, capsys):
    assert run_plan(env) == 0
    capsys.readouterr()
    assert cli.main(["report", "--thread", "t1"]) == 0
    assert "# Viper assessment report" in capsys.readouterr().out
    assert cli.main(["report", "--thread", "t1", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["schema"] == "viper-report/1"
    assert cli.main(["report", "--thread", "t1", "--format", "sarif"]) == 0
    assert json.loads(capsys.readouterr().out)["version"] == "2.1.0"
    with pytest.raises(SystemExit):
        cli.main(["report", "--thread", "t1", "--format", "html"])


def test_unsafe_thread_ids_are_still_rejected_for_every_format(env, capsys):
    for fmt in ("md", "json", "sarif"):
        assert cli.main(["report", "--thread", "../x", "--format", fmt]) == 1


# --- real (TSA) audit anchoring in the CLI ------------------------------------------------------------

def test_tsa_anchor_needs_explicit_network_opt_in(env, capsys):
    assert run_plan(env) == 0
    capsys.readouterr()
    assert cli.main(["audit", "anchor", "--project", "demo", "--provider", "tsa"]) == 1
    assert "network" in capsys.readouterr().out.lower()


def test_tsa_anchor_is_recorded_and_verify_reports_verified(env, monkeypatch, capsys):
    assert run_plan(env) == 0
    seen = {}

    def fake_submit(head, *, endpoint, allow_network=False, transport=None):
        seen.update(head=head, endpoint=endpoint, allow_network=allow_network)
        return b"opaque-token"

    monkeypatch.setattr(anchor, "submit_tsa", fake_submit)
    monkeypatch.setattr(anchor, "make_tsa_verifier",
                        lambda ca=None: lambda p, h, t: p == "tsa" and t == b"opaque-token")
    capsys.readouterr()
    assert cli.main(["audit", "anchor", "--project", "demo", "--provider", "tsa", "--allow-network"]) == 0
    assert seen["endpoint"] == Settings(_env_file=None).anchor_tsa_url and seen["allow_network"] is True
    out = capsys.readouterr().out
    assert "rfc-3161" in out.lower()
    assert cli.main(["audit", "verify", "--project", "demo"]) == 0
    out = capsys.readouterr().out
    assert "anchor tsa" in out and "VERIFIED" in out and "UNVERIFIED" not in out


def test_verify_labels_a_tsa_receipt_unverified_when_the_token_does_not_check_out(env, monkeypatch, capsys):
    assert run_plan(env) == 0
    monkeypatch.setattr(anchor, "submit_tsa", lambda head, **kw: b"opaque-token")
    monkeypatch.setattr(anchor, "make_tsa_verifier", lambda ca=None: lambda p, h, t: False)
    assert cli.main(["audit", "anchor", "--project", "demo", "--provider", "tsa", "--allow-network"]) == 0
    capsys.readouterr()
    rc = cli.main(["audit", "verify", "--project", "demo"])
    out = capsys.readouterr().out
    assert "anchor tsa" in out and "UNVERIFIED" in out and rc == 0


def test_verified_label_appears_for_a_verifying_tsa_receipt(env, monkeypatch, capsys):
    assert run_plan(env) == 0
    monkeypatch.setattr(anchor, "submit_tsa", lambda head, **kw: b"tok")
    monkeypatch.setattr(anchor, "make_tsa_verifier", lambda ca=None: lambda p, h, t: True)
    assert cli.main(["audit", "anchor", "--project", "demo", "--provider", "tsa", "--allow-network"]) == 0
    capsys.readouterr()
    assert cli.main(["audit", "verify", "--project", "demo"]) == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out and "UNVERIFIED" not in out


def test_a_failing_timestamp_service_is_reported_by_class_only(env, monkeypatch, capsys):
    assert run_plan(env) == 0

    def boom(head, **kw):
        raise anchor.AnchorError("tsa returned secret details")

    monkeypatch.setattr(anchor, "submit_tsa", boom)
    capsys.readouterr()
    assert cli.main(["audit", "anchor", "--project", "demo", "--provider", "tsa", "--allow-network"]) == 1
    out = capsys.readouterr().out
    assert "AnchorError" in out and "secret details" not in out


# --- scope limits are visible to the planner -----------------------------------------------------------

def test_planner_prompt_shows_the_scope_limits():
    from viper.agents.planner import LLMPlanner
    from viper.policy.models import Scope
    from viper.tools.registry import default_registry

    scope = Scope(project_id="p", in_scope=("a.test",), max_rate_rps=3, automation_allowed=False,
                  permitted_techniques=("port-scan",), forbidden_techniques=("dos",))
    seen = []
    planner = LLMPlanner(lambda m: (seen.append(m), "[]")[1], default_registry, lambda: scope)
    with pytest.raises(Exception):  # noqa: B017 - an empty plan is rejected; only the prompt matters here
        planner("scan")
    text = "\n".join(m["content"] for m in seen[0])
    assert '"max_rate_rps": 3' in text and '"automation_allowed": false' in text
    assert "port-scan" in text and "dos" in text


# --- the human takeover shell -------------------------------------------------------------------------

def shell_args(project="demo", vm="viper-kali-lab", zone="us-central1-a"):
    return ["exec", "shell", "--project", project, f"--vm={vm}", "--zone", zone]


def test_shell_refuses_unless_a_human_holds_the_control_lock(env, monkeypatch, capsys):
    ran = []
    monkeypatch.setattr(cli.subprocess, "call", lambda argv, **kw: ran.append(argv) or 0)
    assert cli.main(shell_args()) == 1
    assert ran == [] and "takeover" in capsys.readouterr().out


def test_shell_runs_gcloud_ssh_over_iap_with_a_fixed_argv_and_audits_it(env, monkeypatch, capsys):
    ran = []
    monkeypatch.setattr(cli.subprocess, "call", lambda argv, **kw: ran.append((argv, kw)) or 0)
    assert cli.main(["exec", "takeover", "--project", "demo"]) == 0
    assert cli.main(shell_args()) == 0
    argv, kw = ran[0]
    assert isinstance(argv, list) and kw.get("shell") in (None, False)
    assert argv[1:4] == ["compute", "ssh", "viper-kali-lab"] and "--tunnel-through-iap" in argv
    assert argv[argv.index("--zone") + 1] == "us-central1-a"
    log = AuditLog(Settings(_env_file=None, audit_dir=env["tmp"] / "audit"), "demo")
    events = log.events("shell")
    assert [e["event"] for e in events] == ["human_shell_opened"] and events[0]["actor"] == "human"


@pytest.mark.parametrize("vm", ["x; rm -rf /", "a b", "$(id)", "", "-oProxyCommand=evil", "UPPER"])
def test_shell_rejects_hostile_vm_names(env, monkeypatch, vm):
    ran = []
    monkeypatch.setattr(cli.subprocess, "call", lambda argv, **kw: ran.append(argv) or 0)
    assert cli.main(["exec", "takeover", "--project", "demo"]) == 0
    assert cli.main(shell_args(vm=vm)) == 1
    assert ran == []


def test_shell_is_refused_when_the_audit_event_cannot_be_written(env, monkeypatch):
    from viper.agents.audit import AuditError

    ran = []
    monkeypatch.setattr(cli.subprocess, "call", lambda argv, **kw: ran.append(argv) or 0)
    assert cli.main(["exec", "takeover", "--project", "demo"]) == 0

    def boom(self, **kw):
        raise AuditError("disk full")

    monkeypatch.setattr(AuditLog, "append", boom)
    assert cli.main(shell_args()) == 1
    assert ran == []  # no evidence, no shell
