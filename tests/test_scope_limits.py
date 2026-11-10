"""F3: scope limits (rate, automation, techniques) are enforced by the policy engine, fail-closed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from viper import cli
from viper.agents import runner
from viper.config import Settings
from viper.policy.engine import evaluate
from viper.policy.models import (
    Action,
    DecisionType,
    RiskLevel,
    Scope,
    ToolInfo,
    normalize_technique,
)
from viper.tools.registry import DryRunResult, Tool, default_registry

HOST = "scanme.nmap.org"
ON = Settings(_env_file=None, allow_active_testing=True)


def _scope(**over: Any) -> Scope:
    return Scope(project_id="p", in_scope=(HOST,), **over)


def _act(tool: str = "nuclei", **args: Any) -> Action:
    return Action(action_id="a1", tool_name=tool, args={"target": HOST, **args})


def _decide(scope: Scope, action: Action, settings: Settings = ON):
    return evaluate(action, default_registry.get_info(action.tool_name), scope, settings)


# ------------------------------------------------------------------ the scope model
def test_old_scope_files_still_load_with_safe_defaults(tmp_path: Path) -> None:
    f = tmp_path / "s.yaml"
    f.write_text("project_id: demo\nin_scope: [example.com]\n", encoding="utf-8")
    s = runner.load_scope(f)
    assert s.max_rate_rps is None and s.automation_allowed is True and s.permitted_techniques == ()


def test_the_shipped_lab_scope_still_loads() -> None:
    for p in Path("projects").glob("**/scope*.yaml"):
        runner.load_scope(p)


def test_new_fields_change_the_revision() -> None:
    assert _scope().revision != _scope(max_rate_rps=2).revision
    assert _scope().revision != _scope(automation_allowed=False).revision
    assert _scope().revision != _scope(permitted_techniques=("port-scan",)).revision


@pytest.mark.parametrize("bad", [0, -1, 1001, "5", 2.5, True, [1]])
def test_max_rate_rps_is_strictly_bounded(bad: Any) -> None:
    with pytest.raises(ValidationError):
        _scope(max_rate_rps=bad)


@pytest.mark.parametrize("bad", ["false", "no", 0, 1, None, "True"])
def test_automation_allowed_must_be_a_real_bool(bad: Any) -> None:
    with pytest.raises(ValidationError):
        _scope(automation_allowed=bad)


@pytest.mark.parametrize("bad", ["Port-Scan", "port scan", "port_scan", "x;y", "", "a" * 65, "é"])
def test_permitted_techniques_must_be_lowercase_slugs(bad: str) -> None:
    with pytest.raises(ValidationError):
        _scope(permitted_techniques=(bad,))


def test_too_many_permitted_techniques_rejected() -> None:
    with pytest.raises(ValidationError):
        _scope(permitted_techniques=tuple(f"t{i}" for i in range(50)))


def test_unknown_keys_are_still_rejected() -> None:
    with pytest.raises(ValidationError):
        Scope.model_validate({"project_id": "p", "in_scope": [HOST], "max_rate": 5})


@pytest.mark.parametrize("text,slug", [("DoS", "dos"), ("Brute Force", "brute-force"),
                                       ("  port_scan ", "port-scan"), ("INTRUSIVE", "intrusive"),
                                       ("a//b", "a-b"), ("", ""), ("é!", "")])
def test_normalize_technique(text: str, slug: str) -> None:
    assert normalize_technique(text) == slug


# ------------------------------------------------------------------ registry-owned techniques
def test_registry_owns_the_technique_tags() -> None:
    nmap, nuclei = default_registry.get_info("nmap"), default_registry.get_info("nuclei")
    assert nmap is not None and nuclei is not None
    assert nmap.techniques == frozenset({"port-scan", "service-detection"})
    assert nuclei.techniques == frozenset({"web-scan", "template-scan"})
    for name in ("kb_answer", "scope_check", "plan_scan"):
        info = default_registry.get_info(name)
        assert info is not None and info.techniques == frozenset()


def test_a_model_cannot_supply_techniques_in_an_action() -> None:
    with pytest.raises(ValidationError):
        Action.model_validate({"action_id": "a", "tool_name": "nmap", "args": {},
                               "techniques": ["port-scan"]})
    # extra args are the tool schema's problem; the policy only trusts the registry's tags
    d = _decide(_scope(permitted_techniques=("port-scan", "service-detection")),
                _act("nmap", techniques=["web-scan"]))
    assert d.type is DecisionType.REQUIRE_APPROVAL


def test_tool_rejects_unknown_technique_tags() -> None:
    from pydantic import BaseModel, ConfigDict

    class A(BaseModel):
        model_config = ConfigDict(extra="forbid")

    with pytest.raises(ValueError):
        Tool("t", RiskLevel.ACTIVE, A, techniques=frozenset({"not-a-technique"}))


def test_toolinfo_defaults_are_empty() -> None:
    info = ToolInfo(name="x", risk=RiskLevel.READ)
    assert info.techniques == frozenset() and info.default_rate_rps is None


# ------------------------------------------------------------------ engine: automation
def test_automation_not_allowed_denies_every_active_tool() -> None:
    s = _scope(automation_allowed=False)
    for tool in ("nmap", "nuclei"):
        d = _decide(s, _act(tool))
        assert d.type is DecisionType.DENY
        assert d.reason == "automated tools are not permitted by this scope"


def test_automation_not_allowed_does_not_block_read_or_passive_tools() -> None:
    s = _scope(automation_allowed=False)
    assert _decide(s, Action(action_id="p", tool_name="plan_scan",
                             args={"target": HOST})).type is DecisionType.ALLOW
    assert _decide(s, Action(action_id="k", tool_name="kb_answer", args={})).type is DecisionType.ALLOW


def test_automation_allowed_default_still_requires_approval() -> None:
    assert _decide(_scope(), _act("nmap")).type is DecisionType.REQUIRE_APPROVAL


# ------------------------------------------------------------------ engine: rate
def test_rate_above_limit_is_denied_with_exact_reason() -> None:
    d = _decide(_scope(max_rate_rps=2), _act(rate_limit=5))
    assert d.type is DecisionType.DENY and d.reason == "rate 5 exceeds scope limit 2 rps"


def test_rate_at_or_below_limit_is_allowed() -> None:
    for rate in (1, 2):
        assert _decide(_scope(max_rate_rps=2), _act(rate_limit=rate)).type is \
            DecisionType.REQUIRE_APPROVAL


def test_an_omitted_rate_cannot_bypass_the_limit_because_the_tool_default_applies() -> None:
    d = _decide(_scope(max_rate_rps=2), _act())  # nuclei defaults to 5 rps
    assert d.type is DecisionType.DENY and d.reason == "rate 5 exceeds scope limit 2 rps"
    assert _decide(_scope(max_rate_rps=5), _act()).type is DecisionType.REQUIRE_APPROVAL


@pytest.mark.parametrize("bad", ["2", 2.0, True, None, [2], {"x": 1}, -1, 0])
def test_malformed_rate_values_fail_closed_when_a_limit_is_set(bad: Any) -> None:
    d = _decide(_scope(max_rate_rps=10), _act(rate_limit=bad))
    assert d.type is DecisionType.DENY


def test_no_limit_means_no_rate_check() -> None:
    assert _decide(_scope(), _act(rate_limit=10)).type is DecisionType.REQUIRE_APPROVAL


def test_tools_without_a_rate_argument_are_not_rate_checked() -> None:
    assert _decide(_scope(max_rate_rps=1), _act("nmap")).type is DecisionType.REQUIRE_APPROVAL


# ------------------------------------------------------------------ engine: techniques
def test_forbidden_technique_denies_matching_tools() -> None:
    d = _decide(_scope(forbidden_techniques=("port-scan",)), _act("nmap"))
    assert d.type is DecisionType.DENY and d.reason == "technique 'port-scan' is forbidden by scope"
    assert _decide(_scope(forbidden_techniques=("port-scan",)), _act("nuclei")).type is \
        DecisionType.REQUIRE_APPROVAL


@pytest.mark.parametrize("entry", ["Port Scan", "PORT_SCAN", " port-scan ", "Port-Scan"])
def test_forbidden_entries_are_slug_normalised(entry: str) -> None:
    d = _decide(_scope(forbidden_techniques=(entry,)), _act("nmap"))
    assert d.type is DecisionType.DENY and "port-scan" in d.reason


@pytest.mark.parametrize("entry", ["INTRUSIVE", "no heavy load", "dos", "brute-force", "", "???"])
def test_free_text_and_unrelated_forbidden_entries_never_block_by_accident(entry: str) -> None:
    assert _decide(_scope(forbidden_techniques=(entry,)), _act("nmap")).type is \
        DecisionType.REQUIRE_APPROVAL


def test_first_forbidden_technique_is_reported_deterministically() -> None:
    d = _decide(_scope(forbidden_techniques=("service-detection", "port-scan")), _act("nmap"))
    assert d.reason == "technique 'port-scan' is forbidden by scope"


def test_permitted_techniques_restrict_to_the_listed_ones() -> None:
    s = _scope(permitted_techniques=("port-scan", "service-detection"))
    assert _decide(s, _act("nmap")).type is DecisionType.REQUIRE_APPROVAL
    d = _decide(s, _act("nuclei"))
    assert d.type is DecisionType.DENY
    assert d.reason == "technique 'template-scan' is not in the scope's permitted techniques"


def test_partial_permission_is_not_enough() -> None:
    d = _decide(_scope(permitted_techniques=("port-scan",)), _act("nmap"))
    assert d.type is DecisionType.DENY and "service-detection" in d.reason


def test_empty_permitted_list_means_no_restriction() -> None:
    assert _decide(_scope(permitted_techniques=()), _act("nuclei")).type is \
        DecisionType.REQUIRE_APPROVAL


def test_forbidden_wins_over_permitted() -> None:
    s = _scope(permitted_techniques=("port-scan", "service-detection"),
               forbidden_techniques=("port-scan",))
    assert "forbidden" in _decide(s, _act("nmap")).reason


def test_a_permitted_list_does_not_block_techniqueless_tools() -> None:
    s = _scope(permitted_techniques=("port-scan",))
    assert _decide(s, Action(action_id="p", tool_name="plan_scan",
                             args={"target": HOST})).type is DecisionType.ALLOW


# ------------------------------------------------------------------ never weakens existing checks
def test_out_of_scope_and_disabled_active_testing_still_deny_first() -> None:
    s = _scope(max_rate_rps=1000)
    assert _decide(s, Action(action_id="a", tool_name="nmap",
                             args={"target": "evil.example"})).reason == \
        "target missing, excluded or out of scope"
    off = Settings(_env_file=None, allow_active_testing=False)
    assert _decide(s, _act("nmap"), off).reason == "active testing is disabled"


def test_evaluation_errors_still_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    import viper.policy.engine as engine

    monkeypatch.setattr(engine, "_scope_limit_reason", lambda *_a: 1 / 0)
    assert _decide(_scope(), _act("nmap")).reason == "policy evaluation error"


# ------------------------------------------------------------------ end to end
class _Exec:
    def __init__(self) -> None:
        self.ran: list[str] = []

    def run(self, action: Action) -> DryRunResult:  # pragma: no cover - must never be called
        self.ran.append(action.action_id)
        return DryRunResult(tool=action.tool_name, args=action.args, summary="x", simulated=False)


def test_agent_run_denies_every_scanner_when_automation_is_not_allowed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VIPER_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("VIPER_CHECKPOINT_DB", str(tmp_path / "cp.db"))
    monkeypatch.setenv("VIPER_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("VIPER_ALLOW_ACTIVE_TESTING", "true")
    ex = _Exec()
    monkeypatch.setattr(runner, "make_executor", lambda *_a, **_k: ex)
    scope = tmp_path / "scope.yaml"
    scope.write_text(yaml.safe_dump({"project_id": "lab", "in_scope": [HOST],
                                     "automation_allowed": False}), encoding="utf-8")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps([
        {"action_id": "n1", "tool_name": "nmap", "args": {"target": HOST}},
        {"action_id": "u1", "tool_name": "nuclei", "args": {"target": HOST}}]), encoding="utf-8")
    rc = cli.main(["agent", "run", "--scope", str(scope), "--plan", str(plan), "--thread", "t1"])
    out = capsys.readouterr().out
    assert rc == 0 and "PAUSED" not in out
    assert ex.ran == []
    assert "automated tools are not permitted by this scope" in out
    assert "n1" in out and "u1" in out
