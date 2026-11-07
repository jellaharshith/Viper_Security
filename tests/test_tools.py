from __future__ import annotations

import subprocess
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from viper.config import Settings
from viper.policy.engine import evaluate
from viper.policy.models import Action, DecisionType, RiskLevel, Scope, ToolInfo
from viper.tools.registry import (
    DryRunResult,
    Tool,
    ToolRegistry,
    create_tool_info,
    default_registry,
    get,
    get_info,
    get_tool,
    list_info,
    list_tools,
)
from viper.tools.stubs import (
    ALL_STUBS,
    active_probe_stub,
    kb_answer,
    plan_scan,
    scope_check,
)

SCOPE = Scope(
    project_id="test-proj",
    in_scope=("example.com", "*.example.org", "192.168.1.0/24"),
    exclusions=("restricted.example.org",),
)
SETTINGS = Settings(_env_file=None, allow_active_testing=False)  # type: ignore[call-arg]


def test_registry_contains_default_stubs() -> None:
    tools = list_tools()
    tool_names = {t.name for t in tools}
    assert {"kb_answer", "scope_check", "plan_scan", "active_probe_stub"}.issubset(tool_names)

    for stub in ALL_STUBS:
        registered = get(stub.name)
        assert registered is not None
        assert registered.name == stub.name
        assert registered.risk == stub.risk
        assert registered.dry_run_only == stub.dry_run_only


def test_registry_get_and_getitem() -> None:
    tool = get("kb_answer")
    assert tool is not None
    assert tool.name == "kb_answer"

    tool_from_alias = get_tool("kb_answer")
    assert tool_from_alias is tool

    tool_from_item = default_registry["kb_answer"]
    assert tool_from_item is tool

    assert "kb_answer" in default_registry


def test_unknown_tool_handling() -> None:
    assert get("nonexistent_tool") is None
    assert get_info("nonexistent_tool") is None

    with pytest.raises(KeyError, match="nonexistent_tool"):
        _ = default_registry["nonexistent_tool"]

    assert "nonexistent_tool" not in default_registry

    # Policy evaluate with unknown tool returns DENY
    action = Action(action_id="act-unknown", tool_name="nonexistent_tool", args={})
    decision = evaluate(action, get_info("nonexistent_tool"), SCOPE, SETTINGS)
    assert decision.type == DecisionType.DENY
    assert "unknown tool" in decision.reason


def test_tool_info_created_by_registry() -> None:
    info = get_info("kb_answer")
    assert isinstance(info, ToolInfo)
    assert info.name == "kb_answer"
    assert info.risk == RiskLevel.READ
    assert info.dry_run_only is True

    # Helper creator
    custom_info = create_tool_info("custom", RiskLevel.PASSIVE, dry_run_only=True)
    assert isinstance(custom_info, ToolInfo)
    assert custom_info.name == "custom"
    assert custom_info.risk == RiskLevel.PASSIVE


def test_list_and_list_info() -> None:
    tools = list_tools()
    infos = list_info()
    assert len(tools) >= 4
    assert len(infos) == len(tools)
    assert all(isinstance(i, ToolInfo) for i in infos)
    assert {t.name for t in tools} == {i.name for i in infos}


def test_custom_tool_registration_and_overwrite() -> None:
    reg = ToolRegistry()

    class CustomArgs(BaseModel):
        model_config = ConfigDict(extra="forbid")
        param: str

    custom_tool = Tool(
        name="custom_echo",
        risk=RiskLevel.READ,
        params_schema=CustomArgs,
        dry_run_fn=lambda args: DryRunResult(
            tool="custom_echo",
            args=args,
            summary=f"Echo: {args['param']}",
            simulated=True,
        ),
    )

    reg.register(custom_tool)
    assert reg.get("custom_echo") is custom_tool

    # Duplicate registration without overwrite raises ValueError
    with pytest.raises(ValueError, match="already registered"):
        reg.register(custom_tool)

    # Allowed with overwrite=True
    reg.register(custom_tool, overwrite=True)
    assert reg.get("custom_echo") is custom_tool


def test_tool_schema_must_forbid_extra() -> None:
    class BadArgs(BaseModel):
        # extra not forbidden
        param: str

    with pytest.raises(ValueError, match="must configure extra='forbid'"):
        Tool(
            name="bad_tool",
            risk=RiskLevel.READ,
            params_schema=BadArgs,
        )


def test_extra_args_rejected_for_all_stubs() -> None:
    # 1. kb_answer
    assert kb_answer.validate_args({"question": "test"})["question"] == "test"
    with pytest.raises(ValidationError):
        kb_answer.validate_args({"question": "test", "extra_field": "disallowed"})
    with pytest.raises(ValidationError):
        kb_answer.validate_args({})

    # 2. scope_check
    assert scope_check.validate_args({"target": "example.com"})["target"] == "example.com"
    with pytest.raises(ValidationError):
        scope_check.validate_args({"target": "example.com", "extra_field": 123})
    with pytest.raises(ValidationError):
        scope_check.validate_args({})

    # 3. plan_scan
    assert plan_scan.validate_args({"target": "example.com"})["target"] == "example.com"
    with pytest.raises(ValidationError):
        plan_scan.validate_args({"target": "example.com", "inject": True})
    with pytest.raises(ValidationError):
        plan_scan.validate_args({})

    # 4. active_probe_stub
    assert active_probe_stub.validate_args({"target": "example.com"})["target"] == "example.com"
    with pytest.raises(ValidationError):
        active_probe_stub.validate_args({"target": "example.com", "malicious_flag": True})
    with pytest.raises(ValidationError):
        active_probe_stub.validate_args({})


def test_dry_run_rejects_extra_args() -> None:
    with pytest.raises(ValidationError):
        kb_answer.dry_run({"question": "valid?", "unexpected": "junk"})

    with pytest.raises(ValidationError):
        plan_scan.dry_run({"target": "example.com", "extra": 42})


def test_risk_is_registry_owned_model_cannot_override() -> None:
    # Risk is strictly owned by the registry tool instance
    assert kb_answer.risk == RiskLevel.READ
    assert scope_check.risk == RiskLevel.READ
    assert plan_scan.risk == RiskLevel.PASSIVE
    assert active_probe_stub.risk == RiskLevel.ACTIVE

    # Attempting to mutate tool.risk raises AttributeError
    with pytest.raises(AttributeError):
        active_probe_stub.risk = RiskLevel.READ  # type: ignore[misc]

    # Attempting to mutate tool.name raises AttributeError
    with pytest.raises(AttributeError):
        active_probe_stub.name = "renamed"  # type: ignore[misc]

    # ToolInfo is frozen
    info = active_probe_stub.info
    assert info.risk == RiskLevel.ACTIVE
    with pytest.raises(ValidationError):
        info.risk = RiskLevel.READ

    # Action model forbids risk fields
    with pytest.raises(ValidationError):
        Action(action_id="act-1", tool_name="active_probe_stub", args={}, risk=RiskLevel.READ)  # type: ignore[call-arg]

    # Model attempting to smuggle risk in args is rejected by parameter schema
    with pytest.raises(ValidationError):
        active_probe_stub.validate_args({"target": "example.com", "risk": "READ"})


def test_every_stub_returns_simulated_true() -> None:
    cases = [
        (kb_answer, {"question": "What is CVE-2023-4966?"}, "kb_answer"),
        (scope_check, {"target": "example.com"}, "scope_check"),
        (plan_scan, {"target": "example.com"}, "plan_scan"),
        (active_probe_stub, {"target": "example.com"}, "active_probe_stub"),
    ]

    for tool_obj, args, expected_name in cases:
        result = tool_obj.dry_run(args)
        assert isinstance(result, DryRunResult)
        assert result.simulated is True
        assert result.tool == expected_name
        assert isinstance(result.summary, str)
        assert len(result.summary) > 0
        if "target" in args:
            assert result.args["target"] == args["target"]
        else:
            assert result.args["question"] == args["question"]


def test_no_network_no_subprocess_during_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def socket_fail(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("Network egress attempted during dry run!")

    def subprocess_fail(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("Subprocess execution attempted during dry run!")

    import socket

    monkeypatch.setattr(socket.socket, "connect", socket_fail)
    monkeypatch.setattr(socket.socket, "sendto", socket_fail)
    monkeypatch.setattr(subprocess, "Popen", subprocess_fail)
    monkeypatch.setattr(subprocess, "run", subprocess_fail)

    for stub in ALL_STUBS:
        if stub.name == "kb_answer":
            args = {"question": "Explain EternalBlue"}
        else:
            args = {"target": "example.com"}
        result = stub.dry_run(args)
        assert result.simulated is True


def test_active_probe_stub_dry_run_only_allows_approval_interrupt() -> None:
    assert active_probe_stub.dry_run_only is True
    action = Action(action_id="act-active", tool_name="active_probe_stub", args={"target": "example.com"})

    # Even with allow_active_testing=False, dry_run_only=True tools reach REQUIRE_APPROVAL
    decision = evaluate(action, active_probe_stub.info, SCOPE, SETTINGS)
    assert decision.type == DecisionType.REQUIRE_APPROVAL
    assert decision.risk == RiskLevel.ACTIVE
    assert "active action needs human approval" in decision.reason


def test_plan_scan_scope_enforcement() -> None:
    # In scope
    action_in = Action(action_id="act-plan-in", tool_name="plan_scan", args={"target": "example.com"})
    decision_in = evaluate(action_in, plan_scan.info, SCOPE, SETTINGS)
    assert decision_in.type == DecisionType.ALLOW

    # Out of scope
    action_out = Action(action_id="act-plan-out", tool_name="plan_scan", args={"target": "evil.com"})
    decision_out = evaluate(action_out, plan_scan.info, SCOPE, SETTINGS)
    assert decision_out.type == DecisionType.DENY
    assert "out of scope" in decision_out.reason

    # Excluded host
    args_ex = {"target": "restricted.example.org"}
    action_ex = Action(action_id="act-plan-ex", tool_name="plan_scan", args=args_ex)
    decision_ex = evaluate(action_ex, plan_scan.info, SCOPE, SETTINGS)
    assert decision_ex.type == DecisionType.DENY
