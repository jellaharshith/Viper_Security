"""Dry-run tool stubs for M5 agents.

These stubs satisfy the M5 execution contract:
- Pure simulation: zero network egress, zero subprocess execution.
- Deterministic output: returns DryRunResult with simulated=True.
- Fixed risk levels: READ, PASSIVE, or ACTIVE.
- active_probe_stub sets dry_run_only=True so the human approval interrupt is reachable.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from viper.policy.models import RiskLevel
from viper.tools.registry import DryRunResult, Tool, default_registry


class KbAnswerArgs(BaseModel):
    """Arguments for the kb_answer tool."""

    model_config = ConfigDict(extra="forbid")

    question: str
    top_k: int = 4


class ScopeCheckArgs(BaseModel):
    """Arguments for the scope_check tool."""

    model_config = ConfigDict(extra="forbid")

    target: str


class PlanScanArgs(BaseModel):
    """Arguments for the plan_scan tool."""

    model_config = ConfigDict(extra="forbid")

    target: str
    profile: str = "fast"


class ActiveProbeArgs(BaseModel):
    """Arguments for the active_probe_stub tool."""

    model_config = ConfigDict(extra="forbid")

    target: str
    probe_type: str = "ping"


def _kb_answer_dry_run(args: dict[str, Any]) -> DryRunResult:
    return DryRunResult(
        tool="kb_answer",
        args=args,
        summary=f"Simulated knowledge-base retrieval for question: {args.get('question')!r}",
        simulated=True,
    )


def _scope_check_dry_run(args: dict[str, Any]) -> DryRunResult:
    return DryRunResult(
        tool="scope_check",
        args=args,
        summary=f"Simulated scope check for target: {args.get('target')!r}",
        simulated=True,
    )


def _plan_scan_dry_run(args: dict[str, Any]) -> DryRunResult:
    return DryRunResult(
        tool="plan_scan",
        args=args,
        summary=f"Simulated scan plan for target: {args.get('target')!r}",
        simulated=True,
    )


def _active_probe_dry_run(args: dict[str, Any]) -> DryRunResult:
    return DryRunResult(
        tool="active_probe_stub",
        args=args,
        summary=f"Simulated active probe for target: {args.get('target')!r}",
        simulated=True,
    )


kb_answer = Tool(
    name="kb_answer",
    risk=RiskLevel.READ,
    params_schema=KbAnswerArgs,
    dry_run_fn=_kb_answer_dry_run,
    dry_run_only=True,
    description="Query cybersecurity knowledge base (read-only lookup).",
)

scope_check = Tool(
    name="scope_check",
    risk=RiskLevel.READ,
    params_schema=ScopeCheckArgs,
    dry_run_fn=_scope_check_dry_run,
    dry_run_only=True,
    description="Verify whether a target host or IP is within authorized scope.",
)

plan_scan = Tool(
    name="plan_scan",
    risk=RiskLevel.PASSIVE,
    params_schema=PlanScanArgs,
    dry_run_fn=_plan_scan_dry_run,
    dry_run_only=True,
    description="Generate a passive scan plan against an in-scope target.",
)

active_probe_stub = Tool(
    name="active_probe_stub",
    risk=RiskLevel.ACTIVE,
    params_schema=ActiveProbeArgs,
    dry_run_fn=_active_probe_dry_run,
    dry_run_only=True,
    description="Simulated active probe stub (dry-run only; reaches approval checkpoint).",
)

ALL_STUBS: tuple[Tool, ...] = (
    kb_answer,
    scope_check,
    plan_scan,
    active_probe_stub,
)

for _stub in ALL_STUBS:
    if _stub.name not in default_registry._tools:
        default_registry.register(_stub)
