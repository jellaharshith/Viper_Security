"""Real execution tools (M6): nmap and nuclei, dispatched to the Kali VM Exec API.

Unlike the M5 stubs, these are ``dry_run_only=False`` and ``RiskLevel.ACTIVE``, so the policy
engine DENIES them when ``allow_active_testing`` is off and REQUIRES human approval when it is on.
The orchestrator never runs them locally: when active testing is armed, ``make_executor`` selects
``RemoteExecutor``, which POSTs the action to the VM. Their parameter schemas mirror the VM server's
(``vmapi``) allowlist exactly, so an action that validates here also validates there (defense in depth).
The ``dry_run`` fallback below is only a label — it is never the path that touches a real target.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from viper.policy.models import RiskLevel
from viper.tools.registry import DryRunResult, Tool, default_registry


class NmapArgs(BaseModel):
    """nmap arguments — mirrors vmapi's nmap allowlist (no raw flags, no output redirection)."""

    model_config = ConfigDict(extra="forbid")

    target: str
    ports: str | None = None  # up to 32 explicit comma-separated TCP ports (vmapi enforces the cap)
    service_detection: bool = False
    skip_discovery: bool = False


class NucleiArgs(BaseModel):
    """nuclei arguments — mirrors vmapi's nuclei allowlist (fixed passive mode on the server)."""

    model_config = ConfigDict(extra="forbid")

    target: str
    rate_limit: int = Field(default=5, ge=1, le=10)


def _nmap_dry_run(args: dict[str, Any]) -> DryRunResult:
    return DryRunResult(
        tool="nmap", args=args,
        summary=f"[not executed] nmap would scan {args.get('target')!r}", simulated=True,
    )


def _nuclei_dry_run(args: dict[str, Any]) -> DryRunResult:
    return DryRunResult(
        tool="nuclei", args=args,
        summary=f"[not executed] nuclei would scan {args.get('target')!r}", simulated=True,
    )


nmap = Tool(
    name="nmap",
    risk=RiskLevel.ACTIVE,
    params_schema=NmapArgs,
    dry_run_fn=_nmap_dry_run,
    dry_run_only=False,  # real execution permitted once active testing is armed + approved
    description="Port/service scan of an in-scope target, executed on the Kali VM.",
)

nuclei = Tool(
    name="nuclei",
    risk=RiskLevel.ACTIVE,
    params_schema=NucleiArgs,
    dry_run_fn=_nuclei_dry_run,
    dry_run_only=False,
    description="Passive nuclei scan of an in-scope target, executed on the Kali VM.",
)

ALL_REAL_TOOLS: tuple[Tool, ...] = (nmap, nuclei)

for _tool in ALL_REAL_TOOLS:
    if _tool.name not in default_registry._tools:
        default_registry.register(_tool)
