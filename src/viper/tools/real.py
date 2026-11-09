"""Real execution tools (M6): nmap and nuclei, dispatched to the Kali VM Exec API.

Unlike the M5 stubs, these are ``dry_run_only=False`` and ``RiskLevel.ACTIVE``, so the policy
engine DENIES them when ``allow_active_testing`` is off and REQUIRES human approval when it is on.
The orchestrator never runs them locally: when active testing is armed, ``make_executor`` selects
``RemoteExecutor``, which POSTs the action to the VM. Their parameter schemas mirror the VM server's
(``vmapi``) allowlist exactly, so an action that validates here also validates there (defense in depth).
The ``dry_run`` fallback below is only a label — it is never the path that touches a real target.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from viper.policy.models import RiskLevel
from viper.tools.registry import DryRunResult, Tool, default_registry

_PORTS = re.compile(r"[0-9]{1,5}(?:,[0-9]{1,5}){0,31}")


class NmapArgs(BaseModel):
    """nmap arguments - mirrors vmapi's nmap allowlist (no raw flags, no output redirection).

    ``ports`` is validated here exactly as ``vmapi.toolrunner.build_command`` validates it, so a plan
    the human approves can never be refused by the VM for a format reason.
    """

    model_config = ConfigDict(extra="forbid")

    target: str = Field(description="Exact hostname or IP address; must be one of allowed_hosts.")
    ports: str | None = Field(
        default=None,
        description="Comma-separated explicit TCP ports, at most 32, each 1-65535, for example 22,80,443. "
                    "No ranges (1-1000), no spaces, no flags.")
    service_detection: bool = Field(default=False, description="Probe service versions (-sV).")
    skip_discovery: bool = Field(default=False, description="Skip host discovery (-Pn).")

    @field_validator("ports")
    @classmethod
    def _ports_like_the_vm(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _PORTS.fullmatch(value) or any(not 1 <= int(p) <= 65535 for p in value.split(",")):
            raise ValueError("ports must be at most 32 explicit TCP ports (1-65535), comma-separated")
        return value


class NucleiArgs(BaseModel):
    """nuclei arguments - mirrors vmapi's nuclei allowlist (templates, tags, severity: fixed on the VM)."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(description="Exact hostname or IP address; must be one of allowed_hosts.")
    rate_limit: int = Field(default=5, ge=1, le=10, description="Requests per second, 1-10.")


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
    description="Bounded nuclei scan (technology, exposure, misconfiguration) of an in-scope target.",
)

ALL_REAL_TOOLS: tuple[Tool, ...] = (nmap, nuclei)

for _tool in ALL_REAL_TOOLS:
    if _tool.name not in default_registry._tools:
        default_registry.register(_tool)
