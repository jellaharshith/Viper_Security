"""v1.2 web-app probe tools: OTP/2FA, upload-bypass, injection detection, dispatched to the VM.

Same contract as ``real.py``'s nmap/nuclei: ``dry_run_only=False`` and ``RiskLevel.ACTIVE``, so the
policy engine DENIES these when ``allow_active_testing`` is off and REQUIRES human approval when on.
Per-asset narrowing lives in ``Scope.asset_technique_limits`` (policy/models.py), not here — these
schemas only decide what shape of request is possible at all.

Hard safety invariant, by construction, not by convention: every probe selects ONE of a small, fixed,
pre-reviewed set of payloads via an enum field (``mode``/``variant``/``technique``). None of these
schemas carries a free-text payload, file content, username, password, or OTP code field — the model
can choose *which* reviewed probe runs, never *what bytes* it sends. That is what keeps "upload a file
that proves bypass" from ever becoming "upload a webshell", and "test 2FA" from ever becoming "brute
force this account's password".
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from viper.policy.models import RiskLevel
from viper.tools.registry import DryRunResult, Tool, default_registry


class Otp2faProbeArgs(BaseModel):
    """OTP/2FA rate-limit and bypass probe. The test-account session is resolved on the VM from an
    operator-provisioned file, never from these args — so no credential ever reaches the orchestrator,
    the audit log, or the wire between orchestrator and VM.
    """

    model_config = ConfigDict(extra="forbid")

    target: str = Field(description="Exact hostname; must be one of allowed_hosts.")
    endpoint_path: str = Field(description="OTP verify endpoint path, e.g. /api/2fa/verify.")
    mode: Literal["enumerate_codes", "rate_limit_probe"] = Field(
        description="enumerate_codes: sequential OTP guesses against the researcher's OWN pre-"
                    "authorized test session only. rate_limit_probe: repeat ONE known-wrong code "
                    "to observe lockout/throttling behaviour.")
    max_attempts: int = Field(ge=1, le=50, strict=True, description="Hard cap; never unlimited.")
    delay_ms: int = Field(default=250, ge=100, le=5000, strict=True,
                          description="Minimum spacing between attempts; conservative by default.")


class UploadBypassProbeArgs(BaseModel):
    """Upload-filter bypass probe. File bytes are built by a fixed, reviewed template on the VM for
    the chosen ``variant`` — never supplied here. No field can carry file content, so no path from
    the model's proposal to an actual webshell/backdoor byte ever exists in this schema.
    """

    model_config = ConfigDict(extra="forbid")

    target: str = Field(description="Exact hostname; must be one of allowed_hosts.")
    endpoint_path: str = Field(description="Upload endpoint path.")
    variant: Literal["disallowed_extension_render", "content_detector_marker"] = Field(
        description="disallowed_extension_render: a harmless file with a disallowed extension that "
                    "proves it still renders/executes in-browser. content_detector_marker: a benign "
                    "image containing the literal string the content detector flags.")


class InjectionProbeArgs(BaseModel):
    """Single-shot, non-destructive injection detection probe. ``technique`` selects one fixed,
    reviewed payload server-side; this schema never carries a raw SQL/OS payload. Confirms
    *detection*, not exploitation — the researcher performs the actual demonstrated hack manually.
    """

    model_config = ConfigDict(extra="forbid")

    target: str = Field(description="Exact hostname; must be one of allowed_hosts.")
    endpoint_path: str = Field(description="Endpoint/form path to probe.")
    param_name: str = Field(pattern=r"^[A-Za-z0-9_\[\]]{1,64}$",
                            description="Parameter or field name to probe, e.g. username.")
    technique: Literal[
        "sqli_boolean", "sqli_time", "xss_reflected_marker",
        "command_injection_marker", "url_injection_redirect",
    ] = Field(description="Which fixed, reviewed detection payload to send.")


class SecretScanArgs(BaseModel):
    """Passive fetch of ONE exact JS file a browser visiting the page would also fetch (hence
    ``RiskLevel.PASSIVE``: no active-testing approval gate), scanned server-side against a fixed
    table of leaked-secret shapes. No raw regex or content field — the detection patterns are
    fixed in ``vmapi/probes/secret_scan.py``, never supplied by the caller.
    """

    model_config = ConfigDict(extra="forbid")

    target: str = Field(description="Exact hostname; must be one of allowed_hosts.")
    path: str = Field(pattern=r"^/[A-Za-z0-9/_.-]{1,200}\.js$",
                      description="Exact JS file path to fetch, e.g. /static/app.js.")


class GraphqlIntrospectArgs(BaseModel):
    """Single-shot GraphQL introspection probe. The introspection query is FIXED and server-side
    only (type/field names only, no field arguments) — this schema never carries a custom query,
    so it can never become a real query against business data.
    """

    model_config = ConfigDict(extra="forbid")

    target: str = Field(description="Exact hostname; must be one of allowed_hosts.")
    path: str = Field(default="/graphql", pattern=r"^/[A-Za-z0-9/_.-]{1,200}$",
                      description="GraphQL endpoint path.")


def _otp_dry_run(args: dict[str, Any]) -> DryRunResult:
    return DryRunResult(
        tool="otp_2fa_probe", args=args,
        summary=f"[not executed] otp_2fa_probe would run {args.get('mode')!r} against "
                f"{args.get('target')!r}", simulated=True,
    )


def _upload_dry_run(args: dict[str, Any]) -> DryRunResult:
    return DryRunResult(
        tool="upload_bypass_probe", args=args,
        summary=f"[not executed] upload_bypass_probe would try {args.get('variant')!r} against "
                f"{args.get('target')!r}", simulated=True,
    )


def _injection_dry_run(args: dict[str, Any]) -> DryRunResult:
    return DryRunResult(
        tool="injection_probe", args=args,
        summary=f"[not executed] injection_probe would try {args.get('technique')!r} on "
                f"{args.get('param_name')!r} against {args.get('target')!r}", simulated=True,
    )


def _secret_scan_dry_run(args: dict[str, Any]) -> DryRunResult:
    return DryRunResult(
        tool="secret_scan", args=args,
        summary=f"[not executed] secret_scan would fetch {args.get('path')!r} on "
                f"{args.get('target')!r}", simulated=True,
    )


def _graphql_introspect_dry_run(args: dict[str, Any]) -> DryRunResult:
    return DryRunResult(
        tool="graphql_introspect", args=args,
        summary=f"[not executed] graphql_introspect would send a fixed introspection query to "
                f"{args.get('path')!r} on {args.get('target')!r}", simulated=True,
    )


otp_2fa_probe = Tool(
    name="otp_2fa_probe",
    risk=RiskLevel.ACTIVE,
    params_schema=Otp2faProbeArgs,
    dry_run_fn=_otp_dry_run,
    dry_run_only=False,
    description="Bounded OTP/2FA rate-limit and bypass probe of an in-scope target, on the VM.",
    techniques=frozenset({"otp-bypass"}),
    default_rate_rps=4,
)

upload_bypass_probe = Tool(
    name="upload_bypass_probe",
    risk=RiskLevel.ACTIVE,
    params_schema=UploadBypassProbeArgs,
    dry_run_fn=_upload_dry_run,
    dry_run_only=False,
    description="Upload allow-list/content-detector bypass probe (fixed, benign files), on the VM.",
    techniques=frozenset({"upload-bypass"}),
)

injection_probe = Tool(
    name="injection_probe",
    risk=RiskLevel.ACTIVE,
    params_schema=InjectionProbeArgs,
    dry_run_fn=_injection_dry_run,
    dry_run_only=False,
    description="Single-shot, non-destructive injection (XSS/SQLi/command/redirect) detection probe.",
    techniques=frozenset({"injection-test"}),
)

secret_scan = Tool(
    name="secret_scan",
    risk=RiskLevel.PASSIVE,
    params_schema=SecretScanArgs,
    dry_run_fn=_secret_scan_dry_run,
    dry_run_only=False,
    description="Passive fetch of one JS file, scanned server-side for fixed leaked-secret shapes.",
    techniques=frozenset({"secret-scan"}),
)

graphql_introspect = Tool(
    name="graphql_introspect",
    risk=RiskLevel.ACTIVE,
    params_schema=GraphqlIntrospectArgs,
    dry_run_fn=_graphql_introspect_dry_run,
    dry_run_only=False,
    description="Single-shot, fixed GraphQL introspection query (type/field names only).",
    techniques=frozenset({"graphql-introspection"}),
)

ALL_WEBAPP_TOOLS: tuple[Tool, ...] = (
    otp_2fa_probe, upload_bypass_probe, injection_probe, secret_scan, graphql_introspect,
)

for _tool in ALL_WEBAPP_TOOLS:
    if _tool.name not in default_registry._tools:
        default_registry.register(_tool)
