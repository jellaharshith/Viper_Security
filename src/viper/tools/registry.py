"""Tool registry and execution abstractions.

The tool registry is the authoritative creator of policy.models.ToolInfo.
Models propose tool invocations with names and arguments only; the registry owns
the parameter schemas, risk levels, and dry-run execution handlers.
"""

from __future__ import annotations

import builtins
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from viper.policy.models import KNOWN_TECHNIQUES, RiskLevel, ToolInfo


class DryRunResult(BaseModel):
    """Result of a simulated tool execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    summary: str
    simulated: bool = True
    truncated: bool = False  # True when captured output was cut by a client-side limit
    output: str = ""  # captured tool stdout (real execution only); stubs leave it empty
    template_count: int | None = None
    request_count: int | None = None

    @model_validator(mode="before")
    @classmethod
    def _populate_scanner_metrics(cls, data: Any) -> Any:
        if isinstance(data, dict) and data.get("tool") == "nuclei":
            output = data.get("output")
            if isinstance(output, str) and output:
                from viper.findings.parsers import parse_nuclei_metrics

                parsed = parse_nuclei_metrics(output)
                if data.get("template_count") is None:
                    data["template_count"] = parsed["template_count"]
                if data.get("request_count") is None:
                    data["request_count"] = parsed["request_count"]
        return data


# Registry-owned technique tags and default request rates (F3). A model can never supply these;
# tools registered without explicit values fall back to this table by name, else to "none".
TOOL_TECHNIQUES: dict[str, frozenset[str]] = {
    "nmap": frozenset({"port-scan", "service-detection"}),
    "nuclei": frozenset({"web-scan", "template-scan"}),
}
TOOL_DEFAULT_RATE_RPS: dict[str, int] = {"nuclei": 5}  # NucleiArgs.rate_limit default


def create_tool_info(
    name: str, risk: RiskLevel, *, dry_run_only: bool = True,
    techniques: frozenset[str] | None = None, default_rate_rps: int | None = None,
) -> ToolInfo:
    """Create an authoritative ToolInfo record for policy evaluation."""
    chosen = TOOL_TECHNIQUES.get(name, frozenset()) if techniques is None else frozenset(techniques)
    if not chosen <= KNOWN_TECHNIQUES:
        raise ValueError(f"unknown technique tags for tool {name!r}")
    rate = TOOL_DEFAULT_RATE_RPS.get(name) if default_rate_rps is None else default_rate_rps
    return ToolInfo(name=name, risk=risk, dry_run_only=dry_run_only, techniques=chosen,
                    default_rate_rps=rate)


class Tool:
    """Definition of a tool available in Viper.

    Risk levels and parameter schemas are owned by the registry and immutable once created.
    """

    def __init__(
        self,
        name: str,
        risk: RiskLevel,
        params_schema: type[BaseModel],
        dry_run_fn: Callable[[dict[str, Any]], DryRunResult] | None = None,
        *,
        dry_run_only: bool = True,
        description: str = "",
        techniques: frozenset[str] | None = None,
        default_rate_rps: int | None = None,
    ) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Tool name must be a non-empty string")
        if not isinstance(risk, RiskLevel):
            raise ValueError(f"Tool risk must be an instance of RiskLevel, got {risk!r}")
        if not (isinstance(params_schema, type) and issubclass(params_schema, BaseModel)):
            raise ValueError("Tool params_schema must be a Pydantic BaseModel class")
        if getattr(params_schema, "model_config", {}).get("extra") != "forbid":
            raise ValueError(f"Schema {params_schema.__name__} must configure extra='forbid'")

        self._name = name.strip()
        self._risk = risk
        self._params_schema = params_schema
        self._dry_run_fn = dry_run_fn
        self._dry_run_only = bool(dry_run_only)
        self._description = description
        self._info = create_tool_info(
            self._name, self._risk, dry_run_only=self._dry_run_only,
            techniques=techniques, default_rate_rps=default_rate_rps)

    @property
    def name(self) -> str:
        return self._name

    @property
    def risk(self) -> RiskLevel:
        return self._risk

    @property
    def params_schema(self) -> type[BaseModel]:
        return self._params_schema

    @property
    def dry_run_only(self) -> bool:
        return self._dry_run_only

    @property
    def description(self) -> str:
        return self._description

    @property
    def info(self) -> ToolInfo:
        return self._info

    def validate_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Validate input arguments against the schema, rejecting extra/unknown fields."""
        if not isinstance(args, dict):
            raise TypeError(f"Tool arguments must be a dict, got {type(args).__name__}")
        validated = self._params_schema.model_validate(args)
        return validated.model_dump()

    def dry_run(self, args: dict[str, Any]) -> DryRunResult:
        """Execute a simulated dry-run invocation after validating arguments."""
        validated_args = self.validate_args(args)
        if self._dry_run_fn is not None:
            return self._dry_run_fn(validated_args)
        return self._execute_dry_run(validated_args)

    def _execute_dry_run(self, args: dict[str, Any]) -> DryRunResult:
        raise NotImplementedError(f"Tool {self.name!r} does not implement dry-run execution")


class ToolRegistry:
    """Registry maintaining available tools and their authoritative metadata."""

    def __init__(self, *, auto_load_defaults: bool = False) -> None:
        self._tools: dict[str, Tool] = {}
        self._auto_load_defaults = auto_load_defaults
        self._defaults_loaded = False

    def _ensure_defaults(self) -> None:
        if self._auto_load_defaults and not self._defaults_loaded:
            self._defaults_loaded = True
            import viper.tools.real  # noqa: F401  # M6 nmap/nuclei (ACTIVE, real-exec)
            import viper.tools.stubs  # noqa: F401

    def register(self, tool: Tool, *, overwrite: bool = False) -> Tool:
        """Register a tool. Raises ValueError on duplicate unless overwrite=True."""
        if not isinstance(tool, Tool):
            raise TypeError(f"Expected Tool instance, got {type(tool).__name__}")
        if tool.name in self._tools and not overwrite:
            raise ValueError(f"Tool {tool.name!r} is already registered")
        self._tools[tool.name] = tool
        return tool

    def get(self, name: str, default: Tool | None = None) -> Tool | None:
        """Retrieve a tool by name, or return default if not registered."""
        self._ensure_defaults()
        return self._tools.get(name, default)

    def get_info(self, name: str) -> ToolInfo | None:
        """Retrieve the authoritative ToolInfo for a tool, or None if unknown."""
        tool = self.get(name)
        return tool.info if tool is not None else None

    def list(self) -> builtins.list[Tool]:
        """List all registered tools."""
        self._ensure_defaults()
        return builtins.list(self._tools.values())

    def list_info(self) -> builtins.list[ToolInfo]:
        """List ToolInfo for all registered tools."""
        return [tool.info for tool in self.list()]

    def __getitem__(self, name: str) -> Tool:
        tool = self.get(name)
        if tool is None:
            raise KeyError(f"Tool {name!r} not found in registry")
        return tool

    def __contains__(self, name: str) -> bool:
        return self.get(name) is not None

    def __len__(self) -> int:
        self._ensure_defaults()
        return len(self._tools)


default_registry = ToolRegistry(auto_load_defaults=True)
register = default_registry.register
get = default_registry.get
get_tool = default_registry.get
get_info = default_registry.get_info
list_tools = default_registry.list
list_info = default_registry.list_info


def list() -> builtins.list[Tool]:
    """List all registered tools from the default registry."""
    return default_registry.list()
