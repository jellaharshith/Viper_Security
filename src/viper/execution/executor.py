"""M5 executor: dispatches only to registered dry-run stubs. No network, no subprocess."""

from __future__ import annotations

from viper.policy.models import Action
from viper.tools.registry import DryRunResult, ToolRegistry, default_registry


class DryRunExecutor:
    """The only executor in M5. Real execution arrives with the M6 execution plane."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self._registry = registry or default_registry

    def run(self, action: Action) -> DryRunResult:
        tool = self._registry.get(action.tool_name)
        if tool is None:
            raise KeyError(f"unknown tool {action.tool_name!r}")
        return tool.dry_run(action.args)
