"""Fail-safe executor selector.

The default configuration MUST yield ``DryRunExecutor``. ``make_executor`` returns the live
``RemoteExecutor`` only when *every* precondition for active testing is satisfied; any missing
or malformed precondition falls back to dry-run. This is the primary safety gate of the
execution plane, so it is written as "dry-run UNLESS all(...)" — a new or missing field can
only ever make the system safer, never silently enable real execution.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from viper.execution.executor import DryRunExecutor
from viper.execution.remote import ExecSettings, RemoteExecutor
from viper.policy.models import Action
from viper.tools.registry import ToolRegistry, default_registry


@runtime_checkable
class Result(Protocol):
    """Anything an executor returns: it must dump to a JSON-safe dict for the graph.

    ``mode`` mirrors pydantic's ``model_dump`` so the graph can request ``mode="json"`` for
    checkpoint-safe serialization (both ``DryRunResult`` and remote results are pydantic models).
    """

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]: ...


@runtime_checkable
class Executor(Protocol):
    def run(self, action: Action) -> Result: ...


def make_executor(settings: ExecSettings, registry: ToolRegistry | None = None) -> Executor:
    """Return the live ``RemoteExecutor`` iff active testing is fully configured, else ``DryRunExecutor``."""
    registry = registry or default_registry
    if _remote_ready(settings):
        return RemoteExecutor(settings, registry)
    return DryRunExecutor(registry)


def _remote_ready(settings: ExecSettings) -> bool:
    """True only when ALL active-testing preconditions hold. Defensive ``getattr`` so a settings
    object missing a field fails closed (treated as not-ready) rather than raising."""
    if not getattr(settings, "allow_active_testing", False):
        return False
    if not getattr(settings, "exec_api_url", ""):
        return False
    token = getattr(settings, "exec_api_token", None)
    if token is None or not token.get_secret_value():
        return False
    ca = getattr(settings, "exec_api_ca_cert", None)
    if ca is None or not Path(ca).is_file():
        return False
    return True
