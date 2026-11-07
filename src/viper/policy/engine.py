"""Deterministic, deny-by-default policy evaluation. Pure: no I/O, no clock, no network."""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from viper.policy.models import Action, Decision, DecisionType, RiskLevel, Scope, ToolInfo

if TYPE_CHECKING:
    from viper.config import Settings


def normalize_host(value: str) -> str | None:
    """Lowercase, strip a trailing dot, IDN -> punycode. None if it is not a usable host."""
    host = value.strip().lower().rstrip(".")
    if not host or any(c in host for c in "/\\@ ?#"):
        return None
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _match(target: str, entry: str) -> bool:
    """Does one scope entry (host, ``*.domain`` or CIDR) cover ``target``?"""
    try:
        network = ipaddress.ip_network(entry.strip(), strict=False)
    except ValueError:
        network = None
    if network is not None:
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False
    pattern = normalize_host(entry.removeprefix("*."))
    if pattern is None:
        return False
    if entry.startswith("*."):
        return target.endswith("." + pattern)  # subdomains only, not the apex
    return target == pattern


def in_scope(target: str, scope: Scope) -> bool:
    host = normalize_host(target)
    if host is None:
        return False
    if any(_match(host, e) for e in scope.exclusions):
        return False  # exclusions beat inclusions
    return any(_match(host, e) for e in scope.in_scope)


def _deny(action: Action, reason: str, risk: RiskLevel | None = None) -> Decision:
    return Decision(action_id=action.action_id, type=DecisionType.DENY, reason=reason, risk=risk)


def evaluate(action: Action, tool: ToolInfo | None, scope: Scope | None, settings: Settings) -> Decision:
    """Decide ALLOW / REQUIRE_APPROVAL / DENY. ``tool`` comes from the registry, never the model."""
    try:
        return _evaluate(action, tool, scope, settings)
    except Exception:  # deny by default: any evaluation error is a refusal
        return _deny(action, "policy evaluation error")


def _evaluate(action: Action, tool: ToolInfo | None, scope: Scope | None, settings: Settings) -> Decision:
    if tool is None or tool.name != action.tool_name:
        return _deny(action, "unknown tool")
    risk = tool.risk
    if risk == RiskLevel.INTRUSIVE:
        return _deny(action, "intrusive actions are not allowed", risk)
    if risk == RiskLevel.READ:
        return Decision(action_id=action.action_id, type=DecisionType.ALLOW,
                        reason="read-only", risk=risk)
    if scope is None:
        return _deny(action, "no scope loaded", risk)
    target = action.args.get("target")
    if not isinstance(target, str) or not in_scope(target, scope):
        return _deny(action, "target missing, excluded or out of scope", risk)
    if risk == RiskLevel.PASSIVE:
        return Decision(action_id=action.action_id, type=DecisionType.ALLOW,
                        reason="passive action on in-scope target", risk=risk)
    # ACTIVE: real traffic needs the explicit switch; dry-run stubs may still exercise approvals.
    if not tool.dry_run_only and not settings.allow_active_testing:
        return _deny(action, "active testing is disabled", risk)
    return Decision(action_id=action.action_id, type=DecisionType.REQUIRE_APPROVAL,
                    reason="active action needs human approval", risk=risk)
