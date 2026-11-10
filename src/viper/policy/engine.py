"""Deterministic, deny-by-default policy evaluation. Pure: no I/O, no clock, no network."""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from viper.policy.models import (
    KNOWN_TECHNIQUES,
    Action,
    Decision,
    DecisionType,
    RiskLevel,
    Scope,
    ToolInfo,
    normalize_technique,
)

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


def _scope_limit_reason(action: Action, tool: ToolInfo, scope: Scope) -> str | None:
    """First scope limit the action breaks (automation, rate, techniques), or None. Fail-closed.

    Forbidden entries are slug-normalised and only those naming a KNOWN technique are enforced;
    free text such as "INTRUSIVE" is kept for humans and ignored here. Technique tags come from
    the registry (``ToolInfo.techniques``), never from the action.
    """
    if tool.risk == RiskLevel.ACTIVE and not scope.automation_allowed:
        return "automated tools are not permitted by this scope"
    if scope.max_rate_rps is not None:
        # An explicit value (even null) is checked as given; an omitted one means the tool default.
        rate: object = action.args["rate_limit"] if "rate_limit" in action.args else tool.default_rate_rps
        if "rate_limit" in action.args or rate is not None:
            if isinstance(rate, bool) or not isinstance(rate, int) or rate < 1:
                return f"rate {rate!r} is not a valid rate_limit"
            if rate > scope.max_rate_rps:
                return f"rate {rate} exceeds scope limit {scope.max_rate_rps} rps"
    forbidden = {normalize_technique(t) for t in scope.forbidden_techniques} & KNOWN_TECHNIQUES
    for technique in sorted(tool.techniques):
        if technique in forbidden:
            return f"technique '{technique}' is forbidden by scope"
    if scope.permitted_techniques:
        permitted = {normalize_technique(t) for t in scope.permitted_techniques}
        for technique in sorted(tool.techniques):
            if technique not in permitted:
                return f"technique '{technique}' is not in the scope's permitted techniques"
    return None


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
    limit = _scope_limit_reason(action, tool, scope)
    if limit is not None:
        return _deny(action, limit, risk)
    if risk == RiskLevel.PASSIVE:
        return Decision(action_id=action.action_id, type=DecisionType.ALLOW,
                        reason="passive action on in-scope target", risk=risk)
    # ACTIVE: real traffic needs the explicit switch; dry-run stubs may still exercise approvals.
    if not tool.dry_run_only and not settings.allow_active_testing:
        return _deny(action, "active testing is disabled", risk)
    return Decision(action_id=action.action_id, type=DecisionType.REQUIRE_APPROVAL,
                    reason="active action needs human approval", risk=risk)
