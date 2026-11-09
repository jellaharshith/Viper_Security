"""LLM-backed planner (M7). The model PROPOSES a test plan; deterministic code validates it.

Nothing here grants anything: every proposal still goes through ``policy_gate`` (risk, scope,
approval) and is re-checked at ``execute``. The planner only has to be strict about *shape*:
unknown tools, extra keys, duplicate ids, empty or oversized plans all fail closed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from viper.policy.models import Action, Scope
from viper.tools.registry import ToolRegistry

_ACTION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
MAX_REPLY_CHARS = 65_536  # a plan is a few lines; refuse to parse anything bigger
MAX_DECODE_ATTEMPTS = 50
MAX_ACTIONS = 8  # a plan is a handful of scans, not a campaign; humans approve each ACTIVE one

Chat = Callable[[list[dict[str, str]]], str]


class PlannerError(RuntimeError):
    """The model's output could not be turned into a safe, well-formed plan."""


_SYSTEM = (
    "You are the planning step of an authorized penetration-testing assistant. Propose a SHORT "
    "test plan as a JSON array and nothing else. Each item must be exactly "
    '{"action_id": "<unique short id>", "tool_name": "<one of the tools below>", '
    '"args": {...}}. Use only the listed tools and their listed arguments. Targets MUST be '
    "taken from the in-scope list; never invent targets. Do not include risk levels, approvals "
    "or any other keys: a deterministic policy engine decides what runs and a human approves "
    "active tests. Prefer the least intrusive plan that answers the request."
)


def _first_array(text: str) -> list[Any]:
    """First JSON array of objects in ``text`` (tolerates fences and surrounding prose)."""
    if len(text) > MAX_REPLY_CHARS:
        raise PlannerError("model reply too large")
    decoder = json.JSONDecoder()
    attempts = 0
    for start, ch in enumerate(text):
        if ch != "[":
            continue
        attempts += 1
        if attempts > MAX_DECODE_ATTEMPTS:
            break
        try:
            value, _ = decoder.raw_decode(text, start)
        except (ValueError, RecursionError):  # malformed or absurdly deep: not a plan
            continue
        if isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
            return value
    raise PlannerError("model reply contained no JSON array of actions")


def _arg_hint(prop: dict[str, Any]) -> str:
    """One readable line per argument: type (resolving optional/anyOf) plus the schema description."""
    kind = prop.get("type")
    if kind is None:
        kinds = [o.get("type") for o in prop.get("anyOf", []) if o.get("type") not in (None, "null")]
        kind = "|".join(kinds) or "any"
    text = str(prop.get("description", ""))
    return f"{kind}. {text}".strip()


class LLMPlanner:
    def __init__(
        self, chat: Chat, registry: ToolRegistry, scope_provider: Callable[[], Scope | None],
        egress_provider: Callable[[], list[str]] = list,
    ) -> None:
        self._chat = chat
        self._registry = registry
        self._scope = scope_provider
        # Exact hosts the execution plane will accept. Scope may be broader (wildcards, CIDR), so a
        # plan is checked against this list too; otherwise the VM refuses it AFTER a human approved it.
        self._egress = egress_provider

    def _prompt(self, request: str, scope: Scope) -> list[dict[str, str]]:
        tools = []
        for tool in self._registry.list():
            props = tool.params_schema.model_json_schema().get("properties", {})
            tools.append({"name": tool.name, "risk": tool.risk.name, "description": tool.description,
                          "args": {k: _arg_hint(v) for k, v in props.items()}})
        context = {"in_scope": list(scope.in_scope), "excluded": list(scope.exclusions),
                   "forbidden_techniques": list(scope.forbidden_techniques),
                   "allowed_hosts": self._egress(), "tools": tools,
                   "scope_limits": {"max_rate_rps": scope.max_rate_rps,
                                    "automation_allowed": scope.automation_allowed,
                                    "permitted_techniques": list(scope.permitted_techniques)}}
        ctx = json.dumps(context, indent=2)
        user = f"Context:\n{ctx}\n\nRequest:\n{request}"
        return [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": user}]

    def __call__(self, request: str) -> list[Action]:
        scope = self._scope()
        if scope is None:
            raise PlannerError("no scope loaded; refusing to plan")
        try:
            reply = self._chat(self._prompt(request, scope))
        except Exception as exc:  # noqa: BLE001 - any model/transport failure is a planning failure
            raise PlannerError(f"model call failed: {type(exc).__name__}") from None
        items = _first_array(reply)
        if len(items) > MAX_ACTIONS:
            raise PlannerError(f"too many actions proposed ({len(items)} > {MAX_ACTIONS})")
        try:
            actions = [Action.model_validate(i) for i in items]
        except ValidationError:
            raise PlannerError("proposed action has an invalid shape") from None
        ids = [a.action_id for a in actions]
        if any(not _ACTION_ID.fullmatch(i) for i in ids):
            raise PlannerError("invalid action id (letters, digits, _ . - only)")
        if len(set(ids)) != len(ids):
            raise PlannerError("plan has empty or duplicate action ids")
        allowed = {h.lower() for h in self._egress()}
        for action in actions:
            tool = self._registry.get(action.tool_name)
            if tool is None:
                raise PlannerError(f"unknown tool proposed: {action.tool_name!r}")
            if allowed and not tool.dry_run_only:  # a real tool will be sent to the VM
                target = action.args.get("target")
                if not isinstance(target, str) or not target:
                    raise PlannerError(f"{action.tool_name}: a string target is required")
                if target not in allowed:  # exact match, like the VM: mixed case is refused there
                    raise PlannerError(
                        f"{action.tool_name}: target {target!r} is not an exact egress host; "
                        f"allowed: {sorted(allowed)}")
        return actions
