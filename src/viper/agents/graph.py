"""LangGraph agent: plan -> policy_gate -> (approval) -> execute -> report.

The model only proposes actions. Policy, approvals and audit are deterministic code, and
``execute`` re-checks all of them right before dispatch (second enforcement point).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, TypedDict

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import interrupt

from viper.agents.audit import AuditError, AuditLog
from viper.agents.claims import ClaimStore, MemoryClaims
from viper.agents.evidence import digest, rederive
from viper.config import Settings
from viper.execution.control import AGENT, ControlLock
from viper.execution.executor import DryRunExecutor
from viper.execution.factory import Executor
from viper.policy.approvals import (
    PendingApproval,
    ResumePayload,
    action_hash,
    consume,
    make_pending,
    revalidate,
)
from viper.policy.engine import evaluate
from viper.policy.models import Action, Decision, DecisionType, Scope
from viper.report.generator import render_report
from viper.tools.registry import ToolRegistry, default_registry

Planner = Callable[[str], list[Action]]

_UNSAFE = re.compile(r"[^A-Za-z0-9 _.,=()@-]")


def _safe(text: object) -> str:
    """Model-supplied ids and names reach the report, so strip anything that could form Markdown,
    a link, or a heading (no brackets, backticks, slashes, colons or newlines survive)."""
    return _UNSAFE.sub("?", str(text))[:80]


class AgentState(TypedDict, total=False):
    # trusted inputs (set by the CLI, never by the model)
    project_id: str
    thread_id: str
    request: str
    # produced by the graph
    actions: list[dict[str, Any]]
    decisions: dict[str, dict[str, Any]]
    pending: dict[str, dict[str, Any]]
    results: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    analysis_warnings: list[str]
    status: str
    report: str


@dataclass
class Deps:
    planner: Planner
    settings: Settings
    scope_provider: Callable[[], Scope | None]
    audit: AuditLog
    registry: ToolRegistry = field(default_factory=lambda: default_registry)
    claims: ClaimStore = field(default_factory=MemoryClaims)
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    approval_ttl: timedelta = timedelta(minutes=15)
    # M6: pluggable executor (defaults to DryRunExecutor) and the exclusive-control lock.
    executor: Executor | None = None
    control: ControlLock | None = None


def _deny(action: Action, reason: str) -> Decision:
    return Decision(action_id=action.action_id, type=DecisionType.DENY, reason=reason)


def build_graph(deps: Deps, checkpointer: BaseCheckpointSaver[Any]) -> CompiledStateGraph[Any, Any, Any, Any]:
    executor = deps.executor or DryRunExecutor(deps.registry)

    def decide(action: Action) -> Decision:
        tool = deps.registry.get(action.tool_name)
        if tool is not None:
            try:
                tool.validate_args(action.args)
            except (ValueError, TypeError):
                return _deny(action, "arguments rejected by tool schema")
        info = deps.registry.get_info(action.tool_name)
        return evaluate(action, info, deps.scope_provider(), deps.settings)

    def audit(state: AgentState, event: str, actor: str, **kw: Any) -> dict[str, Any]:
        return deps.audit.append(thread_id=state["thread_id"], event=event, actor=actor, **kw)

    # M7: a simulated run keeps one "tool_dry_run" event. Real dispatch writes an INTENT event
    # before the call and a RESULT event (with an output digest) after it; only the result is evidence.
    real = not isinstance(executor, DryRunExecutor)
    dispatch_event = "tool_dispatch" if real else "tool_dry_run"

    def plan(state: AgentState) -> dict[str, Any]:
        actions = deps.planner(state["request"])  # untrusted proposals
        ids = [a.action_id for a in actions]
        if any(not i.strip() for i in ids) or len(set(ids)) != len(ids):
            raise ValueError("plan has empty or duplicate action ids")  # fail closed
        audit(state, "plan_proposed", "agent", detail={"count": len(actions)})
        return {"actions": [a.model_dump(mode="json") for a in actions], "status": "DRAFT_PLAN"}

    def policy_gate(state: AgentState) -> dict[str, Any]:
        scope = deps.scope_provider()
        decisions: dict[str, dict[str, Any]] = {}
        pending: dict[str, dict[str, Any]] = {}
        for raw in state["actions"]:
            action = Action.model_validate(raw)
            d = decide(action)
            decisions[action.action_id] = d.model_dump(mode="json")
            info = deps.registry.get_info(action.tool_name)
            ahash = action_hash(action, info) if info else None
            audit(state, "policy_decision", "policy", action_hash=ahash, decision=d.type.value,
                  detail={"action_id": action.action_id, "reason": d.reason})
            if d.type is DecisionType.REQUIRE_APPROVAL and info and scope:
                p = make_pending(
                    project_id=state["project_id"], thread_id=state["thread_id"], action=action,
                    tool=info, scope_revision=scope.revision,
                    expires_at=deps.now() + deps.approval_ttl,
                )
                pending[p.id] = p.model_dump(mode="json")
                audit(state, "approval_requested", "policy", action_hash=ahash,
                      detail={"action_id": action.action_id, "pending_approval_id": p.id})
        return {"decisions": decisions, "pending": pending,
                "status": "AWAIT_APPROVAL" if pending else "RUNNING"}

    def route_after_gate(state: AgentState) -> str:
        return "approval" if state.get("pending") else "execute"

    def approval(state: AgentState) -> dict[str, Any]:
        # Idempotent until interrupt(): LangGraph re-runs this node from the top on resume.
        waiting = {k: v for k, v in state["pending"].items() if not v["consumed"]}
        answers = interrupt({"pending": list(waiting.values())})
        by_id: dict[str, ResumePayload] = {}
        for item in answers if isinstance(answers, list) else []:
            try:
                parsed = ResumePayload.model_validate(item)
            except ValueError:
                continue  # malformed answers never grant anything
            by_id[parsed.pending_approval_id] = parsed
        scope = deps.scope_provider()
        decisions = dict(state["decisions"])
        updated = dict(state["pending"])
        rejected = False
        for pid, raw in waiting.items():
            record = PendingApproval.model_validate(raw)
            payload = by_id.get(pid)
            reason: str | None
            if payload is None:
                new, reason = record, "no human decision received"
            elif scope is None:
                new, reason = record, "no scope loaded"
            elif not deps.claims.claim(f"approval:{state['thread_id']}:{pid}"):
                new, reason = record, "approval already claimed"  # concurrent or replayed resume
            else:
                new, reason = consume(record, payload, now=deps.now(), thread_id=state["thread_id"],
                                      scope_revision=scope.revision)
            updated[pid] = new.model_dump(mode="json")
            if reason is None and payload is not None:
                audit(state, "approval_granted", "human",
                      detail={"pending_approval_id": pid, "approver": payload.approver})
                audit(state, "approval_consumed", "policy", detail={"pending_approval_id": pid})
            else:
                rejected = True
                event = "approval_expired" if reason == "approval expired" else "approval_denied"
                audit(state, event, "human" if payload else "policy",
                      detail={"pending_approval_id": pid, "reason": reason})
                d = decisions[record.action_id]
                decisions[record.action_id] = {**d, "type": "DENY", "reason": reason}
        # Any refused approval halts the whole run: nothing executes after a human "no".
        return {"pending": updated, "decisions": decisions,
                "status": "REJECTED" if rejected else "RUNNING"}

    def route_after_approval(state: AgentState) -> str:
        return "report" if state.get("status") == "REJECTED" else "execute"

    def execute(state: AgentState) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        scope = deps.scope_provider()
        approvals = {PendingApproval.model_validate(v).action_id: PendingApproval.model_validate(v)
                     for v in state.get("pending", {}).values() if v["consumed"]}
        decisions = dict(state["decisions"])
        # Exclusive control (M6): if a human has taken over the VM, the agent dispatches nothing.
        if deps.control is not None and not deps.control.acquire(AGENT):
            for raw in state["actions"]:
                action = Action.model_validate(raw)
                if decisions[action.action_id]["type"] != "DENY":
                    decisions[action.action_id] = _deny(
                        action, "human holds exclusive control").model_dump(mode="json")
            audit(state, "policy_decision", "policy",
                  detail={"reason": "exclusive control held by human"})
            return {"status": "REJECTED", "results": results, "decisions": decisions}
        for raw in state["actions"]:
            action = Action.model_validate(raw)
            if decisions[action.action_id]["type"] == "DENY":
                continue
            current = decide(action)  # second enforcement point: current scope and settings
            info = deps.registry.get_info(action.tool_name)
            ahash = action_hash(action, info) if info else None
            reason: str | None = None
            if current.type is DecisionType.DENY:
                reason = current.reason
            elif current.type is DecisionType.REQUIRE_APPROVAL:
                record = approvals.get(action.action_id)
                if record is None or info is None or scope is None:
                    reason = "approval missing at dispatch"
                else:  # the whole binding must still hold for what is dispatched right now
                    reason = revalidate(record, action, info, now=deps.now(),
                                        project_id=state["project_id"], thread_id=state["thread_id"],
                                        scope_revision=scope.revision)
            if reason is None and not deps.claims.claim(f"dispatch:{state['thread_id']}:{action.action_id}"):
                reason = "dispatch already claimed; refusing to replay"
            if reason is not None:
                decisions[action.action_id] = _deny(action, reason).model_dump(mode="json")
                audit(state, "policy_decision", "policy", action_hash=ahash, decision="DENY",
                      detail={"action_id": action.action_id, "reason": reason})
                continue
            try:  # audit first: no committed evidence, no dispatch
                entry = audit(state, dispatch_event, "agent", action_hash=ahash,
                               detail={"action_id": action.action_id, "tool": action.tool_name})
                raw = executor.run(action).model_dump(mode="json")
                cite = entry["hash"]
                if real:  # evidence = what came back, committed by digest AFTER the call
                    cite = audit(state, "tool_result", "agent", action_hash=ahash,
                                 detail={"action_id": action.action_id, "tool": action.tool_name,
                                         "digest": digest(str(raw.get("output", ""))),
                                         "simulated": bool(raw.get("simulated", True))})["hash"]
                results.append({**raw, "action_id": action.action_id, "audit_hash": cite})
            except AuditError:
                return {"status": "FAILED", "results": results, "decisions": decisions}
            except Exception as exc:  # noqa: BLE001 - record the class only, then stop the run
                try:
                    audit(state, "run_failed", "agent",
                          detail={"action_id": action.action_id, "error": type(exc).__name__})
                except AuditError:
                    pass
                return {"status": "FAILED", "results": results, "decisions": decisions}
        audit(state, "run_completed", "agent", detail={"count": len(results)})
        return {"results": results, "decisions": decisions, "status": "COMPLETED"}

    def analyze(state: AgentState) -> dict[str, Any]:
        """Deterministic only: findings come from digest-verified tool output, never the LLM."""
        try:
            findings, warnings = rederive(state.get("results", []),
                                          deps.audit.events(state["thread_id"]))
        except AuditError:
            return {"status": "FAILED", "findings": [],
                    "analysis_warnings": ["audit log failed verification; analysis not possible"]}
        audit(state, "findings_generated", "agent", detail={"count": len(findings)})
        return {"findings": [f.model_dump(mode="json") for f in findings],
                "analysis_warnings": warnings}

    def report(state: AgentState) -> dict[str, Any]:
        denied = [k for k, v in state.get("decisions", {}).items() if v["type"] == "DENY"]
        summary = (f"status={state.get('status')} executed={len(state.get('results', []))} "
                   f"denied={len(denied)}")
        try:  # a report cites audit hashes, so it is only built from a verified chain
            events = deps.audit.events(state["thread_id"])
            # Re-derive again from the latest checkpointed results: stored findings are not trusted.
            findings, warnings = rederive(state.get("results", []), events)
            warnings = list(dict.fromkeys([*state.get("analysis_warnings", []), *warnings]))
            text = render_report(findings, events, project_id=state["project_id"],
                                 thread_id=state["thread_id"])
            audit(state, "report_generated", "agent", detail={"count": len(findings)})
        except AuditError:
            return {"status": "FAILED", "report": f"report unavailable: audit log failed ({summary})"}
        names = {a["action_id"]: a["tool_name"] for a in state.get("actions", [])}
        lines = [f"- {_safe(k)} ({_safe(names.get(k, '?'))}): {_safe(v.get('reason', ''))}"
                 for k, v in state.get("decisions", {}).items() if v["type"] == "DENY"]
        if warnings:  # absence of findings must never read as "clean" when analysis was impaired
            text += ("\n\n" + "## Analysis warnings" + "\n\n"
                     + "Analysis is INCOMPLETE; do not read missing findings as a clean result."
                     + "\n\n" + "\n".join(f"- {_safe(w)}" for w in warnings))
        if lines:  # a reader of the report must see what was refused and why, not just a count
            text += "\n\n" + "## Denied actions" + "\n\n" + "\n".join(lines)
        return {"report": text + "\n\n" + "---" + "\n" + "Run summary: " + summary + "\n",
                "findings": [f.model_dump(mode="json") for f in findings]}

    g = StateGraph(AgentState)
    g.add_node("plan", plan)
    g.add_node("policy_gate", policy_gate)
    g.add_node("approval", approval)
    g.add_node("execute", execute)
    g.add_node("analyze", analyze)
    g.add_node("report", report)
    g.add_edge(START, "plan")
    g.add_edge("plan", "policy_gate")
    g.add_conditional_edges("policy_gate", route_after_gate, ["approval", "execute"])
    g.add_conditional_edges("approval", route_after_approval, ["execute", "report"])
    g.add_edge("execute", "analyze")
    g.add_edge("analyze", "report")
    g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer)
