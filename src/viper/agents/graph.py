"""LangGraph agent: plan -> policy_gate -> (approval) -> execute -> report.

The model only proposes actions. Policy, approvals and audit are deterministic code, and
``execute`` re-checks all of them right before dispatch (second enforcement point).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, TypedDict

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import interrupt

from viper.agents.audit import AuditError, AuditLog
from viper.config import Settings
from viper.execution.executor import DryRunExecutor
from viper.policy.approvals import PendingApproval, ResumePayload, action_hash, consume, make_pending
from viper.policy.engine import evaluate
from viper.policy.models import Action, Decision, DecisionType, Scope
from viper.tools.registry import ToolRegistry, default_registry

Planner = Callable[[str], list[Action]]


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
    status: str
    report: str


@dataclass
class Deps:
    planner: Planner
    settings: Settings
    scope_provider: Callable[[], Scope | None]
    audit: AuditLog
    registry: ToolRegistry = field(default_factory=lambda: default_registry)
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    approval_ttl: timedelta = timedelta(minutes=15)


def build_graph(deps: Deps, checkpointer: BaseCheckpointSaver[Any]) -> CompiledStateGraph[Any, Any, Any, Any]:
    executor = DryRunExecutor(deps.registry)

    def decide(action: Action) -> Decision:
        tool = deps.registry.get(action.tool_name)
        if tool is not None:
            try:
                tool.validate_args(action.args)
            except (ValueError, TypeError):
                return Decision(action_id=action.action_id, type=DecisionType.DENY,
                                reason="arguments rejected by tool schema")
        info = deps.registry.get_info(action.tool_name)
        return evaluate(action, info, deps.scope_provider(), deps.settings)

    def audit(state: AgentState, event: str, actor: str, **kw: Any) -> None:
        deps.audit.append(thread_id=state["thread_id"], event=event, actor=actor, **kw)

    def plan(state: AgentState) -> dict[str, Any]:
        actions = deps.planner(state["request"])  # untrusted proposals
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
        for pid, raw in waiting.items():
            record = PendingApproval.model_validate(raw)
            payload = by_id.get(pid)
            reason: str | None
            if payload is None:
                new, reason = record, "no human decision received"
            elif scope is None:
                new, reason = record, "no scope loaded"
            else:
                new, reason = consume(record, payload, now=deps.now(), thread_id=state["thread_id"],
                                      scope_revision=scope.revision)
            updated[pid] = new.model_dump(mode="json")
            if reason is None and payload is not None:
                audit(state, "approval_granted", "human",
                      detail={"pending_approval_id": pid, "approver": payload.approver})
                audit(state, "approval_consumed", "policy", detail={"pending_approval_id": pid})
            else:
                event = "approval_expired" if reason == "approval expired" else "approval_denied"
                audit(state, event, "human" if payload else "policy",
                      detail={"pending_approval_id": pid, "reason": reason})
                d = decisions[record.action_id]
                decisions[record.action_id] = {**d, "type": "DENY", "reason": reason}
        return {"pending": updated, "decisions": decisions, "status": "RUNNING"}

    def execute(state: AgentState) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        approved = {
            PendingApproval.model_validate(v).action_id
            for v in state.get("pending", {}).values()
            if v["consumed"] and state["decisions"][v["action_id"]]["type"] != "DENY"
        }
        for raw in state["actions"]:
            action = Action.model_validate(raw)
            if state["decisions"][action.action_id]["type"] == "DENY":
                continue
            current = decide(action)  # second enforcement point: current scope and settings
            allowed = current.type is DecisionType.ALLOW or (
                current.type is DecisionType.REQUIRE_APPROVAL and action.action_id in approved
            )
            info = deps.registry.get_info(action.tool_name)
            ahash = action_hash(action, info) if info else None
            if not allowed:
                audit(state, "policy_decision", "policy", action_hash=ahash, decision="DENY",
                      detail={"action_id": action.action_id, "reason": current.reason})
                continue
            try:  # audit first: no committed evidence, no dispatch
                audit(state, "tool_dry_run", "agent", action_hash=ahash,
                      detail={"action_id": action.action_id, "tool": action.tool_name})
            except AuditError:
                return {"status": "FAILED", "results": results}
            results.append(executor.run(action).model_dump(mode="json"))
        audit(state, "run_completed", "agent", detail={"count": len(results)})
        return {"results": results, "status": "COMPLETED"}

    def report(state: AgentState) -> dict[str, Any]:
        denied = [k for k, v in state.get("decisions", {}).items() if v["type"] == "DENY"]
        text = (f"status={state.get('status')} executed={len(state.get('results', []))} "
                f"denied={len(denied)}")
        return {"report": text}

    g = StateGraph(AgentState)
    g.add_node("plan", plan)
    g.add_node("policy_gate", policy_gate)
    g.add_node("approval", approval)
    g.add_node("execute", execute)
    g.add_node("report", report)
    g.add_edge(START, "plan")
    g.add_edge("plan", "policy_gate")
    g.add_conditional_edges("policy_gate", route_after_gate, ["approval", "execute"])
    g.add_edge("approval", "execute")
    g.add_edge("execute", "report")
    g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer)
