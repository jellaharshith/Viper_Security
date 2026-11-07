"""Glue for the CLI: load scope/plan files, run or resume a dry-run agent thread."""

from __future__ import annotations

import getpass
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from viper.agents.audit import AuditLog
from viper.agents.claims import SqliteClaims
from viper.agents.graph import Deps, build_graph
from viper.config import Settings
from viper.policy.models import Action, Scope


def load_scope(path: Path) -> Scope:
    """Strict load: unknown keys or bad types raise, so a typo cannot silently widen scope."""
    return Scope.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def load_plan(path: Path) -> list[Action]:
    """Stand-in for the LLM planner in M5: a JSON list of {action_id, tool_name, args}."""
    actions = [Action.model_validate(item) for item in json.loads(path.read_text(encoding="utf-8"))]
    ids = [a.action_id for a in actions]
    if any(not i.strip() for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("plan has empty or duplicate action ids")
    return actions


def _no_planner(_request: str) -> list[Action]:
    raise RuntimeError("resume never re-plans; it continues the saved plan")


def _graph(settings: Settings, scope_path: Path, project_id: str,
           planner: Any, conn: sqlite3.Connection) -> Any:
    # The scope file is re-read at every enforcement point, so edits during a pause are noticed.
    deps = Deps(
        planner=planner, settings=settings, scope_provider=lambda: load_scope(scope_path),
        audit=AuditLog(settings, project_id),
        claims=SqliteClaims(settings.checkpoint_db.with_suffix(".claims.db")),
    )
    return build_graph(deps, SqliteSaver(conn))


def _connect(settings: Settings) -> sqlite3.Connection:
    settings.checkpoint_db.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(settings.checkpoint_db, check_same_thread=False)


def run(
    settings: Settings, scope_path: Path, actions: list[Action], request: str, thread: str,
) -> dict[str, Any]:
    project_id = load_scope(scope_path).project_id
    conn = _connect(settings)
    try:
        graph = _graph(settings, scope_path, project_id, lambda _r: actions, conn)
        state = {"project_id": project_id, "thread_id": thread, "request": request}
        out: dict[str, Any] = graph.invoke(state, {"configurable": {"thread_id": thread}})
        return out
    finally:
        conn.close()


def pending_details(settings: Settings, scope_path: Path, thread: str) -> list[dict[str, Any]]:
    """What a human is about to approve, read from the saved checkpoint (never from a new file)."""
    project_id = load_scope(scope_path).project_id
    conn = _connect(settings)
    try:
        graph = _graph(settings, scope_path, project_id, _no_planner, conn)
        snap = graph.get_state({"configurable": {"thread_id": thread}})
        if snap.values.get("project_id") != project_id:
            raise ValueError("thread belongs to a different project than the supplied scope")
        by_id = {a["action_id"]: a for a in snap.values.get("actions", [])}
        pending = [p for t in snap.tasks for i in t.interrupts for p in i.value["pending"]]
        return [{**p, "action": by_id.get(p["action_id"])} for p in pending]
    finally:
        conn.close()


def resume(settings: Settings, scope_path: Path, thread: str, decision: str) -> dict[str, Any]:
    """Answer every pending approval on a paused thread. The approver is the local OS user."""
    details = pending_details(settings, scope_path, thread)
    if not details:
        raise ValueError("thread has no pending approval")
    answers = [{"pending_approval_id": p["id"], "decision": decision, "approver": getpass.getuser(),
                "action_hash": p["action_hash"], "timestamp": datetime.now(UTC).isoformat()}
               for p in details]
    project_id = load_scope(scope_path).project_id
    conn = _connect(settings)
    try:
        graph = _graph(settings, scope_path, project_id, _no_planner, conn)
        out: dict[str, Any] = graph.invoke(Command(resume=answers),
                                           {"configurable": {"thread_id": thread}})
        return out
    finally:
        conn.close()
