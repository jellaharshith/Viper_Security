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
from viper.agents.graph import Deps, build_graph
from viper.config import Settings
from viper.policy.models import Action, Scope


def load_scope(path: Path) -> Scope:
    """Strict load: unknown keys or bad types raise, so a typo cannot silently widen scope."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Scope.model_validate(data)


def load_plan(path: Path) -> list[Action]:
    """Stand-in for the LLM planner in M5: a JSON list of {action_id, tool_name, args}."""
    return [Action.model_validate(item) for item in json.loads(path.read_text(encoding="utf-8"))]


def _graph(settings: Settings, scope: Scope, actions: list[Action], conn: sqlite3.Connection) -> Any:
    deps = Deps(planner=lambda _request: actions, settings=settings,
                scope_provider=lambda: scope, audit=AuditLog(settings, scope.project_id))
    return build_graph(deps, SqliteSaver(conn))


def _connect(settings: Settings) -> sqlite3.Connection:
    settings.checkpoint_db.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(settings.checkpoint_db, check_same_thread=False)


def run(
    settings: Settings, scope: Scope, actions: list[Action], request: str, thread: str,
) -> dict[str, Any]:
    conn = _connect(settings)
    try:
        graph = _graph(settings, scope, actions, conn)
        state = {"project_id": scope.project_id, "thread_id": thread, "request": request}
        out: dict[str, Any] = graph.invoke(state, {"configurable": {"thread_id": thread}})
        return out
    finally:
        conn.close()


def resume(
    settings: Settings, scope: Scope, actions: list[Action], thread: str, decision: str,
) -> dict[str, Any]:
    """Answer every pending approval on a paused thread. The approver is the local OS user."""
    conn = _connect(settings)
    try:
        graph = _graph(settings, scope, actions, conn)
        cfg = {"configurable": {"thread_id": thread}}
        snap = graph.get_state(cfg)
        pending = [i.value for t in snap.tasks for i in t.interrupts]
        if not pending:
            raise ValueError("thread has no pending approval")
        answers = [{"pending_approval_id": p["id"], "decision": decision, "approver": getpass.getuser(),
                    "action_hash": p["action_hash"], "timestamp": datetime.now(UTC).isoformat()}
                   for p in pending[0]["pending"]]
        out: dict[str, Any] = graph.invoke(Command(resume=answers), cfg)
        return out
    finally:
        conn.close()
