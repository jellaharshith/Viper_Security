"""Glue for the CLI: load scope/plan files, run or resume a dry-run agent thread."""

from __future__ import annotations

import getpass
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command
from pydantic import SecretStr

from viper.agents.audit import AuditLog
from viper.agents.claims import SqliteClaims
from viper.agents.graph import Deps, build_graph
from viper.agents.planner import LLMPlanner
from viper.config import Settings
from viper.execution.control import ControlLock
from viper.execution.factory import make_executor
from viper.llm.client import OllamaClient
from viper.policy.models import Action, Scope
from viper.tools.registry import default_registry

_THREAD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


def valid_thread(thread: str) -> str:
    """Thread ids become file names (reports), so only a plain token is accepted."""
    if not _THREAD.fullmatch(thread):
        raise ValueError("invalid thread id")
    return thread


_REPORT_SUFFIX = {"md": ".md", "json": ".json", "sarif": ".sarif"}


def report_path(settings: Settings, thread: str, fmt: str = "md") -> Path:
    if fmt not in _REPORT_SUFFIX:
        raise ValueError("unknown report format")
    return settings.report_dir / f"{valid_thread(thread)}{_REPORT_SUFFIX[fmt]}"


def _save_report(settings: Settings, thread: str, out: dict[str, Any]) -> None:
    """Persist the finished report (not a paused run); the path is derived, never supplied."""
    if out.get("__interrupt__") or not out.get("report"):
        return
    path = report_path(settings, thread)
    path.parent.mkdir(parents=True, exist_ok=True)
    # "x" = exclusive create: never overwrites a report and never follows a planted symlink.
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(str(out["report"]))
    _save_machine_reports(settings, thread, out)


def _save_machine_reports(settings: Settings, thread: str, out: dict[str, Any]) -> None:
    """JSON and SARIF renderings of the same findings, so other tools can consume them."""
    from viper.agents.audit import AuditError
    from viper.findings.models import Finding
    from viper.report.formats import render_json, render_sarif

    findings = [Finding.model_validate(f) for f in out.get("findings", [])]
    project = str(out.get("project_id") or "")
    try:
        events = AuditLog(settings, project).events(thread)
    except AuditError:
        events = []  # the markdown report already refused to cite an unverified chain
    for fmt, render in (("json", render_json), ("sarif", render_sarif)):
        text = render(findings, events, project_id=project, thread_id=thread)
        with report_path(settings, thread, fmt).open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(text)


def llm_chat(settings: Settings) -> Any:
    """Chat callable on the local Ollama model (shared by the planner and the scope reader)."""
    return OllamaClient(settings.ollama_host, settings.ollama_model, settings.embed_model).chat


def llm_planner(settings: Settings, scope_path: Path) -> LLMPlanner:
    """Ollama-backed planner. Opt-in only; the JSON plan file remains the deterministic path."""
    client = OllamaClient(settings.ollama_host, settings.ollama_model, settings.embed_model)
    return LLMPlanner(client.chat, default_registry, lambda: load_scope(scope_path),
                      egress_provider=settings.egress_hosts)


@dataclass
class _ExecConfig:
    """The subset of ``Settings`` the exec client reads, satisfying ``remote.ExecSettings``.

    Settings stores the egress allowlist as a comma-separated string; the client's Protocol
    wants ``list[str]``, so we materialize it here with ``Settings.egress_hosts()``.
    """

    allow_active_testing: bool
    exec_api_url: str
    exec_api_token: SecretStr
    exec_api_ca_cert: Path
    exec_egress_allowlist: list[str]


def _exec_settings(settings: Settings) -> _ExecConfig:
    return _ExecConfig(
        allow_active_testing=settings.allow_active_testing,
        exec_api_url=settings.exec_api_url,
        exec_api_token=settings.exec_api_token,
        exec_api_ca_cert=settings.exec_api_ca_cert or Path(""),  # "" is not a file -> stays dry-run
        exec_egress_allowlist=settings.egress_hosts(),
    )


def scope_from_text(text: str) -> Scope:
    """Strict parse: unknown keys or bad types raise, so a typo cannot silently widen scope."""
    return Scope.model_validate(yaml.safe_load(text))


def load_scope(path: Path) -> Scope:
    return scope_from_text(path.read_text(encoding="utf-8"))


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
        executor=make_executor(_exec_settings(settings)),
        control=ControlLock(settings.checkpoint_db.with_suffix(".control.db"), project_id),
    )
    return build_graph(deps, SqliteSaver(conn))


def _connect(settings: Settings) -> sqlite3.Connection:
    settings.checkpoint_db.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(settings.checkpoint_db, check_same_thread=False)


def run(
    settings: Settings, scope_path: Path, actions: list[Action] | Any, request: str, thread: str,
) -> dict[str, Any]:
    """``actions`` is a fixed plan (list) or a planner callable (the LLM planner, M7)."""
    valid_thread(thread)
    if report_path(settings, thread).exists():
        raise ValueError("a report already exists for this thread id")
    project_id = load_scope(scope_path).project_id
    planner = (lambda _r: actions) if isinstance(actions, list) else actions
    conn = _connect(settings)
    try:
        graph = _graph(settings, scope_path, project_id, planner, conn)
        if graph.get_state({"configurable": {"thread_id": thread}}).values:
            # Checkpoints are keyed by thread only; reusing one would inherit another run's state.
            raise ValueError("thread id already used; start a new thread or resume it")
        state = {"project_id": project_id, "thread_id": thread, "request": request}
        out: dict[str, Any] = graph.invoke(state, {"configurable": {"thread_id": thread}})
        _save_report(settings, thread, out)
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
    valid_thread(thread)
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
        _save_report(settings, thread, out)
        return out
    finally:
        conn.close()
