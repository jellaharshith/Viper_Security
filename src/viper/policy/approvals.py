"""Human-approval records: bound to one exact action, expiring, and single-use. Pure logic."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from viper.policy.models import Action, ToolInfo


def _sha(data: Any) -> str:
    text = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode()).hexdigest()


def action_hash(action: Action, tool: ToolInfo) -> str:
    """Hash of what is actually being approved: tool, arguments and the registry-owned risk."""
    return _sha({"tool": action.tool_name, "args": action.args, "risk": int(tool.risk)})


class PendingApproval(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    project_id: str
    thread_id: str
    action_id: str
    action_hash: str
    scope_revision: str
    expires_at: datetime
    consumed: bool = False


class ResumePayload(BaseModel):
    """What the trusted local CLI sends on resume. Unknown keys are rejected."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pending_approval_id: str
    decision: Literal["ALLOW", "DENY"]
    approver: str
    action_hash: str
    timestamp: datetime


def make_pending(
    *, project_id: str, thread_id: str, action: Action, tool: ToolInfo,
    scope_revision: str, expires_at: datetime,
) -> PendingApproval:
    digest = action_hash(action, tool)
    pid = _sha([project_id, thread_id, action.action_id, scope_revision, digest,
                expires_at.isoformat()])
    return PendingApproval(
        id=pid, project_id=project_id, thread_id=thread_id, action_id=action.action_id,
        action_hash=digest, scope_revision=scope_revision, expires_at=expires_at,
    )


def revalidate(
    pending: PendingApproval, action: Action, tool: ToolInfo, *, now: datetime,
    project_id: str, thread_id: str, scope_revision: str,
) -> str | None:
    """Re-check a consumed approval against what is about to be dispatched. None = still valid."""
    if pending.project_id != project_id or pending.thread_id != thread_id:
        return "approval belongs to another project or thread"
    if pending.action_id != action.action_id or pending.action_hash != action_hash(action, tool):
        return "action changed since approval"
    if pending.scope_revision != scope_revision:
        return "scope changed since approval"
    if now >= pending.expires_at:
        return "approval expired before dispatch"
    return None


def consume(
    pending: PendingApproval, payload: ResumePayload, *, now: datetime,
    thread_id: str, scope_revision: str,
) -> tuple[PendingApproval, str | None]:
    """Return (updated record, None) if approval is granted, else (record, reason for refusal).

    Fails closed: any mismatch, expiry, replay or explicit DENY refuses execution.
    """
    if pending.consumed:
        return pending, "approval already used"
    if payload.pending_approval_id != pending.id:
        return pending, "approval id mismatch"
    if payload.action_hash != pending.action_hash:
        return pending, "action changed since approval was requested"
    if thread_id != pending.thread_id:
        return pending, "approval belongs to another thread"
    if scope_revision != pending.scope_revision:
        return pending, "scope changed since approval was requested"
    if now >= pending.expires_at:
        return pending, "approval expired"
    if not payload.approver.strip():
        return pending, "missing approver"
    if payload.decision != "ALLOW":
        return pending.model_copy(update={"consumed": True}), "denied by human"
    return pending.model_copy(update={"consumed": True}), None
