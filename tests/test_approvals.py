from datetime import UTC, datetime, timedelta

import pytest

from viper.policy.approvals import ResumePayload, action_hash, consume, make_pending
from viper.policy.models import Action, RiskLevel, ToolInfo

NOW = datetime(2026, 1, 1, tzinfo=UTC)
TOOL = ToolInfo(name="probe", risk=RiskLevel.ACTIVE)
ACTION = Action(action_id="a1", tool_name="probe", args={"target": "example.com"})


def pending(**kw):
    base = {"project_id": "p", "thread_id": "t", "action": ACTION, "tool": TOOL,
            "scope_revision": "rev1", "expires_at": NOW + timedelta(minutes=5)}
    base.update(kw)
    return make_pending(**base)


def payload(p, **kw):
    base = {"pending_approval_id": p.id, "decision": "ALLOW", "approver": "alice",
            "action_hash": p.action_hash, "timestamp": NOW}
    base.update(kw)
    return ResumePayload(**base)


def run(p, pl, **kw):
    args = {"now": NOW, "thread_id": "t", "scope_revision": "rev1"}
    args.update(kw)
    return consume(p, pl, **args)


def test_valid_approval_is_granted_and_consumed():
    p = pending()
    new, reason = run(p, payload(p))
    assert reason is None and new.consumed


def test_replay_is_refused():
    p = pending()
    used, _ = run(p, payload(p))
    _, reason = run(used, payload(p))
    assert reason == "approval already used"


@pytest.mark.parametrize("override,expected", [
    ({"pending_approval_id": "x"}, "approval id mismatch"),
    ({"action_hash": "x"}, "action changed since approval was requested"),
    ({"approver": "  "}, "missing approver"),
    ({"decision": "DENY"}, "denied by human"),
])
def test_refusals(override, expected):
    p = pending()
    new, reason = run(p, payload(p, **override))
    assert reason == expected


def test_expired_wrong_thread_and_scope_change_refused():
    p = pending()
    assert run(p, payload(p), now=NOW + timedelta(minutes=5))[1] == "approval expired"
    assert run(p, payload(p), thread_id="other")[1] == "approval belongs to another thread"
    assert run(p, payload(p), scope_revision="rev2")[1] == "scope changed since approval was requested"


def test_changed_args_change_hash_and_id():
    other = Action(action_id="a1", tool_name="probe", args={"target": "evil.com"})
    assert action_hash(ACTION, TOOL) != action_hash(other, TOOL)
    assert pending().id != pending(action=other).id


def test_payload_rejects_unknown_keys():
    with pytest.raises(ValueError):
        ResumePayload(pending_approval_id="a", decision="ALLOW", approver="x", action_hash="h",
                      timestamp=NOW, extra="no")  # type: ignore[call-arg]
