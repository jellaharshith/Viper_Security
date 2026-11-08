"""Exclusive-control lock: one holder per project, human preemption, reentrant for the agent."""

from __future__ import annotations

from viper.execution.control import AGENT, ControlLock


def _lock(tmp_path, project="p1"):
    return ControlLock(tmp_path / "control.db", project)


def test_a_free_lock_has_no_holder(tmp_path):
    assert _lock(tmp_path).holder() is None


def test_acquire_grants_when_free(tmp_path):
    lk = _lock(tmp_path)
    assert lk.acquire(AGENT) is True
    assert lk.holder() == AGENT


def test_acquire_is_reentrant_for_the_same_holder(tmp_path):
    lk = _lock(tmp_path)
    assert lk.acquire(AGENT) is True
    assert lk.acquire(AGENT) is True  # re-asking never deadlocks the agent against itself


def test_acquire_refused_while_another_party_holds_it(tmp_path):
    lk = _lock(tmp_path)
    assert lk.acquire("human:alice") is True
    assert lk.acquire(AGENT) is False


def test_takeover_preempts_the_current_holder(tmp_path):
    lk = _lock(tmp_path)
    lk.acquire(AGENT)
    lk.takeover("human:alice")
    assert lk.holder() == "human:alice"
    assert lk.acquire(AGENT) is False  # the agent is now locked out


def test_release_only_succeeds_for_the_holder(tmp_path):
    lk = _lock(tmp_path)
    lk.acquire(AGENT)
    assert lk.release("human:alice") is False  # cannot release someone else's lock
    assert lk.holder() == AGENT
    assert lk.release(AGENT) is True
    assert lk.holder() is None


def test_the_lock_is_durable_across_separate_instances(tmp_path):
    db = tmp_path / "control.db"
    ControlLock(db, "p1").acquire(AGENT)
    assert ControlLock(db, "p1").acquire("human:bob") is False  # a different process is refused


def test_projects_are_independent(tmp_path):
    db = tmp_path / "control.db"
    assert ControlLock(db, "p1").acquire(AGENT) is True
    assert ControlLock(db, "p2").acquire("human:bob") is True
