"""Tests for the orchestrator-side execution client (factory selector + RemoteExecutor).

No real network: the VM Exec API is driven by an ``httpx.MockTransport`` (respx is not
installed). No real VM, no subprocess. The selector's fail-safe default is the primary
safety property under test: a default config must always yield ``DryRunExecutor``.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from viper.agents.claims import MemoryClaims
from viper.execution.executor import DryRunExecutor
from viper.execution.factory import make_executor
from viper.execution.remote import (
    DispatchAlreadyClaimed,
    EgressDenied,
    RemoteAuthError,
    RemoteExecutor,
)
from viper.policy.models import Action

TOKEN = "exec-token-xyz"  # noqa: S105 (fake test value)
TARGET = "scanme.nmap.org"


def _settings(**over: Any) -> SimpleNamespace:
    """A settings stub with every precondition satisfied; ``over`` flips individual fields.

    ``exec_api_ca_cert`` points at this test file, which is guaranteed to exist, so the
    "CA file exists" precondition holds without creating fixtures.
    """
    base: dict[str, Any] = {
        "allow_active_testing": True,
        "exec_api_url": "https://vm.internal:8443",
        "exec_api_token": SecretStr(TOKEN),
        "exec_api_ca_cert": Path(__file__),
        "exec_egress_allowlist": [TARGET],
    }
    base.update(over)
    return SimpleNamespace(**base)


def _action(target: Any = TARGET, action_id: str = "act-1") -> Action:
    args: dict[str, Any] = {"flags": "-sV -Pn"}
    if target is not None:
        args["target"] = target
    return Action(action_id=action_id, tool_name="nmap", args=args)


def _executor(handler: Any, settings: SimpleNamespace | None = None, **kw: Any) -> RemoteExecutor:
    client = httpx.Client(
        base_url="https://vm.internal:8443", transport=httpx.MockTransport(handler)
    )
    return RemoteExecutor(
        settings or _settings(), client=client, claims=MemoryClaims(), poll_interval=0.0, **kw
    )


# --------------------------------------------------------------------------- selector


def test_selector_default_config_is_dry_run() -> None:
    default = _settings(
        allow_active_testing=False,
        exec_api_url="",
        exec_api_token=SecretStr(""),
        exec_api_ca_cert=Path("does-not-exist.pem"),
        exec_egress_allowlist=[],
    )
    assert isinstance(make_executor(default), DryRunExecutor)


@pytest.mark.parametrize(
    "missing",
    [
        {"allow_active_testing": False},
        {"exec_api_url": ""},
        {"exec_api_token": SecretStr("")},
        {"exec_api_ca_cert": Path("does-not-exist.pem")},
    ],
)
def test_selector_each_missing_precondition_falls_back_to_dry_run(missing: dict[str, Any]) -> None:
    assert isinstance(make_executor(_settings(**missing)), DryRunExecutor)


def test_selector_all_preconditions_met_selects_remote() -> None:
    assert isinstance(make_executor(_settings()), RemoteExecutor)


# --------------------------------------------------------------------------- egress gate


def test_out_of_scope_target_denied_before_any_http() -> None:
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(201, json={"job_id": "act-1", "state": "running"})

    ex = _executor(handler)
    with pytest.raises(EgressDenied):
        ex.run(_action(target="evil.example.com"))
    assert calls == []  # denied purely client-side; nothing left the orchestrator


def test_missing_target_denied_before_any_http() -> None:
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(201, json={"job_id": "act-1", "state": "running"})

    ex = _executor(handler)
    with pytest.raises(EgressDenied):
        ex.run(_action(target=None))
    assert calls == []


# --------------------------------------------------------------------------- auth / claim


def test_bad_token_raises_auth_error() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "bad token"})

    ex = _executor(handler)
    with pytest.raises(RemoteAuthError):
        ex.run(_action())


def test_duplicate_dispatch_is_claimed_once_and_makes_no_second_post() -> None:
    posts: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            posts.append(req)
            return httpx.Response(201, json={"job_id": "act-1", "state": "running"})
        return httpx.Response(200, json={"job_id": "act-1", "state": "done", "exit_code": 0})

    claims = MemoryClaims()
    client = httpx.Client(
        base_url="https://vm.internal:8443", transport=httpx.MockTransport(handler)
    )
    ex = RemoteExecutor(_settings(), client=client, claims=claims, poll_interval=0.0)
    ex.run(_action())
    with pytest.raises(DispatchAlreadyClaimed):
        ex.run(_action())  # same action_id
    assert len(posts) == 1


# --------------------------------------------------------------------------- happy path


def test_happy_path_posts_polls_and_returns_result() -> None:
    seen: list[tuple[str, str]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        if req.method == "POST" and req.url.path == "/jobs":
            assert req.headers["Authorization"] == f"Bearer {TOKEN}"
            body = json.loads(req.content)
            assert body == {
                "job_id": "act-1",
                "tool": "nmap",
                "args": {"flags": "-sV -Pn", "target": TARGET},
                "target": TARGET,
            }
            return httpx.Response(201, json={"job_id": "act-1", "state": "running"})
        if req.method == "GET" and req.url.path == "/jobs/act-1":
            # first poll still running, then terminal — exercises the loop
            n = sum(1 for m, p in seen if m == "GET")
            if n < 2:
                return httpx.Response(200, json={"job_id": "act-1", "state": "running", "exit_code": None})
            return httpx.Response(200, json={"job_id": "act-1", "state": "done", "exit_code": 0})
        raise AssertionError(f"unexpected {req.method} {req.url.path}")

    result = _executor(handler).run(_action())
    assert result.simulated is False
    assert result.tool == "nmap"
    assert result.args == {"flags": "-sV -Pn", "target": TARGET}
    assert "done" in result.summary.lower()
    # polled at least twice (running -> done) and dumps cleanly for graph.execute
    assert sum(1 for m, _ in seen if m == "GET") >= 2
    assert result.model_dump(mode="json")["simulated"] is False
