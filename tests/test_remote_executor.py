"""Tests for the orchestrator-side execution client (factory selector + RemoteExecutor).

No real network: the VM Exec API is driven by an ``httpx.MockTransport`` (respx is not
installed). No real VM, no subprocess. The selector's fail-safe default is the primary
safety property under test: a default config must always yield ``DryRunExecutor``.
"""

from __future__ import annotations

import json
import re
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
    ExecutionPlaneUnreachable,
    RemoteAuthError,
    RemoteExecutor,
    RemoteJobError,
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
        if req.url.path.endswith("/stream"):
            return _sse(["x"])
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
            # the job id is namespaced per dispatch (see test_job_id_is_unique_*), so check shape
            assert re.fullmatch(r"act-1-[0-9a-f]{12}", body.pop("job_id"))
            assert body == {
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
        if req.url.path == "/jobs/act-1/stream":
            return _sse(["22/tcp open ssh"])
        raise AssertionError(f"unexpected {req.method} {req.url.path}")

    result = _executor(handler).run(_action())
    assert result.simulated is False
    assert result.tool == "nmap"
    assert result.args == {"flags": "-sV -Pn", "target": TARGET}
    assert "done" in result.summary.lower()
    # polled at least twice (running -> done) and dumps cleanly for graph.execute
    assert sum(1 for m, _ in seen if m == "GET") >= 2
    assert result.model_dump(mode="json")["simulated"] is False


# --------------------------------------------------------------------------- output capture


def _sse(lines: list[str]) -> httpx.Response:
    body = "".join(f"data: {ln}\n\n" for ln in lines)
    return httpx.Response(
        200, stream=_Chunks([body.encode()]), headers={"content-type": "text/event-stream"}
    )


def _job_handler(stream: Any, state: str = "done", seen: list[httpx.Request] | None = None) -> Any:
    def handler(req: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(req)
        if req.method == "POST":
            return httpx.Response(201, json={"job_id": "act-1", "state": "running"})
        if req.url.path.endswith("/stream"):
            return stream(req) if callable(stream) else stream
        return httpx.Response(200, json={"job_id": "act-1", "state": state, "exit_code": 0})

    return handler


def test_done_job_output_is_captured_from_stream() -> None:
    seen: list[httpx.Request] = []
    h = _job_handler(_sse(["PORT STATE SERVICE", "22/tcp open ssh", "80/tcp open http"]), seen=seen)
    result = _executor(h).run(_action())
    assert result.output == "PORT STATE SERVICE\n22/tcp open ssh\n80/tcp open http"
    assert result.simulated is False
    stream_reqs = [r for r in seen if r.url.path == "/jobs/act-1/stream"]
    assert len(stream_reqs) == 1
    assert stream_reqs[0].headers["Authorization"] == f"Bearer {TOKEN}"


def test_output_is_capped_at_one_mib_and_never_raises() -> None:
    big = ["x" * 1000] * 3000  # ~3 MB
    result = _executor(_job_handler(_sse(big))).run(_action())
    assert 0 < len(result.output.encode()) <= 1024 * 1024


def test_stream_http_error_after_done_raises() -> None:
    from viper.execution.remote import RemoteJobError

    h = _job_handler(lambda r: httpx.Response(500, text="boom"))
    with pytest.raises(RemoteJobError):
        _executor(h).run(_action())


def test_stream_transport_error_after_done_raises() -> None:
    from viper.execution.remote import RemoteJobError

    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadError("connection reset", request=req)

    with pytest.raises(RemoteJobError):
        _executor(_job_handler(boom)).run(_action())


def test_stream_401_raises_auth_error() -> None:
    h = _job_handler(lambda r: httpx.Response(401, json={"detail": "no"}))
    with pytest.raises(RemoteAuthError):
        _executor(h).run(_action())


def test_failed_job_still_raises_and_fetches_no_stream() -> None:
    from viper.execution.remote import RemoteJobError

    seen: list[httpx.Request] = []
    h = _job_handler(_sse(["secret partial output"]), state="failed", seen=seen)
    with pytest.raises(RemoteJobError):
        _executor(h).run(_action())
    assert not any(r.url.path.endswith("/stream") for r in seen)


def test_dry_run_stubs_have_empty_output() -> None:
    from viper.tools.registry import DryRunResult, default_registry

    assert DryRunResult(tool="t", summary="s").output == ""
    tool = default_registry.get("plan_scan")
    assert tool is not None
    assert tool.dry_run({"target": TARGET}).output == ""


# ------------------------------------------------- ROUND 4: bounded stream reading (#6)


class _Chunks(httpx.SyncByteStream):
    """A stream that yields given chunks, counts bytes pulled, optionally fails at the end."""

    def __init__(self, chunks: Any, fail: bool = False) -> None:
        self._chunks = chunks
        self._fail = fail
        self.pulled = 0

    def __iter__(self) -> Any:
        for c in self._chunks:
            self.pulled += len(c)
            yield c
        if self._fail:
            raise httpx.ReadError("late failure")


def _stream_resp(stream: _Chunks) -> httpx.Response:
    return httpx.Response(200, stream=stream, headers={"content-type": "text/event-stream"})


def test_chunk_boundaries_do_not_corrupt_lines() -> None:
    body = b"data: alpha\n\ndata: beta\r\n\n: comment\ndata:gamma\n\n"
    chunks = [body[i : i + 3] for i in range(0, len(body), 3)]
    r = _executor(_job_handler(_stream_resp(_Chunks(chunks)))).run(_action())
    assert r.output == "alpha\nbeta\ngamma"
    assert r.truncated is False


def test_unterminated_giant_line_is_bounded_and_truncated() -> None:
    from viper.execution import remote

    s = _Chunks([b"data: " + b"A" * 8192] + [b"A" * 8192] * 2000)  # ~16 MiB, no newline
    r = _executor(_job_handler(_stream_resp(s))).run(_action())
    assert r.truncated is True
    assert len(r.output.encode()) <= remote.MAX_OUTPUT_BYTES
    assert s.pulled <= remote.MAX_WIRE_BYTES + 65536  # stopped reading at the wire cap


def test_ignored_sse_fields_count_against_wire_cap() -> None:
    from viper.execution import remote

    s = _Chunks([b": keepalive " + b"x" * 4000 + b"\n"] * 5000)  # ~20 MB of ignored comments
    r = _executor(_job_handler(_stream_resp(s))).run(_action())
    assert r.output == ""
    assert r.truncated is True
    assert s.pulled <= remote.MAX_WIRE_BYTES + 65536


def test_capture_cap_sets_truncated_and_keeps_draining_to_observe_failure() -> None:
    from viper.execution.remote import RemoteJobError

    line = b"data: " + b"y" * 1000 + b"\n\n"
    chunks = [line] * 1500  # ~1.5 MB: past the 1 MiB capture cap, under the wire cap
    ok = _executor(_job_handler(_stream_resp(_Chunks(chunks)))).run(_action())
    assert ok.truncated is True and len(ok.output.encode()) <= 1024 * 1024
    with pytest.raises(RemoteJobError):  # failure AFTER the cap must still be seen
        _executor(_job_handler(_stream_resp(_Chunks(chunks, fail=True)))).run(_action())


def test_small_output_is_not_truncated() -> None:
    r = _executor(_job_handler(_sse(["a", "b"]))).run(_action())
    assert r.truncated is False


def test_stream_time_limit_stops_reading_and_marks_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    from viper.execution import remote

    ticks = iter(range(0, 10_000, 100))
    monkeypatch.setattr(remote, "_now", lambda: float(next(ticks)))
    s = _Chunks([b"data: " + b"x" * 8000 + b"\n\n"] * 1000)
    r = _executor(_job_handler(_stream_resp(s))).run(_action())
    assert r.truncated is True
    assert s.pulled < 8008 * 100  # stopped long before the 1000 chunks were pulled


def test_dry_run_result_truncated_defaults_false() -> None:
    from viper.tools.registry import DryRunResult

    assert DryRunResult(tool="t", summary="s").truncated is False


# ------------------------------------------- ROUND 5: stream limits cannot be bypassed


def test_stream_request_demands_identity_and_short_read_timeout() -> None:
    seen: list[httpx.Request] = []
    _executor(_job_handler(_sse(["a"]), seen=seen)).run(_action())
    (req,) = [r for r in seen if r.url.path.endswith("/stream")]
    assert req.headers["Accept-Encoding"] == "identity"
    assert req.extensions["timeout"]["read"] <= 10


@pytest.mark.parametrize("enc", ["gzip", "br", "deflate", "gzip, identity"])
def test_compressed_stream_response_is_refused(enc: str) -> None:
    import gzip

    from viper.execution.remote import RemoteJobError

    body = gzip.compress(b"data: bomb\n\n")
    resp = httpx.Response(
        200, stream=_Chunks([body]), headers={"content-encoding": enc, "content-type": "text/event-stream"}
    )
    with pytest.raises(RemoteJobError):
        _executor(_job_handler(resp)).run(_action())


def test_identity_content_encoding_is_accepted() -> None:
    resp = httpx.Response(
        200, stream=_Chunks([b"data: ok\n\n"]), headers={"content-encoding": "identity"}
    )
    assert _executor(_job_handler(resp)).run(_action()).output == "ok"


def test_slow_drip_stream_stops_at_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    from viper.execution import remote

    clock = {"t": 0.0}

    def now() -> float:
        clock["t"] += 50.0  # every observation costs 50 s of fake time
        return clock["t"]

    monkeypatch.setattr(remote, "_now", now)
    s = _Chunks([b"d"] * 10_000)  # one byte per network read
    r = _executor(_job_handler(_stream_resp(s))).run(_action())
    assert r.truncated is True
    assert s.pulled <= 5  # deadline enforced after every received chunk, not every 8 KiB


# --------------------------------------------------------------------------- job id namespacing

_VM_JOB_ID = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")  # mirrors vmapi.app.JobRequest.job_id


def _echo_vm(posted: list[str]) -> Any:
    """A VM that accepts any job id, records it, and finishes the job at once."""

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST" and req.url.path == "/jobs":
            job_id = json.loads(req.content)["job_id"]
            posted.append(job_id)
            return httpx.Response(201, json={"job_id": job_id, "state": "running"})
        if req.url.path.endswith("/stream"):
            return _sse(["ok"])
        return httpx.Response(200, json={"job_id": posted[-1], "state": "done", "exit_code": 0})

    return handler


def test_job_id_is_unique_per_dispatch_even_for_the_same_action_id() -> None:
    """Real Test 1: reusing an action id across runs collided with HTTP 409 until vmapi restarted."""
    posted: list[str] = []
    # two separate runs: fresh executors and claim stores, same action id
    _executor(_echo_vm(posted)).run(_action(action_id="nmap_scan"))
    _executor(_echo_vm(posted)).run(_action(action_id="nmap_scan"))
    assert len(posted) == 2 and posted[0] != posted[1]
    assert all(p.startswith("nmap_scan-") and _VM_JOB_ID.match(p) for p in posted)


def test_job_id_is_always_valid_for_the_vm_even_for_odd_action_ids() -> None:
    posted: list[str] = []
    odd = "act/with spaces.and:punct" + "x" * 300
    _executor(_echo_vm(posted)).run(_action(action_id=odd))
    assert _VM_JOB_ID.match(posted[0])


# --------------------------------------------------------------------------- unreachable plane


def test_dispatch_connect_error_is_reported_as_plane_unreachable() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=req)

    with pytest.raises(ExecutionPlaneUnreachable, match="unreachable") as err:
        _executor(handler).run(_action())
    assert isinstance(err.value, RemoteJobError)  # existing handlers keep working


def test_poll_timeout_after_dispatch_is_not_a_bare_read_timeout() -> None:
    """Spot preemption mid-scan used to surface as a generic httpx.ReadTimeout."""

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            return httpx.Response(201, json={"job_id": "act-1", "state": "running"})
        raise httpx.ReadTimeout("timed out", request=req)

    with pytest.raises(ExecutionPlaneUnreachable) as err:
        _executor(handler).run(_action())
    text = str(err.value)
    assert "act-1" in text and "preempt" in text.lower() and "ReadTimeout" in text
    assert "state is unknown" in text  # never imply the job did or did not run


def test_stream_transport_failure_is_reported_as_plane_unreachable() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            return httpx.Response(201, json={"job_id": "act-1", "state": "running"})
        if req.url.path.endswith("/stream"):
            raise httpx.ReadError("connection reset", request=req)
        return httpx.Response(200, json={"job_id": "act-1", "state": "done", "exit_code": 0})

    with pytest.raises(ExecutionPlaneUnreachable):
        _executor(handler).run(_action())
