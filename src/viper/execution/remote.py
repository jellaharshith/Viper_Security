"""Orchestrator -> VM execution client.

``RemoteExecutor`` posts one *already-approved* policy ``Action`` to the Exec API over TLS
(verifying the VM's CA), re-asserts the target against the client-side egress allowlist
*before* any byte leaves the orchestrator, binds a durable single-use dispatch claim, polls
the job to a terminal state, and returns a result shaped like ``registry.DryRunResult`` with
``simulated=False`` so ``graph.execute`` is unchanged.

Selection of this executor over ``DryRunExecutor`` is the job of ``factory.make_executor``;
reaching here already means active testing was explicitly enabled and fully configured.
"""

from __future__ import annotations

import ssl
import time
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import httpx
from pydantic import SecretStr

from viper.agents.claims import ClaimStore, MemoryClaims
from viper.policy.models import Action
from viper.tools.registry import DryRunResult, ToolRegistry, default_registry

# Terminal job states per the SHARED CONTRACT (Exec API v1). "running"/"paused" are not terminal.
TERMINAL_STATES = frozenset({"done", "killed", "failed"})
# Hard cap on captured stdout kept in memory/checkpoints; excess is truncated, never an error.
MAX_OUTPUT_BYTES = 1024 * 1024
# Independent bounds on what the client will *read* from a stream, ignored SSE fields included.
MAX_WIRE_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_STREAM_SECONDS = 120.0
STREAM_CHUNK_BYTES = 8192


def _now() -> float:
    return time.monotonic()


@runtime_checkable
class ExecSettings(Protocol):
    """The settings surface this client reads. Kept as a Protocol so this module imports
    nothing from ``config.py`` (owned by the coordinator) and stays decoupled from wiring."""

    allow_active_testing: bool
    exec_api_url: str
    exec_api_token: SecretStr
    exec_api_ca_cert: Path
    exec_egress_allowlist: list[str]


class RemoteExecutionError(RuntimeError):
    """Base class for every remote-execution failure."""


class EgressDenied(RemoteExecutionError):
    """The action's target is absent from, or not present in, the egress allowlist."""


class DispatchAlreadyClaimed(RemoteExecutionError):
    """This ``action_id`` was already dispatched; the durable claim blocks re-sending it."""


class RemoteAuthError(RemoteExecutionError):
    """The Exec API rejected the bearer token (HTTP 401)."""


class RemoteJobError(RemoteExecutionError):
    """Unexpected HTTP status, or the job never reached a terminal state."""


class RemoteExecutor:
    def __init__(
        self,
        settings: ExecSettings,
        registry: ToolRegistry | None = None,
        *,
        client: httpx.Client | None = None,
        claims: ClaimStore | None = None,
        poll_interval: float = 2.0,
        max_polls: int = 600,
    ) -> None:
        self._settings = settings
        self._registry = registry or default_registry
        self._claims: ClaimStore = claims if claims is not None else MemoryClaims()
        self._poll_interval = poll_interval
        self._max_polls = max_polls
        self._auth = {"Authorization": f"Bearer {settings.exec_api_token.get_secret_value()}"}
        # Lazy: an executor must be constructible without building a TLS context. The real
        # client (verified against the VM CA) is built on first dispatch; tests inject one.
        self._client = client

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            ctx = ssl.create_default_context(cafile=str(self._settings.exec_api_ca_cert))
            self._client = httpx.Client(
                base_url=self._settings.exec_api_url,
                verify=ctx,
                timeout=30.0,
                follow_redirects=False,
            )
        return self._client

    def run(self, action: Action) -> DryRunResult:
        target = self._check_egress(action.args.get("target"))  # client-side gate, BEFORE any HTTP
        if not self._claims.claim(f"dispatch:{action.action_id}"):
            raise DispatchAlreadyClaimed(action.action_id)
        job = self._dispatch(action, target)
        state, exit_code = self._poll(str(job["job_id"]))
        output, truncated = self._fetch_output(str(job["job_id"])) if state == "done" else ("", False)
        return self._result_for(action, state, exit_code, output, truncated)

    def _fetch_output(self, job_id: str) -> tuple[str, bool]:
        """Replay the SSE stream of a finished job (same TLS client + bearer auth).

        Reads bounded byte chunks into a bounded line buffer, so memory and time are limited
        no matter what the server sends (including oversized or unterminated lines and ignored
        SSE fields). Returns ``(output, truncated)``: ``data:`` payloads joined by newlines,
        capped at ``MAX_OUTPUT_BYTES``. After the capture cap is hit the stream keeps being
        drained (discarding) up to ``MAX_WIRE_BYTES``/``MAX_STREAM_SECONDS`` so a later stream
        failure is still observed. Hitting any limit sets ``truncated`` and never raises; a
        401, non-200 or transport failure raises, so a finished job can never become
        success-with-missing-output.
        """
        lines: list[bytes] = []
        size = 0
        truncated = False
        wire = 0
        buf = bytearray()
        overflow = False  # current line already exceeded MAX_LINE_BYTES; discard until newline

        def take(line: bytes) -> None:
            nonlocal size, truncated
            if not line.startswith(b"data:"):
                return
            payload = line[5:]
            if payload.startswith(b" "):
                payload = payload[1:]
            room = MAX_OUTPUT_BYTES - size - (1 if lines else 0)
            if room <= 0:
                truncated = True
                return
            if len(payload) > room:
                payload = payload[:room]
                truncated = True
            size += len(payload) + (1 if lines else 0)
            lines.append(payload)

        try:
            start = _now()
            with self._get_client().stream(
                "GET", f"/jobs/{job_id}/stream", headers=self._auth
            ) as resp:
                if resp.status_code == 401:
                    raise RemoteAuthError(f"Exec API rejected the bearer token on stream {job_id}")
                if resp.status_code != 200:
                    raise RemoteJobError(f"GET /jobs/{job_id}/stream returned {resp.status_code}")
                for chunk in resp.iter_bytes(chunk_size=STREAM_CHUNK_BYTES):
                    wire += len(chunk)
                    parts = chunk.split(b"\n")
                    for i, part in enumerate(parts):
                        if not overflow:
                            buf += part
                            if len(buf) > MAX_LINE_BYTES:
                                del buf[MAX_LINE_BYTES:]
                                overflow = True
                                truncated = True
                        if i < len(parts) - 1:  # a newline ended this line
                            if not overflow or buf.startswith(b"data:"):
                                take(bytes(buf).rstrip(b"\r"))
                            buf.clear()
                            overflow = False
                    if wire >= MAX_WIRE_BYTES or _now() - start > MAX_STREAM_SECONDS:
                        truncated = True
                        break
                else:
                    if buf and not overflow:
                        take(bytes(buf).rstrip(b"\r"))
        except httpx.HTTPError as exc:
            raise RemoteJobError(f"stream for job {job_id} failed: {exc.__class__.__name__}") from exc
        return b"\n".join(lines).decode("utf-8", errors="replace"), truncated

    def _check_egress(self, target: Any) -> str:
        allow = getattr(self._settings, "exec_egress_allowlist", []) or []
        if not isinstance(target, str) or target not in allow:
            raise EgressDenied(f"target {target!r} is not in the egress allowlist")
        return target

    def _dispatch(self, action: Action, target: str) -> dict[str, Any]:
        body = {
            "job_id": action.action_id,
            "tool": action.tool_name,
            "args": dict(action.args),
            "target": target,
        }
        resp = self._get_client().post("/jobs", json=body, headers=self._auth)
        if resp.status_code == 401:
            raise RemoteAuthError("Exec API rejected the bearer token on POST /jobs")
        if resp.status_code != 201:
            raise RemoteJobError(f"POST /jobs returned {resp.status_code}")
        data: dict[str, Any] = resp.json()
        return data

    def _poll(self, job_id: str) -> tuple[str, int | None]:
        for _ in range(self._max_polls):
            resp = self._get_client().get(f"/jobs/{job_id}", headers=self._auth)
            if resp.status_code == 401:
                raise RemoteAuthError(f"Exec API rejected the bearer token on GET /jobs/{job_id}")
            if resp.status_code != 200:
                raise RemoteJobError(f"GET /jobs/{job_id} returned {resp.status_code}")
            payload = resp.json()
            state = str(payload.get("state"))
            if state in TERMINAL_STATES:
                exit_code = payload.get("exit_code")
                return state, exit_code if exit_code is None else int(exit_code)
            time.sleep(self._poll_interval)
        raise RemoteJobError(f"job {job_id} did not reach a terminal state in {self._max_polls} polls")

    def _result_for(
        self,
        action: Action,
        state: str,
        exit_code: int | None,
        output: str = "",
        truncated: bool = False,
    ) -> DryRunResult:
        """Map a terminal job ``state`` to the result handed back to ``graph.execute``.

        The returned value MUST be a ``registry.DryRunResult`` carrying ``tool``, ``args`` and
        ``simulated=False`` (it was real execution). ``state`` is one of ``TERMINAL_STATES``.

        Only ``done`` is a successful completion. ``failed``/``killed`` raise ``RemoteJobError``
        so the caller can never record a job that errored or was emergency-stopped as a clean
        result; ``DryRunResult`` has no status field to carry that distinction otherwise.
        """
        target = action.args.get("target")
        if state != "done":
            raise RemoteJobError(
                f"{action.tool_name} on {target!r} ended {state} (exit_code={exit_code})"
            )
        return DryRunResult(
            tool=action.tool_name,
            args=dict(action.args),
            summary=f"{action.tool_name} on {target!r} completed: done (exit_code={exit_code})",
            simulated=False,
            output=output,
            truncated=truncated,
        )
