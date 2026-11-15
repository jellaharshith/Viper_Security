"""OTP/2FA rate-limit and bypass probe (v1.2). Run on the VM by ``toolrunner.build_command``.

Two fixed, reviewed modes only — never a free-text attack script:
- ``rate_limit_probe``: repeats ONE known-wrong code, stops at the first explicit lockout/
  throttle signal (HTTP 429, or a 403/423 naming a lockout) or at ``max_attempts``, whichever
  comes first. Confirms whether the rate limit exists and how many attempts it tolerates.
- ``enumerate_codes``: sequential, small, bounded OTP guesses against the researcher's OWN
  pre-authorized test session (its headers come from ``session_headers()``, never from args).

Emits one JSONL record per attempt; a human/the findings parser decides what counts as a
confirmed bypass. This script only observes and reports.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable
from typing import Any

import httpx

try:
    from vmapi.probes._common import build_client, emit, parse_args_json, redact_headers, session_headers
except ImportError:  # run as a bare VM subprocess: no vmapi package on sys.path, only this dir
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _common import build_client, emit, parse_args_json, redact_headers, session_headers  # type: ignore[import-not-found]

_WRONG_CODE = "000000"
_LOCKOUT_STATUSES = frozenset({429, 423})


def _is_lockout(response: httpx.Response) -> bool:
    if response.status_code in _LOCKOUT_STATUSES:
        return True
    if response.status_code == 403:
        body = response.text.lower()
        return "lock" in body or "rate" in body or "too many" in body
    return False


def run(args: dict[str, Any], *, client: httpx.Client,
        sleep: Callable[[int], None] = lambda ms: time.sleep(ms / 1000)) -> None:
    target = args["target"]
    endpoint_path = args["endpoint_path"]
    mode = args["mode"]
    max_attempts = int(args["max_attempts"])
    delay_ms = int(args.get("delay_ms", 250))
    url = f"https://{target}{endpoint_path}"
    headers = session_headers()

    for attempt in range(1, max_attempts + 1):
        code = _WRONG_CODE if mode == "rate_limit_probe" else f"{attempt:06d}"
        response = client.post(url, data={"otp_code": code}, headers=headers)
        lockout = _is_lockout(response)
        emit({
            "tool": "otp_2fa_probe", "mode": mode, "attempt": attempt, "target": target,
            "endpoint_path": endpoint_path, "status_code": response.status_code,
            "response_headers": redact_headers(dict(response.headers)),
            "response_snippet": response.text[:512], "lockout_observed": lockout,
        })
        if lockout:
            break
        if attempt < max_attempts:
            sleep(delay_ms)


def build_client_from_env() -> httpx.Client:  # pragma: no cover - thin wiring, exercised on the VM
    return build_client()


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin wiring, exercised on the VM
    args = parse_args_json(argv if argv is not None else sys.argv[1:])
    with build_client_from_env() as client:
        run(args, client=client)


if __name__ == "__main__":  # pragma: no cover
    main()
