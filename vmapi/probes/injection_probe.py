"""Single-shot, non-destructive injection detection probe (v1.2). Run on the VM by ``toolrunner``.

``PAYLOADS`` is a fixed, reviewed table: one string per technique, never a model- or caller-
supplied payload. Every entry is a *detection* probe (boolean diff, timing, reflected/echoed
marker, redirect check) — never a destructive statement or a real OS command. Confirming the
finding stops at "the condition exists"; the researcher performs and records the actual chained
exploitation manually, as the bounty requires.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from typing import Any

import httpx

try:
    from vmapi.probes._common import build_client, emit, parse_args_json, redact_headers, session_headers
except ImportError:  # run as a bare VM subprocess: no vmapi package on sys.path, only this dir
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _common import build_client, emit, parse_args_json, redact_headers, session_headers  # type: ignore[import-not-found]

_MARKER = f"VIPER-{uuid.uuid4().hex[:10]}"

PAYLOADS: dict[str, str] = {
    "sqli_boolean": "' OR '1'='1",
    "sqli_time": "' OR SLEEP(3)-- -",
    "xss_reflected_marker": f"<b>{_MARKER}</b>",
    "command_injection_marker": f"; echo {_MARKER}",
    "url_injection_redirect": "https://example.invalid/viper-redirect-poc",
}


def run(args: dict[str, Any], *, client: httpx.Client) -> None:
    target = args["target"]
    endpoint_path = args["endpoint_path"]
    param_name = args["param_name"]
    technique = args["technique"]
    url = f"https://{target}{endpoint_path}"
    payload = PAYLOADS[technique]
    headers = session_headers()

    start = time.monotonic()
    response = client.get(url, params={param_name: payload}, headers=headers)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    record: dict[str, Any] = {
        "tool": "injection_probe", "technique": technique, "target": target,
        "endpoint_path": endpoint_path, "param_name": param_name,
        "status_code": response.status_code, "elapsed_ms": elapsed_ms,
        "response_headers": redact_headers(dict(response.headers)),
        "response_snippet": response.text[:512],
    }
    if technique == "xss_reflected_marker":
        record["marker_reflected_unescaped"] = payload in response.text
    elif technique == "command_injection_marker":
        record["marker_echoed"] = _MARKER in response.text
    elif technique == "url_injection_redirect":
        location = response.headers.get("location", "")
        record["redirected_to_payload"] = "viper-redirect-poc" in location
    emit(record)


def build_client_from_env() -> httpx.Client:  # pragma: no cover - thin wiring, exercised on the VM
    return build_client()


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin wiring, exercised on the VM
    args = parse_args_json(argv if argv is not None else sys.argv[1:])
    with build_client_from_env() as client:
        run(args, client=client)


if __name__ == "__main__":  # pragma: no cover
    main()
