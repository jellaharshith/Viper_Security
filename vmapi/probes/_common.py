"""Shared plumbing for v1.2 web-app probes: arg parsing, session headers, JSONL emission.

Output contract mirrors nuclei's ``-jsonl``: one JSON object per line on stdout, so the existing
``RemoteExecutor._fetch_output`` -> audit log -> findings-parser pipeline applies unchanged.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from typing import Any

import httpx


def parse_args_json(argv: list[str]) -> dict[str, Any]:
    parser = argparse.ArgumentParser()
    parser.add_argument("--args-json", required=True)
    parsed = parser.parse_args(argv)
    data = json.loads(parsed.args_json)
    if not isinstance(data, dict):
        raise ValueError("--args-json must decode to a JSON object")
    return data


def session_headers() -> dict[str, str]:
    """Headers for the researcher's own pre-authorized test account, from a VM-local file only.

    Never sourced from argv/args: this is the mechanism that keeps a credential out of the audit
    log (which persists ``Action.args``) and off the wire between the orchestrator and this VM.
    """
    path = os.environ.get("VIPER_EXEC_ALSCO_TEST_SESSION_FILE")
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def build_client(transport: httpx.BaseTransport | None = None) -> httpx.Client:
    """TLS is verified by default. ``VIPER_EXEC_ALSCO_ACCEPT_EXPIRED_CERT=1`` is a narrow,
    explicit, operator-set exception for this engagement's single allowlisted target (its own
    cert expired) - never a general default, and never read from ``Action.args``/the wire.
    """
    accept_expired = os.environ.get("VIPER_EXEC_ALSCO_ACCEPT_EXPIRED_CERT") == "1"
    return httpx.Client(
        verify=not accept_expired, timeout=10.0, follow_redirects=False,
        headers={"User-Agent": "viper-webapp-probe/1.2"}, transport=transport,
    )


def emit(record: Mapping[str, Any]) -> None:
    sys.stdout.write(json.dumps(dict(record), sort_keys=True) + "\n")
    sys.stdout.flush()


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Never print the researcher's own session credential into logs/evidence."""
    sensitive = {"authorization", "cookie", "x-api-key"}
    return {k: ("<redacted>" if k.lower() in sensitive else v) for k, v in headers.items()}
