"""Single-shot GraphQL introspection probe (CRYPTO-H1 round 1). Run on the VM by ``toolrunner``.

The introspection query is FIXED and server-side only — type/field names only, no field
arguments, nothing that could be mistaken for a real query against business data. Exactly ONE
HTTP request per invocation: no retry loop, no mutation, ever — this must never become a DoS
vector.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import httpx

try:
    from vmapi.probes._common import build_client, emit, parse_args_json, redact_headers
except ImportError:  # run as a bare VM subprocess: no vmapi package on sys.path, only this dir
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _common import build_client, emit, parse_args_json, redact_headers  # type: ignore[import-not-found]

# Fixed, server-side only; type/field names only, no field arguments, read-only.
INTROSPECTION_QUERY = (
    "{ __schema { queryType { name } mutationType { name } types { name kind } } }"
)


def run(args: dict[str, Any], *, client: httpx.Client) -> None:
    target = args["target"]
    path = args["path"]
    url = f"https://{target}{path}"
    response = client.post(url, json={"query": INTROSPECTION_QUERY})  # exactly one request

    record: dict[str, Any] = {
        "tool": "graphql_introspect",
        "target": target,
        "path": path,
        "status_code": response.status_code,
        "response_headers": redact_headers(dict(response.headers)),
        "introspection_enabled": False,
    }
    try:
        body: Any = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        data = body.get("data")
        if isinstance(data, dict) and "__schema" in data:
            record["introspection_enabled"] = True
            schema = data["__schema"]
            if isinstance(schema, dict):
                types = schema.get("types")
                if isinstance(types, list):
                    record["schema_type_count"] = len(types)
    emit(record)


def build_client_from_env() -> httpx.Client:  # pragma: no cover - thin wiring, exercised on the VM
    return build_client()


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin wiring, exercised on the VM
    args = parse_args_json(argv if argv is not None else sys.argv[1:])
    with build_client_from_env() as client:
        run(args, client=client)


if __name__ == "__main__":  # pragma: no cover
    main()
