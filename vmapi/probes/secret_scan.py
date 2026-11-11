"""Passive secret-scan probe (CRYPTO-H1 round 1). Run on the VM by ``toolrunner``.

Fetches ONE exact JS file path a browser visiting the page would also fetch — nothing more active
than that, which is why this tool is ``RiskLevel.PASSIVE`` and needs no human-approval gate. The
response body is scanned against a FIXED, server-side table of leaked-secret regexes; the caller
never supplies a regex or arbitrary content. Matched values are partially redacted before being
emitted (first 4 / last 4 characters only), since this output flows into an audit log.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any

import httpx

try:
    from vmapi.probes._common import build_client, emit, parse_args_json, redact_headers
except ImportError:  # run as a bare VM subprocess: no vmapi package on sys.path, only this dir
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _common import build_client, emit, parse_args_json, redact_headers  # type: ignore[import-not-found]

# Fixed, server-side only; never configurable by the caller.
INTERNAL_DOMAIN_SUFFIXES: tuple[str, ...] = (".internal.crypto.com",)

_INTERNAL_HOST_ALTERNATION = "|".join(re.escape(suffix) for suffix in INTERNAL_DOMAIN_SUFFIXES)

PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "bearer_token": re.compile(r"Bearer [A-Za-z0-9\-_.]{20,}"),
    # A real JWT's header segment is base64url of JSON starting '{"...', which always encodes
    # to "eyJ" - requiring that prefix is the standard JWT-detection heuristic. Without it this
    # matched ordinary minified-JS dotted property chains (e.g. a captcha library's
    # "geetest_holder.geetest_wind.geetest_fallback") as a "high severity exposed JWT".
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "internal_hostname": re.compile(rf"[a-z0-9-]+(?:{_INTERNAL_HOST_ALTERNATION})"),
}


def _redact(value: str) -> str:
    """First 4 and last 4 characters only; the full secret never reaches the emitted record."""
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def scan(body: str) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    for name, pattern in PATTERNS.items():
        for m in pattern.finditer(body):
            matches.append({"pattern_name": name, "redacted_snippet": _redact(m.group(0))})
    return matches


def run(args: dict[str, Any], *, client: httpx.Client) -> None:
    target = args["target"]
    path = args["path"]
    url = f"https://{target}{path}"
    response = client.get(url)
    body = response.text if response.status_code == 200 else ""
    record: dict[str, Any] = {
        "tool": "secret_scan",
        "target": target,
        "path": path,
        "status_code": response.status_code,
        "response_headers": redact_headers(dict(response.headers)),
        "matches": scan(body) if body else [],
    }
    emit(record)


def build_client_from_env() -> httpx.Client:  # pragma: no cover - thin wiring, exercised on the VM
    return build_client()


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin wiring, exercised on the VM
    args = parse_args_json(argv if argv is not None else sys.argv[1:])
    with build_client_from_env() as client:
        run(args, client=client)


if __name__ == "__main__":  # pragma: no cover
    main()
