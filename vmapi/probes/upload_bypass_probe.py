"""Upload allow-list / content-detector bypass probe (v1.2). Run on the VM by ``toolrunner``.

Two fixed, reviewed variants only. File BYTES are built here by ``build_payload`` — a constant
template per variant — never supplied by the model or the orchestrator, so there is no path from
a proposed action to an actual webshell/backdoor byte.
"""

from __future__ import annotations

import os
import sys
import uuid
from typing import Any

import httpx

try:
    from vmapi.probes._common import build_client, emit, parse_args_json, redact_headers, session_headers
except ImportError:  # run as a bare VM subprocess: no vmapi package on sys.path, only this dir
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _common import build_client, emit, parse_args_json, redact_headers, session_headers  # type: ignore[import-not-found]

# A real, valid, minimal JPEG (1x1 px) followed by a COM (comment) segment carrying the literal
# marker string the content detector is documented to flag. Harmless: no executable content.
_MINIMAL_JPEG = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000ffdb004300"
    + "01" * 63
    + "ffc0000b08000100010100000000ffc4001000010000000000000000000000000000"
    + "ffda0008010100003f00d2ffd9"
)


def build_payload(variant: str) -> tuple[bytes, str, str]:
    """Fixed, reviewed (content, filename, content_type) for one variant. Never model-supplied."""
    marker = f"VIPER-POC-{uuid.uuid4().hex[:12]}"
    if variant == "content_detector_marker":
        # A JPEG COM (comment) segment (marker 0xFFFE) carrying the literal string the content
        # detector is documented to flag, spliced right after the SOI marker of a real, valid JPEG.
        comment_bytes = f"php_uname {marker}".encode()
        segment = b"\xff\xfe" + (len(comment_bytes) + 2).to_bytes(2, "big") + comment_bytes
        content = _MINIMAL_JPEG[:2] + segment + _MINIMAL_JPEG[2:]
        return content, "viper-poc.jpg", "image/jpeg"
    if variant == "disallowed_extension_render":
        # A harmless, self-identifying marker: proves rendering/execution without doing anything
        # beyond setting document.title. No shell, no file/process/network access of any kind.
        html = (
            "<!doctype html><html><body>"
            f"<script>document.title='{marker}';</script>"
            "</body></html>"
        )
        return html.encode(), "viper-poc.html", "text/html"
    raise ValueError(f"unknown variant {variant!r}")


def run(args: dict[str, Any], *, client: httpx.Client) -> None:
    target = args["target"]
    endpoint_path = args["endpoint_path"]
    variant = args["variant"]
    url = f"https://{target}{endpoint_path}"
    content, filename, content_type = build_payload(variant)
    headers = session_headers()
    response = client.post(url, files={"file": (filename, content, content_type)}, headers=headers)
    emit({
        "tool": "upload_bypass_probe", "variant": variant, "target": target,
        "endpoint_path": endpoint_path, "filename": filename, "content_type": content_type,
        "status_code": response.status_code,
        "response_headers": redact_headers(dict(response.headers)),
        "response_snippet": response.text[:512],
    })


def build_client_from_env() -> httpx.Client:  # pragma: no cover - thin wiring, exercised on the VM
    return build_client()


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin wiring, exercised on the VM
    args = parse_args_json(argv if argv is not None else sys.argv[1:])
    with build_client_from_env() as client:
        run(args, client=client)


if __name__ == "__main__":  # pragma: no cover
    main()
