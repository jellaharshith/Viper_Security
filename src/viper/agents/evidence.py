"""Evidence binding (M7): findings are re-derived from tool output whose digest was audited.

The audit chain proves the log was not edited, but state in a checkpoint can still be changed.
So a finding is only ever produced by re-parsing an output whose SHA-256 matches the digest
committed in the ``tool_result`` audit event, and the event must be bound to that exact
action and tool. Anything else is dropped and reported as a warning, never as "clean".
"""

from __future__ import annotations

import hashlib
from typing import Any

from viper.findings.models import Finding
from viper.findings.parsers import parse_nmap_ex, parse_nuclei_ex

_PARSERS = {"nmap": parse_nmap_ex, "nuclei": parse_nuclei_ex}


def digest(output: str) -> str:
    return hashlib.sha256(output.encode("utf-8")).hexdigest()


def rederive(
    results: list[dict[str, Any]], events: list[dict[str, Any]],
) -> tuple[list[Finding], list[str]]:
    by_hash = {str(e.get("hash")): e for e in events}
    findings: list[Finding] = []
    warnings: list[str] = []
    for r in results:
        if r.get("simulated", True):
            continue
        action_id, tool = str(r.get("action_id")), str(r.get("tool"))
        event = by_hash.get(str(r.get("audit_hash")))
        detail = (event or {}).get("detail") or {}
        if (event is None or event.get("event") != "tool_result"
                or detail.get("action_id") != action_id or detail.get("tool") != tool):
            warnings.append(f"{action_id}: no matching tool_result audit event; output ignored")
            continue
        output = str(r.get("output", ""))
        if detail.get("digest") != digest(output):
            warnings.append(f"{action_id}: output digest mismatch; output ignored")
            continue
        if r.get("truncated"):
            warnings.append(f"{action_id}: output truncated; analysis is incomplete")
        parser = _PARSERS.get(tool)
        if parser is None:
            continue
        try:
            parsed, skipped = parser(output, action_id=action_id,
                                     target=str(r.get("args", {}).get("target", "")),
                                     audit_refs=[str(event["hash"])])
            findings += parsed
            if skipped:
                warnings.append(
                    f"{action_id}: {skipped} record(s) skipped as malformed; analysis is incomplete")
        except Exception:  # noqa: BLE001 - never turn a parser failure into "no findings"
            warnings.append(f"{action_id}: parser failed; analysis is incomplete")
    return findings, warnings
