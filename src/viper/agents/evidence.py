"""Evidence binding (M7): the verified audit log is the authority, the checkpoint is a cache.

Findings are only ever produced by re-parsing a tool output that (a) belongs to a real
``tool_result`` audit event, (b) matches the SHA-256 digest committed in that event, and
(c) is bound to the exact action the policy approved (same arguments, same action hash).
The checkpoint is mutable state, so we never trust it for what ran or what it returned:
we iterate the AUDITED results and require exactly one matching checkpoint entry for each.
Anything missing, duplicated, edited or unaudited becomes a warning, never a "clean" report.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

from viper.findings.models import Finding
from viper.findings.parsers import parse_nmap_ex, parse_nuclei_ex

_PARSERS = {"nmap": parse_nmap_ex, "nuclei": parse_nuclei_ex}


def digest(output: str) -> str:
    return hashlib.sha256(output.encode("utf-8")).hexdigest()


def rederive(
    results: list[dict[str, Any]],
    events: list[dict[str, Any]],
    *,
    actions: list[dict[str, Any]],
    bind: Callable[[dict[str, Any]], str | None],
) -> tuple[list[Finding], list[str]]:
    """``events`` must come from a verified chain; ``bind`` recomputes an action's policy hash."""
    findings: list[Finding] = []
    warnings: list[str] = []
    by_id = {str(a.get("action_id")): a for a in actions}
    claimed: set[str] = set()
    for ev in events:
        detail = ev.get("detail") or {}
        if ev.get("event") != "tool_result" or detail.get("simulated", True):
            continue  # only real, audited executions are evidence
        action_id, tool, ev_hash = str(detail.get("action_id")), str(detail.get("tool")), str(ev.get("hash"))
        claimed.add(ev_hash)
        matches = [r for r in results if r.get("audit_hash") == ev_hash]
        if not matches:
            warnings.append(f"{action_id}: audited result missing from checkpoint; analysis is incomplete")
            continue
        if len(matches) > 1:
            warnings.append(f"{action_id}: duplicate checkpoint results for one audited result; ignored")
            continue
        r, action = matches[0], by_id.get(action_id)
        if (r.get("action_id") != action_id or r.get("tool") != tool or r.get("simulated") is not False
                or action is None or action.get("tool_name") != tool
                or r.get("args") != action.get("args") or bind(action) != ev.get("action_hash")):
            warnings.append(f"{action_id}: checkpoint result does not match its audited binding; ignored")
            continue
        output = str(r.get("output", ""))
        if detail.get("digest") != digest(output):
            warnings.append(f"{action_id}: output digest mismatch; output ignored")
            continue
        if detail.get("truncated"):  # the audited flag wins over whatever the checkpoint says
            warnings.append(f"{action_id}: output truncated; analysis is incomplete")
        parser = _PARSERS.get(tool)
        if parser is None:
            continue
        try:
            parsed, skipped = parser(output, action_id=action_id,
                                     target=str(action.get("args", {}).get("target", "")),
                                     audit_refs=[ev_hash])
            findings += parsed
            if skipped:
                warnings.append(
                    f"{action_id}: {skipped} record(s) skipped as malformed; analysis is incomplete")
        except Exception:  # noqa: BLE001 - never turn a parser failure into "no findings"
            warnings.append(f"{action_id}: parser failed; analysis is incomplete")
    for r in results:  # a result that claims real execution but has no audit event is not evidence
        if not r.get("simulated", True) and str(r.get("audit_hash")) not in claimed:
            warnings.append(f"{r.get('action_id')}: result without an audit event ignored")
    return findings, warnings
