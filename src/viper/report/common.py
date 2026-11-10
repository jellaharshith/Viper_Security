"""Shared report counting, display neutralisation and audit citation resolution.

Callers supply scope-checked findings and verified audit events. These helpers
check citation context, not audit-chain integrity or evidence digests.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from viper.findings.models import Finding

SEVERITIES = ("critical", "high", "medium", "low", "info")


def visible(text: str) -> str:
    """Make control, format/bidi and surrogate characters inert and visible."""
    parts = []
    for char in text:
        code = ord(char)
        if unicodedata.category(char) in {"Cc", "Cf", "Cs"}:
            parts.append(f"\\x{code:02x}" if code < 256 else
                         f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            parts.append(char)
    return "".join(parts)


def neutralize(value: Any) -> Any:
    """Neutralize every string in a report-owned JSON-compatible structure."""
    if isinstance(value, str):
        return visible(value)
    if isinstance(value, dict):
        return {visible(str(key)): neutralize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [neutralize(item) for item in value]
    return value


def counts(findings: list[Finding]) -> dict[str, Any]:
    matrix = {severity: {"confirmed": 0, "hypothesis": 0} for severity in SEVERITIES}
    for finding in findings:
        matrix[finding.severity][finding.confidence] += 1
    return {"total": len(findings),
            "confirmed": sum(f.confidence == "confirmed" for f in findings),
            "hypothesis": sum(f.confidence == "hypothesis" for f in findings),
            "by_severity": {severity: sum(row.values()) for severity, row in matrix.items()},
            "by_severity_and_confidence": matrix}


def citations_for(
    finding: Finding, events: list[dict[str, Any]], thread_id: str,
) -> list[dict[str, Any]]:
    citations = []
    for ref in finding.audit_refs:
        matches = [event for event in events if event.get("hash") == ref]
        event = matches[0] if len(matches) == 1 else {}
        detail = event.get("detail")
        resolved = (bool(re.fullmatch(r"[a-f0-9]{64}", ref))
                    and event.get("event") == "tool_result" and event.get("thread_id") == thread_id
                    and isinstance(detail, dict) and detail.get("action_id") == finding.source_action_id
                    and detail.get("tool") == finding.source_tool and detail.get("simulated") is False)
        citation: dict[str, Any] = {"finding_id": finding.id, "reference": ref,
                                    "status": "resolved" if resolved else "unresolved"}
        if resolved:
            seq = event.get("seq", "unknown")
            citation.update(event="tool_result", sequence=seq if type(seq) in (str, int) else "unknown",
                            source_action_id=finding.source_action_id, source_tool=finding.source_tool)
        citations.append(citation)
    return citations or [{"finding_id": finding.id, "reference": None, "status": "unresolved"}]


def small_json(evidence: str) -> Any:
    """Parse only small JSON evidence; malformed/deep/non-finite input stays raw."""
    if len(evidence.encode("utf-8", errors="surrogatepass")) >= 8192:
        raise ValueError("evidence is not small JSON")

    def reject_constant(value: str) -> None:
        raise ValueError("non-finite JSON")

    return json.loads(evidence, parse_constant=reject_constant)


def rule_id(finding: Finding) -> str:
    """Stable SARIF rule identity: nuclei template or nmap protocol/port."""
    if finding.source_tool == "nuclei":
        try:
            data = small_json(finding.evidence)
            template = data.get("template-id") if isinstance(data, dict) else None
        except (ValueError, RecursionError):
            template = None
        if not isinstance(template, str) or not template:
            match = re.search(r"\(([^()]+)\)$", finding.title)
            template = match[1] if match else finding.title
        return "nuclei:" + template
    match = re.search(r"\b([0-9]{1,5})/(tcp|udp)\b", finding.evidence)
    if match is None:
        match = re.search(r"\b([0-9]{1,5})/(tcp|udp)\b", finding.title)
    return f"nmap:{match[2]}/{int(match[1])}" if match else "nmap:" + finding.title
