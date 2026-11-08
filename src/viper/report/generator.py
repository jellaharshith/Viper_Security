"""Render schema-v1 findings without interpreting tool evidence as Markdown.

The caller enforces asset scope and supplies parser-produced findings. Citations
resolve only to real tool results within the requested thread/action/tool;
this renderer does not verify the audit chain or evidence digest itself.
"""

from __future__ import annotations

import html
import re
from typing import Any

from viper.findings.models import Finding

_DIRECTIONAL = frozenset({0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x2070)})


def _visible(text: str) -> str:
    """Expose control bytes and Unicode direction changes instead of executing them."""
    parts = []
    for char in text:
        code = ord(char)
        if code < 32 or 127 <= code <= 159:
            parts.append(f"\\x{code:02x}")
        elif code in _DIRECTIONAL:
            parts.append(f"\\u{code:04x}")
        else:
            parts.append(char)
    return "".join(parts)


def _plain(text: str) -> str:
    escaped = html.escape(_visible(text), quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+!|>~])", r"\\\1", escaped)


def render_report(
    findings: list[Finding], audit_events: list[dict[str, Any]], *, project_id: str, thread_id: str,
) -> str:
    """Produce Markdown; absent/ambiguous/foreign citations stay unresolved.

    Confirmed means the supplied deterministic parser observed the described
    condition, not that an exploit or security impact was independently proven.
    Audit payloads are deliberately not reproduced (they may contain secrets).
    """
    lines = ["# Viper assessment report", "", f"Project: {_plain(project_id)}",
             f"Thread: {_plain(thread_id)}", "",
             "Assets below are supplied as in-scope by the caller; scope is enforced upstream.",
             "Confirmed denotes parser evidence of the stated condition, not proof of exploitability.",
             "Audit citations identify supplied events; chain integrity must be verified separately.", ""]
    citations: list[str] = []
    for confidence, heading in [("confirmed", "Confirmed findings"), ("hypothesis", "Hypotheses")]:
        lines += [f"## {heading}", ""]
        group = [finding for finding in findings if finding.confidence == confidence]
        if not group:
            lines += ["No confirmed findings." if confidence == "confirmed" else "No hypotheses.", ""]
        for finding in group:
            lines += [f"### {_plain(finding.id)}: {_plain(finding.title)}", ""]
            for label, value in [
                ("In-scope asset", finding.affected_asset), ("Source tool", finding.source_tool),
                ("Source action", finding.source_action_id), ("Severity", finding.severity),
                ("Severity rationale", finding.severity_rationale), ("Confidence", finding.confidence),
                ("Reproducibility", finding.reproducibility), ("Remediation", finding.remediation),
            ]:
                lines += [f"{label}: {_plain(value)}", ""]
            # Indented blocks cannot be terminated by attacker-controlled fences.
            lines += ["Evidence (raw excerpt):", ""]
            # Preserve evidence line layout while showing each original LF visibly.
            evidence_lines = finding.evidence.split("\n")
            for index, line in enumerate(evidence_lines):
                suffix = r"\x0a" if index < len(evidence_lines) - 1 else ""
                lines += ["    " + html.escape(_visible(line) + suffix)]
            lines += ["", "References:", ""]
            lines += [f"- {_plain(ref)}" for ref in finding.references] or ["- None supplied."]
            lines += ["", "Audit citations:", ""]
            for ref in finding.audit_refs:
                matches = [e for e in audit_events if e.get("hash") == ref]
                event = matches[0] if len(matches) == 1 else {}
                detail = event.get("detail")
                if (not re.fullmatch(r"[a-f0-9]{64}", ref)
                        or event.get("event") != "tool_result"
                        or event.get("thread_id") != thread_id
                        or not isinstance(detail, dict)
                        or detail.get("action_id") != finding.source_action_id
                        or detail.get("tool") != finding.source_tool
                        or detail.get("simulated") is not False):
                    lines += [f"- Unresolved audit reference: {_plain(ref)}"]
                    continue
                number = len(citations) + 1
                lines += [f"- [audit-{number}](#audit-{number}): `{ref}`"]
                kind = _plain(str(event.get("event", "unknown")))
                citations += [f'- <a id="audit-{number}"></a>[audit-{number}]: `{ref}`; event {kind}; '
                              f"sequence {_plain(str(event.get('seq', 'unknown')))}; "
                              f"action {_plain(finding.source_action_id)}"]
            if not finding.audit_refs:
                lines += ["- Unresolved: no audit references supplied."]
            lines += [""]
    lines += ["## Audit event index", ""] + (citations or ["No resolved audit citations."])
    return "\n".join(lines) + "\n"
