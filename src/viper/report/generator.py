"""Markdown reports with inert evidence and citations bound to real tool results."""

from __future__ import annotations

import html
import json
import re
from typing import Any

from viper.findings.models import Finding
from viper.report.common import (
    SEVERITIES,
    citations_for,
    counts,
    extract_scanner_metrics,
    format_metric,
    neutralize,
    small_json,
    visible,
)


def _plain(text: str) -> str:
    escaped = html.escape(visible(text), quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+!|>~])", r"\\\1", escaped)


def _evidence(evidence: str) -> list[str]:
    language = ""
    try:
        content = json.dumps(neutralize(small_json(evidence)), ensure_ascii=False, indent=2, allow_nan=False)
        language = "json"
    except (ValueError, RecursionError):
        # Original line endings remain visibly represented, plus layout for readability.
        content = "\\x0a\n".join(visible(line) for line in evidence.split("\n"))
    longest = max((len(run) for run in re.findall(r"`+", content)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + language, content, fence]


def render_report(
    findings: list[Finding], audit_events: list[dict[str, Any]], *, project_id: str, thread_id: str,
) -> str:
    """Render parser findings; citation context is checked, not chain integrity or exploitability.

    Audit event payloads are never reproduced. Evidence is literal code, not HTML
    or Markdown, with a fence longer than every backtick run in the content.
    """
    totals = counts(findings)
    lines = ["# Viper assessment report", "", f"Project: {_plain(project_id)}",
             f"Thread: {_plain(thread_id)}", "", "## Executive summary", "",
             f"{totals['total']} findings: {totals['confirmed']} confirmed "
             f"and {totals['hypothesis']} hypotheses.",
             "", "| Severity | Confirmed | Hypothesis |", "|---|---:|---:|"]
    for severity in SEVERITIES:
        row = totals["by_severity_and_confidence"][severity]
        lines.append(f"| {severity} | {row['confirmed']} | {row['hypothesis']} |")
    lines += ["", "Assets are supplied as in-scope by the caller; scope is enforced upstream.",
              "Confirmed denotes parser evidence of the stated condition, not proof of exploitability.",
              "Audit citations identify supplied events; chain integrity must be verified separately.", ""]
    scanner_records = extract_scanner_metrics(audit_events, findings)
    lines += ["## Scanner metrics", ""]
    if scanner_records:
        lines += ["| Tool | Action | Executed templates | Requests |",
                  "|---|---|---:|---:|"]
        for m in scanner_records:
            t = _plain(m["tool"])
            a = _plain(m["action_id"])
            tc = format_metric(m["template_count"])
            rc = format_metric(m["request_count"])
            lines.append(f"| {t} | {a} | {tc} | {rc} |")
    else:
        lines += ["- Executed templates: unknown", "- Requests: unknown"]
    lines.append("")
    index: list[str] = []
    for confidence, heading in [("confirmed", "Confirmed findings"), ("hypothesis", "Hypotheses")]:
        lines += [f"## {heading}", ""]
        group = [finding for finding in findings if finding.confidence == confidence]
        if not group:
            lines += ["No confirmed findings." if confidence == "confirmed" else "No hypotheses.", ""]
        for tool in sorted({finding.source_tool for finding in group}):
            lines += [f"### {_plain(tool)}", ""]
            for finding in (finding for finding in group if finding.source_tool == tool):
                lines += [f"#### {_plain(finding.id)}: {_plain(finding.title)}", ""]
                fields = [("In-scope asset", finding.affected_asset), ("Source tool", finding.source_tool),
                          ("Source action", finding.source_action_id), ("Severity", finding.severity),
                          ("Severity rationale", finding.severity_rationale),
                          ("Confidence", finding.confidence),
                          ("Reproducibility", finding.reproducibility), ("Remediation", finding.remediation)]
                if finding.description:
                    fields.append(("Description", finding.description))
                if finding.cwe:
                    fields.append(("CWE", ", ".join(finding.cwe)))
                for label, value in fields:
                    lines += [f"{label}: {_plain(value)}", ""]
                lines += ["Evidence (raw excerpt):", "", *_evidence(finding.evidence), "", "References:", ""]
                lines += [f"- {_plain(ref)}" for ref in finding.references] or ["- None supplied."]
                lines += ["", "Audit citations:", ""]
                for citation in citations_for(finding, audit_events, thread_id):
                    ref = citation["reference"]
                    if citation["status"] != "resolved":
                        lines.append(f"- Unresolved audit reference: {_plain(ref)}" if ref is not None
                                     else "- Unresolved: no audit references supplied.")
                        continue
                    number = len(index) + 1
                    lines.append(f"- [audit-{number}](#audit-{number}): `{ref}`")
                    index.append(f'- <a id="audit-{number}"></a>[audit-{number}]: `{ref}`; '
                                 f"event {_plain(citation['event'])}; "
                                 f"sequence {_plain(str(citation['sequence']))}; "
                                 f"action {_plain(finding.source_action_id)}")
                lines += [""]
    lines += ["## Audit event index", ""] + (index or ["No resolved audit citations."])
    return "\n".join(lines) + "\n"
