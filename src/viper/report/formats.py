"""JSON and SARIF 2.1.0 exports; no audit payloads, implicit trust or network calls."""

from __future__ import annotations

import json
from typing import Any

from viper.findings.models import Finding
from viper.report.common import (
    citations_for,
    counts,
    extract_scanner_metrics,
    neutralize,
    rule_id,
)


def _dump(data: dict[str, Any]) -> str:
    return json.dumps(neutralize(data), ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def _format_scanner_metrics(
    audit_events: list[dict[str, Any]], findings: list[Finding]
) -> list[dict[str, Any]]:
    metrics = extract_scanner_metrics(audit_events, findings)
    if not metrics:
        return [{
            "tool": "nuclei",
            "action_id": "unknown",
            "template_count": "unknown",
            "request_count": "unknown",
        }]
    return [
        {
            "tool": m["tool"],
            "action_id": m["action_id"],
            "template_count": m["template_count"] if m["template_count"] is not None else "unknown",
            "request_count": m["request_count"] if m["request_count"] is not None else "unknown",
        }
        for m in metrics
    ]


def render_json(
    findings: list[Finding], audit_events: list[dict[str, Any]], *, project_id: str, thread_id: str,
) -> str:
    """Export findings and contextual citation status, not a claim of audit-chain verification."""
    return _dump({"schema": "viper-report/1", "project_id": project_id, "thread_id": thread_id,
                  "counts": counts(findings),
                  "scanner_metrics": _format_scanner_metrics(audit_events, findings),
                  "findings": [finding.model_dump(mode="json") for finding in findings],
                  "audit_citations": [citation for finding in findings
                                      for citation in citations_for(finding, audit_events, thread_id)]})


def render_sarif(
    findings: list[Finding], audit_events: list[dict[str, Any]], *, project_id: str, thread_id: str,
) -> str:
    """One rule per template or protocol/port, with logical asset locations and stable fingerprints."""
    rules: dict[str, dict[str, str]] = {}
    results = []
    for finding in findings:
        key = rule_id(finding)
        rules.setdefault(key, {"id": key})
        results.append({
            "ruleId": key,
            "level": {"info": "note", "low": "note", "medium": "warning",
                      "high": "error", "critical": "error"}[finding.severity],
            "message": {"text": finding.title},
            "properties": {"confidence": finding.confidence, "severity": finding.severity,
                           "source_action_id": finding.source_action_id, "audit_refs": finding.audit_refs,
                           "description": finding.description, "cwe": finding.cwe,
                           "audit_citations": citations_for(finding, audit_events, thread_id)},
            "locations": [{"logicalLocations": [{"name": finding.affected_asset}]}],
            "partialFingerprints": {"viperFindingId/v1": finding.id},
        })
    return _dump({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Viper", "rules": list(rules.values())}},
                "properties": {
                    "project_id": project_id,
                    "thread_id": thread_id,
                    "counts": counts(findings),
                    "scanner_metrics": _format_scanner_metrics(audit_events, findings),
                },
                "results": results,
            }
        ],
    })
