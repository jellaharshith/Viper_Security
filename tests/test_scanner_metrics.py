"""Tests for Defect 4: per-run scanner metrics (template and request counts)."""

from __future__ import annotations

import json
from pathlib import Path

from viper.findings.models import Finding
from viper.findings.parsers import parse_nuclei_metrics
from viper.report.common import extract_scanner_metrics, format_metric
from viper.report.formats import render_json, render_sarif
from viper.report.generator import render_report
from viper.tools.registry import DryRunResult

FIXTURES = Path(__file__).parent / "fixtures" / "findings"
HEAD = "a" * 64


def test_parse_nuclei_metrics_from_stats_json() -> None:
    output = (
        '{"template-id":"apache-detect","matcher-status":true}\n'
        '{"timestamp":"2026-11-09T10:00:00Z","templates":42,"requests":150}\n'
    )
    metrics = parse_nuclei_metrics(output)
    assert metrics["template_count"] == 42
    assert metrics["request_count"] == 150


def test_parse_nuclei_metrics_from_text_stats() -> None:
    output = (
        "[INF] Starting scan\n"
        "[0:00:10] | Templates: 18 | Requests: 85 (8.5/s) |\n"
    )
    metrics = parse_nuclei_metrics(output)
    assert metrics["template_count"] == 18
    assert metrics["request_count"] == 85


def test_parse_nuclei_metrics_from_jsonl_findings_without_stats() -> None:
    output = (FIXTURES / "nuclei_real.jsonl").read_text(encoding="utf-8")
    metrics = parse_nuclei_metrics(output)
    # nuclei_real.jsonl has 4 distinct template-ids (http-missing-security-headers,
    # apache-detect, git-config-exposure, cdn-redirect-detect), but no stats line
    assert metrics["template_count"] == 4
    assert metrics["request_count"] is None  # missing, never 0


def test_parse_nuclei_metrics_empty_output_returns_none() -> None:
    metrics = parse_nuclei_metrics("")
    assert metrics["template_count"] is None
    assert metrics["request_count"] is None


def test_format_metric_missing_renders_unknown_never_zero() -> None:
    assert format_metric(None) == "unknown"
    assert format_metric(0) == "0"
    assert format_metric(42) == "42"


def test_dry_run_result_auto_populates_scanner_metrics_for_nuclei() -> None:
    output = '{"timestamp":"2026-11-09T10:00:00Z","templates":12,"requests":60}\n'
    res = DryRunResult(
        tool="nuclei",
        args={"target": "127.0.0.1"},
        summary="done",
        simulated=False,
        output=output,
    )
    assert res.template_count == 12
    assert res.request_count == 60


def test_dry_run_result_preserves_none_for_missing_metrics() -> None:
    res = DryRunResult(
        tool="nuclei",
        args={"target": "127.0.0.1"},
        summary="done",
        simulated=False,
        output="",
    )
    assert res.template_count is None
    assert res.request_count is None


def _finding() -> Finding:
    return Finding.model_validate({
        "id": "F1",
        "title": "Missing Header",
        "affected_asset": "127.0.0.1",
        "source_tool": "nuclei",
        "source_action_id": "scan_nuclei",
        "evidence": '{"template-id":"http-missing-security-headers"}',
        "severity": "info",
        "severity_rationale": "Missing header",
        "confidence": "confirmed",
        "reproducibility": "nuclei -u 127.0.0.1",
        "remediation": "Add headers",
        "references": [],
        "audit_refs": [HEAD],
    })


def test_report_markdown_renders_scanner_metrics() -> None:
    event = {
        "hash": HEAD,
        "thread_id": "t1",
        "event": "tool_result",
        "seq": 4,
        "detail": {
            "action_id": "scan_nuclei",
            "tool": "nuclei",
            "digest": "b" * 64,
            "simulated": False,
            "template_count": 35,
            "request_count": 120,
        },
    }
    report = render_report([_finding()], [event], project_id="lab", thread_id="t1")
    assert "## Scanner metrics" in report
    assert r"scan\_nuclei" in report
    assert "35" in report
    assert "120" in report


def test_report_markdown_missing_metrics_render_as_unknown_never_zero() -> None:
    event = {
        "hash": HEAD,
        "thread_id": "t1",
        "event": "tool_result",
        "seq": 4,
        "detail": {
            "action_id": "scan_nuclei",
            "tool": "nuclei",
            "digest": "b" * 64,
            "simulated": False,
            # no template_count or request_count
        },
    }
    report = render_report([_finding()], [event], project_id="lab", thread_id="t1")
    assert "## Scanner metrics" in report
    assert "unknown" in report
    # must not invent a 0
    lines = [ln for ln in report.splitlines() if r"scan\_nuclei" in ln]
    assert lines
    assert " 0 " not in lines[0]


def test_report_json_and_sarif_include_scanner_metrics() -> None:
    event = {
        "hash": HEAD,
        "thread_id": "t1",
        "event": "tool_result",
        "seq": 4,
        "detail": {
            "action_id": "scan_nuclei",
            "tool": "nuclei",
            "digest": "b" * 64,
            "simulated": False,
            "template_count": 20,
            "request_count": 99,
        },
    }
    json_rep = json.loads(render_json([_finding()], [event], project_id="lab", thread_id="t1"))
    assert "scanner_metrics" in json_rep
    metrics = json_rep["scanner_metrics"]
    assert len(metrics) == 1
    assert metrics[0]["tool"] == "nuclei"
    assert metrics[0]["action_id"] == "scan_nuclei"
    assert metrics[0]["template_count"] == 20
    assert metrics[0]["request_count"] == 99

    sarif_rep = json.loads(render_sarif([_finding()], [event], project_id="lab", thread_id="t1"))
    run_props = sarif_rep["runs"][0]["properties"]
    assert "scanner_metrics" in run_props
    assert run_props["scanner_metrics"][0]["template_count"] == 20
    assert run_props["scanner_metrics"][0]["request_count"] == 99


def test_report_json_and_sarif_missing_metrics_render_as_unknown() -> None:
    event = {
        "hash": HEAD,
        "thread_id": "t1",
        "event": "tool_result",
        "seq": 4,
        "detail": {
            "action_id": "scan_nuclei",
            "tool": "nuclei",
            "digest": "b" * 64,
            "simulated": False,
        },
    }
    json_rep = json.loads(render_json([_finding()], [event], project_id="lab", thread_id="t1"))
    m = json_rep["scanner_metrics"][0]
    assert m["template_count"] == "unknown"
    assert m["request_count"] == "unknown"


def test_extract_scanner_metrics_direct() -> None:
    events = [
        {"event": "tool_dispatch", "detail": {"tool": "nuclei"}},  # ignored
        {"event": "tool_result", "detail": {"tool": "nmap", "action_id": "n1"}},  # ignored
        {
            "event": "tool_result",
            "detail": {
                "tool": "nuclei",
                "action_id": "u1",
                "template_count": 50,
                "request_count": 200,
            },
        },
    ]
    records = extract_scanner_metrics(events)
    assert len(records) == 1
    assert records[0] == {
        "tool": "nuclei",
        "action_id": "u1",
        "template_count": 50,
        "request_count": 200,
    }

