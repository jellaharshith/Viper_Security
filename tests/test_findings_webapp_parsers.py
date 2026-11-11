"""Deterministic parsers for the v1.2 web-app probes: JSONL -> list[Finding]. Fixture-driven,
offline only. ``confidence="confirmed"`` only for an unambiguous accept/reject or marker signal
in the probe's own output; a single-shot SQLi probe without a baseline stays a "hypothesis".
"""

from __future__ import annotations

import json

import pytest

from viper.findings import parsers
from viper.findings.parsers import parse_injection_probe, parse_otp_probe, parse_upload_probe

TARGET = "sandbox.securegateway.com"


def _jsonl(*records: dict) -> str:
    return "\n".join(json.dumps(r) for r in records)


# ---------------------------------------------------------------------------- OTP

def test_otp_rate_limit_probe_with_no_lockout_is_a_confirmed_finding() -> None:
    out = _jsonl(
        *[{"tool": "otp_2fa_probe", "mode": "rate_limit_probe", "attempt": i,
           "target": TARGET, "endpoint_path": "/x", "status_code": 401,
           "lockout_observed": False, "response_snippet": "no"} for i in range(1, 6)]
    )
    findings = parse_otp_probe(out, action_id="a1", target=TARGET, audit_refs=["h1"])
    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"
    assert findings[0].source_tool == "otp_2fa_probe"


def test_otp_rate_limit_probe_with_a_lockout_is_no_finding() -> None:
    out = _jsonl(
        {"tool": "otp_2fa_probe", "mode": "rate_limit_probe", "attempt": 1, "target": TARGET,
         "endpoint_path": "/x", "status_code": 429, "lockout_observed": True, "response_snippet": ""},
    )
    assert parse_otp_probe(out, action_id="a1", target=TARGET, audit_refs=[]) == []


def test_otp_enumerate_codes_success_is_a_confirmed_critical_finding() -> None:
    out = _jsonl(
        {"tool": "otp_2fa_probe", "mode": "enumerate_codes", "attempt": 1, "target": TARGET,
         "endpoint_path": "/x", "status_code": 401, "lockout_observed": False, "response_snippet": ""},
        {"tool": "otp_2fa_probe", "mode": "enumerate_codes", "attempt": 2, "target": TARGET,
         "endpoint_path": "/x", "status_code": 200, "lockout_observed": False, "response_snippet": ""},
    )
    findings = parse_otp_probe(out, action_id="a1", target=TARGET, audit_refs=[])
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].confidence == "confirmed"


def test_otp_enumerate_codes_all_failing_is_no_finding() -> None:
    out = _jsonl(
        {"tool": "otp_2fa_probe", "mode": "enumerate_codes", "attempt": 1, "target": TARGET,
         "endpoint_path": "/x", "status_code": 401, "lockout_observed": False, "response_snippet": ""},
    )
    assert parse_otp_probe(out, action_id="a1", target=TARGET, audit_refs=[]) == []


def test_otp_parser_ignores_garbled_lines() -> None:
    out = "not json\n{\"tool\": \"otp_2fa_probe\"}\n" + _jsonl(
        {"tool": "otp_2fa_probe", "mode": "rate_limit_probe", "attempt": 1, "target": TARGET,
         "endpoint_path": "/x", "status_code": 401, "lockout_observed": False, "response_snippet": ""},
    )
    findings = parse_otp_probe(out, action_id="a1", target=TARGET, audit_refs=[])
    assert len(findings) == 1


# ---------------------------------------------------------------------------- upload

def test_upload_accepted_is_a_confirmed_finding() -> None:
    out = _jsonl({"tool": "upload_bypass_probe", "variant": "content_detector_marker",
                  "target": TARGET, "endpoint_path": "/upload", "filename": "x.jpg",
                  "content_type": "image/jpeg", "status_code": 200, "response_snippet": "ok"})
    findings = parse_upload_probe(out, action_id="a1", target=TARGET, audit_refs=["h1"])
    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"
    assert findings[0].severity == "critical"


def test_upload_rejected_is_no_finding() -> None:
    out = _jsonl({"tool": "upload_bypass_probe", "variant": "content_detector_marker",
                  "target": TARGET, "endpoint_path": "/upload", "filename": "x.jpg",
                  "content_type": "image/jpeg", "status_code": 415, "response_snippet": "rejected"})
    assert parse_upload_probe(out, action_id="a1", target=TARGET, audit_refs=[]) == []


# ---------------------------------------------------------------------------- injection

def test_xss_marker_reflected_unescaped_is_a_confirmed_finding() -> None:
    out = _jsonl({"tool": "injection_probe", "technique": "xss_reflected_marker", "target": TARGET,
                  "endpoint_path": "/search", "param_name": "q", "status_code": 200,
                  "elapsed_ms": 10, "response_snippet": "<b>VIPER-x</b>",
                  "marker_reflected_unescaped": True})
    findings = parse_injection_probe(out, action_id="a1", target=TARGET, audit_refs=["h1"])
    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"


def test_xss_marker_not_reflected_is_no_finding() -> None:
    out = _jsonl({"tool": "injection_probe", "technique": "xss_reflected_marker", "target": TARGET,
                  "endpoint_path": "/search", "param_name": "q", "status_code": 200,
                  "elapsed_ms": 10, "response_snippet": "escaped", "marker_reflected_unescaped": False})
    assert parse_injection_probe(out, action_id="a1", target=TARGET, audit_refs=[]) == []


def test_sqli_boolean_single_shot_is_a_hypothesis_not_confirmed() -> None:
    out = _jsonl({"tool": "injection_probe", "technique": "sqli_boolean", "target": TARGET,
                  "endpoint_path": "/login", "param_name": "user", "status_code": 200,
                  "elapsed_ms": 10, "response_snippet": "logged in"})
    findings = parse_injection_probe(out, action_id="a1", target=TARGET, audit_refs=[])
    assert len(findings) == 1
    assert findings[0].confidence == "hypothesis"


def test_command_injection_marker_echoed_is_a_confirmed_finding() -> None:
    out = _jsonl({"tool": "injection_probe", "technique": "command_injection_marker", "target": TARGET,
                  "endpoint_path": "/ping", "param_name": "host", "status_code": 200,
                  "elapsed_ms": 10, "response_snippet": "VIPER-abc", "marker_echoed": True})
    findings = parse_injection_probe(out, action_id="a1", target=TARGET, audit_refs=[])
    assert findings[0].confidence == "confirmed"
    assert findings[0].severity == "critical"


@pytest.fixture
def secret_record() -> dict:
    return {"tool": "secret_scan", "target": TARGET, "path": "/static/app.js",
            "status_code": 200, "response_headers": {},
            "matches": [{"pattern_name": "aws_access_key", "redacted_snippet": "AKIA...ABCD"}]}


@pytest.fixture
def graphql_record() -> dict:
    return {"tool": "graphql_introspect", "target": TARGET, "path": "/graphql",
            "status_code": 200, "response_headers": {}, "introspection_enabled": True,
            "schema_type_count": 12}


def _crypto_parser(name: str):
    parser = getattr(parsers, name, None)
    assert callable(parser), f"missing parser: {name}"
    return parser


@pytest.mark.parametrize("pattern,severity", [
    ("aws_access_key", "high"), ("bearer_token", "high"),
    ("jwt", "high"), ("internal_hostname", "medium"),
])
def test_secret_scan_confirms_each_pattern_using_only_redacted_evidence(
    secret_record, pattern, severity,
):
    secret_record["matches"][0]["pattern_name"] = pattern
    secret_record["unexpected_raw_body"] = "MUST_NOT_APPEAR_IN_EVIDENCE"
    findings = _crypto_parser("parse_secret_scan")(
        _jsonl(secret_record), action_id="s1", target=TARGET, audit_refs=["h1"])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == severity and finding.confidence == "confirmed"
    assert finding.source_tool == "secret_scan" and finding.source_action_id == "s1"
    assert finding.affected_asset == TARGET and finding.audit_refs == ["h1"]
    assert finding.evidence == "AKIA...ABCD"


def test_secret_scan_deduplicates_pattern_and_path(secret_record):
    second_path = {**secret_record, "path": "/other.js"}
    second_pattern = {**secret_record, "matches": [
        {"pattern_name": "jwt", "redacted_snippet": "abcd...efgh"}]}
    findings, skipped = _crypto_parser("parse_secret_scan_ex")(
        _jsonl(secret_record, secret_record, second_path, second_pattern),
        action_id="s1", target=TARGET, audit_refs=[])
    assert len(findings) == 3 and len({f.id for f in findings}) == 3 and skipped == 0


def test_secret_scan_no_matches_produces_no_finding(secret_record):
    secret_record["matches"] = []
    assert _crypto_parser("parse_secret_scan_ex")(
        _jsonl(secret_record), action_id="s1", target=TARGET, audit_refs=[]) == ([], 0)


@pytest.mark.parametrize("bad", [
    {"matches": "aws_access_key"}, {"matches": [None]},
    {"matches": [{"pattern_name": "aws_access_key"}]},
    {"matches": [{"pattern_name": "unknown", "redacted_snippet": "redacted"}]},
    {"path": None},
])
def test_secret_scan_counts_malformed_records_and_keeps_valid_findings(secret_record, bad):
    output = "garbled\n{broken\n" + _jsonl({**secret_record, **bad}, secret_record)
    findings, skipped = _crypto_parser("parse_secret_scan_ex")(
        output, action_id="s1", target=TARGET, audit_refs=[])
    assert len(findings) == 1 and skipped == 3


def test_graphql_introspection_is_confirmed_medium_schema_disclosure(graphql_record):
    findings = _crypto_parser("parse_graphql_introspect")(
        _jsonl(graphql_record, graphql_record), action_id="g1", target=TARGET, audit_refs=["h2"])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.confidence == "confirmed" and finding.severity == "medium"
    assert finding.source_tool == "graphql_introspect" and finding.source_action_id == "g1"
    assert finding.affected_asset == TARGET and finding.audit_refs == ["h2"]
    assert json.loads(finding.evidence)["schema_type_count"] == 12


def test_graphql_disabled_is_no_finding(graphql_record):
    graphql_record["introspection_enabled"] = False
    assert _crypto_parser("parse_graphql_introspect_ex")(
        _jsonl(graphql_record), action_id="g1", target=TARGET, audit_refs=[]) == ([], 0)


@pytest.mark.parametrize("bad", [
    {"introspection_enabled": "true"}, {"introspection_enabled": 1},
    {"introspection_enabled": None}, {"path": []},
])
def test_graphql_counts_malformed_lines_and_keeps_valid_findings(graphql_record, bad):
    findings, skipped = _crypto_parser("parse_graphql_introspect_ex")(
        "garbled\n{broken\n" + _jsonl({**graphql_record, **bad}, graphql_record),
        action_id="g1", target=TARGET, audit_refs=[])
    assert len(findings) == 1 and skipped == 3
