"""v1.2 web-app probe scripts: offline only, via httpx.MockTransport — never a live socket."""
# ruff: noqa: S101 -- pytest assertions

from __future__ import annotations

import json

import httpx
import pytest
from vmapi.probes import graphql_introspect, injection_probe, otp_2fa_probe, secret_scan, upload_bypass_probe

TARGET = "sandbox.securegateway.com"
ROYAL = "sandbox-royal.securegateway.com"


def _lines(capsys: pytest.CaptureFixture[str]) -> list[dict]:
    out = capsys.readouterr().out.strip().splitlines()
    return [json.loads(line) for line in out if line]


# ---------------------------------------------------------------------------- otp_2fa_probe

def test_otp_rate_limit_probe_makes_exactly_max_attempts_requests_and_stops(capsys) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(401, json={"error": "invalid code"})

    client = otp_2fa_probe.build_client(transport=httpx.MockTransport(handler))
    otp_2fa_probe.run({
        "target": TARGET, "endpoint_path": "/api/2fa/verify",
        "mode": "rate_limit_probe", "max_attempts": 4, "delay_ms": 100,
    }, client=client, sleep=lambda _ms: None)
    assert len(calls) == 4
    records = _lines(capsys)
    assert len(records) == 4
    assert all(r["tool"] == "otp_2fa_probe" for r in records)
    assert all(r["attempt"] == i + 1 for i, r in enumerate(records))


def test_otp_probe_stops_early_on_an_explicit_lockout_response(capsys) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        status = 429 if len(calls) >= 2 else 401
        return httpx.Response(status)

    client = otp_2fa_probe.build_client(transport=httpx.MockTransport(handler))
    otp_2fa_probe.run({
        "target": TARGET, "endpoint_path": "/api/2fa/verify",
        "mode": "rate_limit_probe", "max_attempts": 10, "delay_ms": 100,
    }, client=client, sleep=lambda _ms: None)
    assert len(calls) == 2  # stopped at the first 429, not all 10 attempts
    records = _lines(capsys)
    assert records[-1]["status_code"] == 429
    assert records[-1]["lockout_observed"] is True


def test_otp_probe_never_sends_a_real_password_field() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        assert "password" not in body.lower()
        return httpx.Response(401)

    client = otp_2fa_probe.build_client(transport=httpx.MockTransport(handler))
    otp_2fa_probe.run({
        "target": TARGET, "endpoint_path": "/api/2fa/verify",
        "mode": "enumerate_codes", "max_attempts": 2, "delay_ms": 100,
    }, client=client, sleep=lambda _ms: None)


# ---------------------------------------------------------------------------- upload_bypass_probe

def test_upload_probe_sends_a_multipart_request_and_records_whether_it_was_accepted(capsys) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        return httpx.Response(200, text="upload ok")

    client = upload_bypass_probe.build_client(transport=httpx.MockTransport(handler))
    upload_bypass_probe.run({
        "target": TARGET, "endpoint_path": "/upload",
        "variant": "content_detector_marker",
    }, client=client)
    records = _lines(capsys)
    assert len(records) == 1
    assert records[0]["tool"] == "upload_bypass_probe"
    assert records[0]["status_code"] == 200


def test_content_detector_marker_file_is_a_valid_jpeg_containing_the_literal_marker() -> None:
    content, filename, content_type = upload_bypass_probe.build_payload("content_detector_marker")
    assert filename.endswith(".jpg")
    assert content.startswith(b"\xff\xd8")  # JPEG magic bytes: a real, valid image
    assert b"php_uname" in content
    assert content_type == "image/jpeg"


def test_disallowed_extension_render_file_has_no_offensive_script_beyond_a_harmless_marker() -> None:
    content, filename, content_type = upload_bypass_probe.build_payload("disallowed_extension_render")
    text = content.decode()
    assert "VIPER-POC-" in text
    # Never a shell/backdoor payload: no process/file/network primitives in the marker file.
    for banned in ("eval(", "exec(", "system(", "subprocess", "<?php"):
        assert banned not in text


# ---------------------------------------------------------------------------- injection_probe

@pytest.mark.parametrize("technique", [
    "sqli_boolean", "sqli_time", "xss_reflected_marker",
    "command_injection_marker", "url_injection_redirect",
])
def test_every_technique_has_exactly_one_fixed_reviewed_payload(technique: str) -> None:
    payload = injection_probe.PAYLOADS[technique]
    assert isinstance(payload, str) and payload


def test_injection_probe_sends_the_param_as_a_query_string_value(capsys) -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, text="ok")

    client = injection_probe.build_client(transport=httpx.MockTransport(handler))
    injection_probe.run({
        "target": ROYAL, "endpoint_path": "/search",
        "param_name": "q", "technique": "xss_reflected_marker",
    }, client=client)
    assert "q=" in seen["url"]
    records = _lines(capsys)
    assert records[0]["technique"] == "xss_reflected_marker"


def test_injection_probe_never_runs_a_destructive_sql_statement() -> None:
    for technique in ("sqli_boolean", "sqli_time"):
        payload = injection_probe.PAYLOADS[technique].lower()
        for banned in ("drop ", "delete ", "update ", "insert ", "union select"):
            assert banned not in payload


# ---------------------------------------------------------------------------- secret_scan

def test_secret_scan_detects_each_fixed_secret_shape_and_redacts_it(capsys) -> None:
    body = (
        "const key = 'AKIAABCDEFGHIJKLMNOP';"
        "const auth = 'Bearer abcdefghijklmnopqrstuvwxyz0123456789';"
        "const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';"
        "const host = 'api-internal.internal.crypto.com';"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    client = secret_scan.build_client(transport=httpx.MockTransport(handler))
    secret_scan.run({"target": TARGET, "path": "/static/app.js"}, client=client)
    records = _lines(capsys)
    assert len(records) == 1
    record = records[0]
    assert record["tool"] == "secret_scan"
    names = {m["pattern_name"] for m in record["matches"]}
    assert {"aws_access_key", "bearer_token", "jwt", "internal_hostname"} <= names
    for m in record["matches"]:
        if m["pattern_name"] == "aws_access_key":
            assert "AKIAABCDEFGHIJKLMNOP" not in m["redacted_snippet"]  # never the full secret
            assert m["redacted_snippet"].startswith("AKIA")


def test_secret_scan_clean_response_yields_no_matches(capsys) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="console.log('nothing to see here');")

    client = secret_scan.build_client(transport=httpx.MockTransport(handler))
    secret_scan.run({"target": TARGET, "path": "/static/app.js"}, client=client)
    assert _lines(capsys)[0]["matches"] == []


def test_secret_scan_non_200_does_not_crash_and_reports_no_matches(capsys) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="AKIAABCDEFGHIJKLMNOP")  # would match if the body were scanned

    client = secret_scan.build_client(transport=httpx.MockTransport(handler))
    secret_scan.run({"target": TARGET, "path": "/static/missing.js"}, client=client)
    records = _lines(capsys)
    assert records[0]["status_code"] == 404
    assert records[0]["matches"] == []


def test_secret_scan_empty_body_yields_no_matches(capsys) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="")

    client = secret_scan.build_client(transport=httpx.MockTransport(handler))
    secret_scan.run({"target": TARGET, "path": "/static/empty.js"}, client=client)
    assert _lines(capsys)[0]["matches"] == []


# ---------------------------------------------------------------------------- graphql_introspect

def test_graphql_introspect_detects_enabled_introspection(capsys) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={
            "data": {"__schema": {
                "queryType": {"name": "Query"}, "mutationType": None,
                "types": [{"name": "Query", "kind": "OBJECT"}, {"name": "String", "kind": "SCALAR"}],
            }},
        })

    client = graphql_introspect.build_client(transport=httpx.MockTransport(handler))
    graphql_introspect.run({"target": TARGET, "path": "/graphql"}, client=client)
    assert len(calls) == 1  # exactly one request, no retry loop
    records = _lines(capsys)
    assert records[0]["introspection_enabled"] is True
    assert records[0]["schema_type_count"] == 2


def test_graphql_introspect_false_on_error_response(capsys) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"errors": [{"message": "introspection disabled"}]})

    client = graphql_introspect.build_client(transport=httpx.MockTransport(handler))
    graphql_introspect.run({"target": TARGET, "path": "/graphql"}, client=client)
    assert _lines(capsys)[0]["introspection_enabled"] is False


def test_graphql_introspect_false_when_data_has_no_schema_key(capsys) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"me": {"id": 1}}})

    client = graphql_introspect.build_client(transport=httpx.MockTransport(handler))
    graphql_introspect.run({"target": TARGET, "path": "/graphql"}, client=client)
    assert _lines(capsys)[0]["introspection_enabled"] is False


def test_graphql_introspect_sends_exactly_one_request_no_matter_the_response() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(500, text="boom")

    client = graphql_introspect.build_client(transport=httpx.MockTransport(handler))
    graphql_introspect.run({"target": TARGET, "path": "/graphql"}, client=client)
    assert len(calls) == 1


def test_graphql_introspect_query_has_no_field_arguments_and_is_not_a_mutation() -> None:
    query = graphql_introspect.INTROSPECTION_QUERY
    assert "(" not in query  # no field arguments anywhere
    assert query.strip().startswith("{ __schema")  # a query, never a mutation
