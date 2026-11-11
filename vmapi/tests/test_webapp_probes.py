"""v1.2 web-app probe tools on the VM side: argv construction only, same allowlist discipline as
nmap/nuclei (``vmapi.toolrunner.build_command``). No network, no subprocess execution here.
"""
# ruff: noqa: S101 -- pytest assertions

from __future__ import annotations

import json
import sys

import pytest
from vmapi.toolrunner import TOOLS, build_command

ALLOWED = frozenset({"sandbox.securegateway.com", "sandbox-royal.securegateway.com"})


def test_new_tools_are_in_the_allowlist() -> None:
    assert {"otp_2fa_probe", "upload_bypass_probe", "injection_probe"} <= set(TOOLS)


def test_otp_probe_builds_a_python_subprocess_argv_with_json_args() -> None:
    args = {"target": "sandbox.securegateway.com", "endpoint_path": "/api/2fa/verify",
            "mode": "rate_limit_probe", "max_attempts": 5, "delay_ms": 500}
    command = build_command("otp_2fa_probe", args, "sandbox.securegateway.com", ALLOWED)
    assert command[0] == sys.executable
    assert command[1].endswith("otp_2fa_probe.py")
    assert "--args-json" in command
    payload = json.loads(command[command.index("--args-json") + 1])
    assert payload == args


def test_upload_probe_builds_argv() -> None:
    args = {"target": "sandbox.securegateway.com", "endpoint_path": "/upload",
            "variant": "content_detector_marker"}
    command = build_command("upload_bypass_probe", args, "sandbox.securegateway.com", ALLOWED)
    assert command[1].endswith("upload_bypass_probe.py")


def test_injection_probe_builds_argv() -> None:
    args = {"target": "sandbox-royal.securegateway.com", "endpoint_path": "/login",
            "param_name": "username", "technique": "sqli_boolean"}
    command = build_command("injection_probe", args, "sandbox-royal.securegateway.com", ALLOWED)
    assert command[1].endswith("injection_probe.py")


def test_unallowlisted_arg_rejected_for_each_new_tool() -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        build_command("otp_2fa_probe", {"target": "sandbox.securegateway.com",
                      "endpoint_path": "/x", "mode": "rate_limit_probe", "max_attempts": 5,
                      "extra_flag": "x"}, "sandbox.securegateway.com", ALLOWED)


def test_target_not_allowlisted_rejected() -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        build_command("otp_2fa_probe", {"target": "evil.com", "endpoint_path": "/x",
                      "mode": "rate_limit_probe", "max_attempts": 5}, "evil.com", ALLOWED)


def test_target_mismatch_between_args_and_positional_rejected() -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        build_command("otp_2fa_probe", {"target": "sandbox.securegateway.com",
                      "endpoint_path": "/x", "mode": "rate_limit_probe", "max_attempts": 5},
                      "sandbox-royal.securegateway.com", ALLOWED)


@pytest.mark.parametrize("mode", ["anything_goes", "", 5, None])
def test_otp_mode_must_be_one_of_the_fixed_set(mode: object) -> None:
    with pytest.raises(ValueError):
        build_command("otp_2fa_probe", {"target": "sandbox.securegateway.com",
                      "endpoint_path": "/x", "mode": mode, "max_attempts": 5},
                      "sandbox.securegateway.com", ALLOWED)


@pytest.mark.parametrize("max_attempts", [0, -1, 51, "5", True, 5.0, None])
def test_otp_max_attempts_is_a_bounded_strict_int(max_attempts: object) -> None:
    with pytest.raises(ValueError):
        build_command("otp_2fa_probe", {"target": "sandbox.securegateway.com",
                      "endpoint_path": "/x", "mode": "rate_limit_probe",
                      "max_attempts": max_attempts}, "sandbox.securegateway.com", ALLOWED)


@pytest.mark.parametrize("variant", ["upload_a_webshell", "", 5])
def test_upload_variant_must_be_one_of_the_fixed_set(variant: object) -> None:
    with pytest.raises(ValueError):
        build_command("upload_bypass_probe", {"target": "sandbox.securegateway.com",
                      "endpoint_path": "/x", "variant": variant}, "sandbox.securegateway.com",
                      ALLOWED)


@pytest.mark.parametrize("technique", ["drop_tables", "", 5])
def test_injection_technique_must_be_one_of_the_fixed_set(technique: object) -> None:
    with pytest.raises(ValueError):
        build_command("injection_probe", {"target": "sandbox-royal.securegateway.com",
                      "endpoint_path": "/x", "param_name": "p", "technique": technique},
                      "sandbox-royal.securegateway.com", ALLOWED)


@pytest.mark.parametrize("param_name", ["", "a" * 65, "bad name", "bad;name", 5])
def test_injection_param_name_is_bounded(param_name: object) -> None:
    with pytest.raises(ValueError):
        build_command("injection_probe", {"target": "sandbox-royal.securegateway.com",
                      "endpoint_path": "/x", "param_name": param_name,
                      "technique": "sqli_boolean"}, "sandbox-royal.securegateway.com", ALLOWED)


@pytest.mark.parametrize("endpoint_path", ["", "no-leading-slash", "/x" * 200,
                                           "/x\n/y", "http://evil.com/x", "/x\x00y"])
def test_endpoint_path_is_sane_for_every_new_tool(endpoint_path: object) -> None:
    for tool, extra in (
        ("otp_2fa_probe", {"mode": "rate_limit_probe", "max_attempts": 5}),
        ("upload_bypass_probe", {"variant": "content_detector_marker"}),
        ("injection_probe", {"param_name": "p", "technique": "sqli_boolean"}),
    ):
        with pytest.raises(ValueError):
            build_command(tool, {"target": "sandbox.securegateway.com",
                          "endpoint_path": endpoint_path, **extra},
                          "sandbox.securegateway.com", ALLOWED)


@pytest.mark.parametrize("tool,path", [
    ("secret_scan", "/static/app.js"), ("graphql_introspect", "/api/graphql"),
])
def test_crypto_probes_build_exact_python_argv(tool, path):
    args = {"target": "sandbox.securegateway.com", "path": path}
    command = build_command(tool, args, args["target"], ALLOWED)
    assert tool in TOOLS
    assert command[:3] == [sys.executable, f"/opt/viper/probes/{tool}.py", "--args-json"]
    assert len(command) == 4 and json.loads(command[3]) == args


def test_graphql_omitted_path_is_materialized_in_subprocess_payload():
    command = build_command("graphql_introspect", {"target": "sandbox.securegateway.com"},
                            "sandbox.securegateway.com", ALLOWED)
    assert json.loads(command[3]) == {"target": "sandbox.securegateway.com", "path": "/graphql"}


@pytest.mark.parametrize("tool,path,field", [
    ("secret_scan", "/app.js", "regex"), ("secret_scan", "/app.js", "content"),
    ("graphql_introspect", "/graphql", "query"),
    ("graphql_introspect", "/graphql", "endpoint_path"),
])
def test_crypto_rejects_unallowlisted_fields_on_otherwise_valid_request(tool, path, field):
    args = {"target": "sandbox.securegateway.com", "path": path}
    assert build_command(tool, args, args["target"], ALLOWED)
    with pytest.raises(ValueError, match="allowlisted"):
        build_command(tool, {**args, field: "injected"}, args["target"], ALLOWED)


@pytest.mark.parametrize("tool", ["secret_scan", "graphql_introspect"])
@pytest.mark.parametrize("path", [
    "", "/", "no-slash.js", "/x.js?token=x", "/x y.js", "/x;id.js", "/x\n.js",
    "/x.js\n", "/x\x00.js", "//evil.com:443/x.js", "/caf\u00e9.js", 5, None, True, [],
    "/" + "a" * 201 + ".js",
])
def test_crypto_rejects_paths_outside_committed_schema(tool, path):
    with pytest.raises(ValueError, match="path"):
        build_command(tool, {"target": "sandbox.securegateway.com", "path": path},
                      "sandbox.securegateway.com", ALLOWED)


@pytest.mark.parametrize("path", ["/app", "/app.json", "/.js"])
def test_secret_scan_requires_nonempty_js_file_path(path):
    with pytest.raises(ValueError, match="path"):
        build_command("secret_scan", {"target": "sandbox.securegateway.com", "path": path},
                      "sandbox.securegateway.com", ALLOWED)


def test_secret_scan_requires_explicit_path():
    with pytest.raises(ValueError, match="path"):
        build_command("secret_scan", {"target": "sandbox.securegateway.com"},
                      "sandbox.securegateway.com", ALLOWED)
