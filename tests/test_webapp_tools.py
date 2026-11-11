"""v1.2 web-app probe tools (OTP/2FA, upload-bypass, injection): ACTIVE, denied unless armed,
approval-gated, strict schemas, fixed (never model-supplied) payload selection.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from viper.config import Settings
from viper.policy.engine import evaluate
from viper.policy.models import Action, DecisionType, RiskLevel, Scope
from viper.tools.registry import default_registry
from viper.tools.webapp import (
    GraphqlIntrospectArgs,
    InjectionProbeArgs,
    Otp2faProbeArgs,
    SecretScanArgs,
    UploadBypassProbeArgs,
)

SCOPE = Scope.model_validate({
    "project_id": "alsco-h1",
    "in_scope": [
        "sandbox.securegateway.com", "sandbox-royal.securegateway.com",
        "sandbox-crypto.securegateway.com",
    ],
    "asset_technique_limits": [
        {"host": "sandbox.securegateway.com", "permitted_techniques": ["otp-bypass", "upload-bypass"]},
        {"host": "sandbox-royal.securegateway.com", "permitted_techniques": ["injection-test"]},
    ],
})

ON = Settings(allow_active_testing=True)
OFF = Settings(allow_active_testing=False)

TOOLS = ("otp_2fa_probe", "upload_bypass_probe", "injection_probe")


def _act(tool: str, **args: object) -> Action:
    return Action(action_id="a1", tool_name=tool, args=dict(args))


@pytest.mark.parametrize("name", TOOLS)
def test_webapp_tools_are_registered_active_and_real(name: str) -> None:
    info = default_registry.get_info(name)
    assert info is not None
    assert info.risk is RiskLevel.ACTIVE
    assert info.dry_run_only is False


@pytest.mark.parametrize("name", TOOLS)
def test_webapp_tools_denied_when_active_testing_is_off(name: str) -> None:
    a = _act(name, target="sandbox.securegateway.com", endpoint_path="/x")
    d = evaluate(a, default_registry.get_info(name), SCOPE, OFF)
    assert d.type is DecisionType.DENY


def test_otp_probe_requires_approval_on_its_own_asset() -> None:
    a = Action(action_id="a1", tool_name="otp_2fa_probe", args={
        "target": "sandbox.securegateway.com", "endpoint_path": "/api/2fa/verify",
        "mode": "rate_limit_probe", "max_attempts": 5,
    })
    d = evaluate(a, default_registry.get_info("otp_2fa_probe"), SCOPE, ON)
    assert d.type is DecisionType.REQUIRE_APPROVAL


def test_otp_probe_denied_on_the_other_asset_which_does_not_permit_otp_bypass() -> None:
    a = Action(action_id="a1", tool_name="otp_2fa_probe", args={
        "target": "sandbox-royal.securegateway.com", "endpoint_path": "/api/2fa/verify",
        "mode": "rate_limit_probe", "max_attempts": 5,
    })
    d = evaluate(a, default_registry.get_info("otp_2fa_probe"), SCOPE, ON)
    assert d.type is DecisionType.DENY


def test_injection_probe_requires_approval_on_royal_cms_only() -> None:
    royal = Action(action_id="a1", tool_name="injection_probe", args={
        "target": "sandbox-royal.securegateway.com", "endpoint_path": "/login",
        "param_name": "username", "technique": "sqli_boolean",
    })
    gateway = Action(action_id="a2", tool_name="injection_probe", args={
        "target": "sandbox.securegateway.com", "endpoint_path": "/login",
        "param_name": "username", "technique": "sqli_boolean",
    })
    info = default_registry.get_info("injection_probe")
    assert evaluate(royal, info, SCOPE, ON).type is DecisionType.REQUIRE_APPROVAL
    assert evaluate(gateway, info, SCOPE, ON).type is DecisionType.DENY


def test_out_of_scope_target_denied_even_when_armed() -> None:
    a = _act("injection_probe", target="evil.com", endpoint_path="/x", param_name="p",
             technique="xss_reflected_marker")
    d = evaluate(a, default_registry.get_info("injection_probe"), SCOPE, ON)
    assert d.type is DecisionType.DENY


def test_a_scope_that_forbids_brute_force_does_not_block_the_otp_tool() -> None:
    scope = SCOPE.model_copy(update={"forbidden_techniques": ("brute-force",)})
    a = Action(action_id="a1", tool_name="otp_2fa_probe", args={
        "target": "sandbox.securegateway.com", "endpoint_path": "/x",
        "mode": "rate_limit_probe", "max_attempts": 5,
    })
    d = evaluate(a, default_registry.get_info("otp_2fa_probe"), scope, ON)
    assert d.type is DecisionType.REQUIRE_APPROVAL


# --- schema strictness: no raw payloads, no unbounded attempts, no free-text technique selection ---

def test_otp_args_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Otp2faProbeArgs(target="t", endpoint_path="/x", mode="rate_limit_probe", max_attempts=5,
                        password="not-a-real-secret")  # type: ignore[call-arg] # noqa: S106


def test_otp_args_has_no_password_or_username_field() -> None:
    fields = Otp2faProbeArgs.model_fields
    assert "password" not in fields
    assert "username" not in fields
    assert "code" not in fields  # the attempted OTP code is never model-supplied


@pytest.mark.parametrize("max_attempts", [0, -1, 51, "5", True, 5.0])
def test_otp_max_attempts_is_bounded_and_strict(max_attempts: object) -> None:
    with pytest.raises(ValidationError):
        Otp2faProbeArgs(target="t", endpoint_path="/x", mode="rate_limit_probe", max_attempts=max_attempts)


def test_otp_mode_rejects_arbitrary_strings() -> None:
    with pytest.raises(ValidationError):
        Otp2faProbeArgs(target="t", endpoint_path="/x", mode="anything_goes", max_attempts=5)


def test_upload_variant_rejects_arbitrary_strings() -> None:
    with pytest.raises(ValidationError):
        UploadBypassProbeArgs(target="t", endpoint_path="/x", variant="upload_a_webshell")


def test_upload_args_has_no_file_content_field() -> None:
    fields = UploadBypassProbeArgs.model_fields
    assert "content" not in fields
    assert "file_bytes" not in fields
    assert "payload" not in fields


def test_injection_technique_rejects_arbitrary_strings() -> None:
    with pytest.raises(ValidationError):
        InjectionProbeArgs(target="t", endpoint_path="/x", param_name="p", technique="drop_tables")


def test_injection_args_has_no_raw_payload_field() -> None:
    fields = InjectionProbeArgs.model_fields
    assert "payload" not in fields
    assert "command" not in fields


@pytest.mark.parametrize("param_name", ["", "a" * 65, "bad name", "bad;name"])
def test_injection_param_name_is_bounded(param_name: str) -> None:
    with pytest.raises(ValidationError):
        InjectionProbeArgs(target="t", endpoint_path="/x", param_name=param_name,
                           technique="xss_reflected_marker")


# --- secret_scan: PASSIVE, no approval required, fixed server-side detection patterns only ---

def test_secret_scan_is_registered_passive_and_real() -> None:
    info = default_registry.get_info("secret_scan")
    assert info is not None
    assert info.risk is RiskLevel.PASSIVE
    assert info.dry_run_only is False


def test_secret_scan_allowed_on_in_scope_target_without_approval() -> None:
    a = Action(action_id="a1", tool_name="secret_scan",
               args={"target": "sandbox-crypto.securegateway.com", "path": "/static/app.js"})
    d = evaluate(a, default_registry.get_info("secret_scan"), SCOPE, OFF)
    assert d.type is DecisionType.ALLOW


def test_secret_scan_denied_out_of_scope() -> None:
    a = Action(action_id="a1", tool_name="secret_scan", args={"target": "evil.com", "path": "/app.js"})
    d = evaluate(a, default_registry.get_info("secret_scan"), SCOPE, OFF)
    assert d.type is DecisionType.DENY


def test_secret_scan_args_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        SecretScanArgs(target="t", path="/app.js", regex="x")  # type: ignore[call-arg]


def test_secret_scan_args_has_no_regex_or_content_field() -> None:
    fields = SecretScanArgs.model_fields
    assert "regex" not in fields
    assert "content" not in fields
    assert "pattern" not in fields


@pytest.mark.parametrize("path", [
    "app.js",            # missing leading slash
    "/app.css",          # not .js
    "/app.js.php",       # doesn't end in .js
    "/%2e%2e/x.js",      # encoded traversal: '%' is outside the allowed character class
    "/a b.js",            # space is outside the allowed character class
    "",
])
def test_secret_scan_path_must_be_an_exact_js_file(path: str) -> None:
    with pytest.raises(ValidationError):
        SecretScanArgs(target="t", path=path)


def test_secret_scan_path_accepts_a_well_formed_js_path() -> None:
    args = SecretScanArgs(target="t", path="/static/app.bundle.js")
    assert args.path == "/static/app.bundle.js"


# --- graphql_introspect: ACTIVE, single-shot, fixed introspection query only ---

def test_graphql_introspect_is_registered_active_and_real() -> None:
    info = default_registry.get_info("graphql_introspect")
    assert info is not None
    assert info.risk is RiskLevel.ACTIVE
    assert info.dry_run_only is False


def test_graphql_introspect_denied_when_active_testing_is_off() -> None:
    a = Action(action_id="a1", tool_name="graphql_introspect",
               args={"target": "sandbox-crypto.securegateway.com", "path": "/graphql"})
    d = evaluate(a, default_registry.get_info("graphql_introspect"), SCOPE, OFF)
    assert d.type is DecisionType.DENY


def test_graphql_introspect_requires_approval_when_armed() -> None:
    a = Action(action_id="a1", tool_name="graphql_introspect",
               args={"target": "sandbox-crypto.securegateway.com", "path": "/graphql"})
    d = evaluate(a, default_registry.get_info("graphql_introspect"), SCOPE, ON)
    assert d.type is DecisionType.REQUIRE_APPROVAL


def test_graphql_introspect_args_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        GraphqlIntrospectArgs(target="t", path="/graphql", query="{ me }")  # type: ignore[call-arg]


def test_graphql_introspect_args_has_no_query_field() -> None:
    fields = GraphqlIntrospectArgs.model_fields
    assert "query" not in fields


def test_graphql_introspect_path_defaults_to_graphql() -> None:
    args = GraphqlIntrospectArgs(target="t")
    assert args.path == "/graphql"


@pytest.mark.parametrize("path", ["graphql", "/gra phql", "/gra;phql", ""])
def test_graphql_introspect_path_rejects_bad_values(path: str) -> None:
    with pytest.raises(ValidationError):
        GraphqlIntrospectArgs(target="t", path=path)
