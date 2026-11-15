import pytest

from viper.config import Settings
from viper.policy.engine import evaluate, in_scope, normalize_host
from viper.policy.models import Action, AssetTechniqueLimit, DecisionType, RiskLevel, Scope, ToolInfo

SCOPE = Scope(
    project_id="p1",
    in_scope=("example.com", "*.example.org", "10.0.0.0/24", "bücher.example"),
    exclusions=("admin.example.org", "10.0.0.5"),
)


def act(tool: str = "t", **args: object) -> Action:
    return Action(action_id="a1", tool_name=tool, args=dict(args))


def tool(risk: RiskLevel, dry: bool = True, name: str = "t",
         techniques: frozenset[str] = frozenset()) -> ToolInfo:
    return ToolInfo(name=name, risk=risk, dry_run_only=dry, techniques=techniques)


S = Settings(_env_file=None)


def kind(a: Action, t: ToolInfo | None, scope: Scope | None = SCOPE, s: Settings = S) -> DecisionType:
    return evaluate(a, t, scope, s).type


def test_read_allowed_without_scope():
    assert kind(act(), tool(RiskLevel.READ), None) == DecisionType.ALLOW


def test_unknown_or_mismatched_tool_denied():
    assert kind(act(), None) == DecisionType.DENY
    assert kind(act("other"), tool(RiskLevel.READ)) == DecisionType.DENY


def test_intrusive_always_denied_even_when_active_testing_on():
    on = Settings(_env_file=None, allow_active_testing=True)
    t = tool(RiskLevel.INTRUSIVE, dry=False)
    assert kind(act(target="example.com"), t, SCOPE, on) == DecisionType.DENY


def test_passive_requires_in_scope_target():
    t = tool(RiskLevel.PASSIVE)
    assert kind(act(target="example.com"), t) == DecisionType.ALLOW
    assert kind(act(target="evil.com"), t) == DecisionType.DENY
    assert kind(act(), t) == DecisionType.DENY
    assert kind(act(target=5), t) == DecisionType.DENY
    assert kind(act(target="example.com"), t, None) == DecisionType.DENY


def test_active_real_tool_denied_while_switch_off_and_needs_approval_when_on():
    real = tool(RiskLevel.ACTIVE, dry=False)
    a = act(target="example.com")
    assert kind(a, real) == DecisionType.DENY
    on = Settings(_env_file=None, allow_active_testing=True)
    assert kind(a, real, SCOPE, on) == DecisionType.REQUIRE_APPROVAL


def test_active_dry_run_stub_reaches_approval_even_with_switch_off():
    assert kind(act(target="example.com"), tool(RiskLevel.ACTIVE, dry=True)) == DecisionType.REQUIRE_APPROVAL


@pytest.mark.parametrize("target,expected", [
    ("example.com", True), ("EXAMPLE.COM.", True), ("www.example.com", False),
    ("a.example.org", True), ("example.org", False),  # wildcard excludes the apex
    ("admin.example.org", False),  # exclusion wins
    ("10.0.0.7", True), ("10.0.0.5", False), ("10.0.1.1", False),
    ("xn--bcher-kva.example", True), ("bücher.example", True),
    ("example.com/path", False), ("user@example.com", False), ("", False),
    ("exаmple.com", False),  # Cyrillic 'а' homoglyph is a different host
])
def test_scope_matching(target, expected):
    assert in_scope(target, SCOPE) is expected


def test_model_cannot_smuggle_risk_or_permissions():
    with pytest.raises(ValueError):
        Action(action_id="a", tool_name="t", args={}, risk="READ")  # type: ignore[call-arg]


def test_scope_revision_changes_with_scope():
    other = SCOPE.model_copy(update={"in_scope": ("example.com",)})
    assert SCOPE.revision != other.revision
    assert SCOPE.revision == SCOPE.model_copy().revision


def test_evaluation_error_denies():
    class Boom(dict):  # type: ignore[type-arg]
        def get(self, *_a: object) -> object:
            raise RuntimeError("boom")

    a = Action.model_construct(action_id="a", tool_name="t", args=Boom())
    assert kind(a, tool(RiskLevel.PASSIVE)) == DecisionType.DENY


def test_normalize_host_rejects_garbage():
    assert normalize_host("a b") is None
    assert normalize_host("Example.COM.") == "example.com"


def _scope_with_limit(*limits: AssetTechniqueLimit) -> Scope:
    return SCOPE.model_copy(update={"asset_technique_limits": limits})


def test_asset_technique_limit_narrows_permitted_techniques_for_that_host_only():
    scope = _scope_with_limit(
        AssetTechniqueLimit(host="example.com", permitted_techniques=("web-scan",))
    )
    web = tool(RiskLevel.ACTIVE, dry=True, techniques=frozenset({"web-scan"}))
    injection = tool(RiskLevel.ACTIVE, dry=True, name="i", techniques=frozenset({"injection-test"}))
    on = Settings(_env_file=None, allow_active_testing=True)
    # Narrowed to web-scan only on example.com: web-scan allowed, injection-test denied.
    assert kind(act(target="example.com"), web, scope, on) == DecisionType.REQUIRE_APPROVAL
    assert kind(act("i", target="example.com"), injection, scope, on) == DecisionType.DENY
    # A different in-scope host has no override, so it keeps the unrestricted (global) behaviour.
    assert kind(act("i", target="a.example.org"), injection, scope, on) == DecisionType.REQUIRE_APPROVAL


def test_asset_technique_limit_forbidden_is_additive_to_global():
    scope = _scope_with_limit(
        AssetTechniqueLimit(host="example.com", forbidden_techniques=("web-scan",))
    )
    web = tool(RiskLevel.ACTIVE, dry=True, techniques=frozenset({"web-scan"}))
    on = Settings(_env_file=None, allow_active_testing=True)
    assert kind(act(target="example.com"), web, scope, on) == DecisionType.DENY
    # Not forbidden anywhere else.
    assert kind(act(target="a.example.org"), web, scope, on) == DecisionType.REQUIRE_APPROVAL


def test_asset_technique_limit_for_a_different_host_has_no_effect():
    scope = _scope_with_limit(
        AssetTechniqueLimit(host="a.example.org", permitted_techniques=("web-scan",))
    )
    injection = tool(RiskLevel.ACTIVE, dry=True, techniques=frozenset({"injection-test"}))
    on = Settings(_env_file=None, allow_active_testing=True)
    assert kind(act(target="example.com"), injection, scope, on) == DecisionType.REQUIRE_APPROVAL


def test_empty_asset_override_is_a_noop():
    scope = _scope_with_limit(AssetTechniqueLimit(host="example.com"))
    injection = tool(RiskLevel.ACTIVE, dry=True, techniques=frozenset({"injection-test"}))
    on = Settings(_env_file=None, allow_active_testing=True)
    assert kind(act(target="example.com"), injection, scope, on) == DecisionType.REQUIRE_APPROVAL


def test_otp_bypass_and_brute_force_are_distinct_technique_slugs():
    otp = tool(RiskLevel.ACTIVE, dry=True, techniques=frozenset({"otp-bypass"}))
    brute = tool(RiskLevel.ACTIVE, dry=True, name="b", techniques=frozenset({"brute-force"}))
    on = Settings(_env_file=None, allow_active_testing=True)
    forbid_brute_force = SCOPE.model_copy(update={"forbidden_techniques": ("brute-force",)})
    # Forbidding brute-force does not catch the distinct otp-bypass slug.
    assert kind(act(target="example.com"), otp, forbid_brute_force, on) == DecisionType.REQUIRE_APPROVAL
    forbid_otp = SCOPE.model_copy(update={"forbidden_techniques": ("otp-bypass",)})
    # And forbidding otp-bypass does not catch plain brute-force.
    assert kind(act("b", target="example.com"), brute, forbid_otp, on) == DecisionType.REQUIRE_APPROVAL


def test_old_scope_without_asset_technique_limits_still_loads_and_evaluates():
    old = Scope(project_id="p2", in_scope=("example.com",))
    assert old.asset_technique_limits == ()
    t = tool(RiskLevel.PASSIVE)
    assert kind(act(target="example.com"), t, old) == DecisionType.ALLOW
