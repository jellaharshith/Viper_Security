import pytest

from viper.config import Settings
from viper.policy.engine import evaluate, in_scope, normalize_host
from viper.policy.models import Action, DecisionType, RiskLevel, Scope, ToolInfo

SCOPE = Scope(
    project_id="p1",
    in_scope=("example.com", "*.example.org", "10.0.0.0/24", "bücher.example"),
    exclusions=("admin.example.org", "10.0.0.5"),
)


def act(tool: str = "t", **args: object) -> Action:
    return Action(action_id="a1", tool_name=tool, args=dict(args))


def tool(risk: RiskLevel, dry: bool = True, name: str = "t") -> ToolInfo:
    return ToolInfo(name=name, risk=risk, dry_run_only=dry)


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
