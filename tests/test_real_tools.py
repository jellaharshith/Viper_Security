"""M6 real tools (nmap/nuclei): ACTIVE, denied unless armed, approval-gated, strict schemas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from viper.config import Settings
from viper.policy.engine import evaluate
from viper.policy.models import Action, DecisionType, RiskLevel, Scope
from viper.tools.real import NmapArgs, NucleiArgs
from viper.tools.registry import default_registry

SCOPE = Scope.model_validate({"project_id": "lab", "in_scope": ["scanme.nmap.org"], "exclusions": []})


def _nmap(target: str = "scanme.nmap.org") -> Action:
    return Action(action_id="a1", tool_name="nmap", args={"target": target, "ports": "22,80"})


def test_nmap_and_nuclei_are_registered_active_and_real() -> None:
    for name in ("nmap", "nuclei"):
        info = default_registry.get_info(name)
        assert info is not None
        assert info.risk is RiskLevel.ACTIVE
        assert info.dry_run_only is False  # real execution is possible once armed + approved


def test_nmap_denied_when_active_testing_is_off() -> None:
    d = evaluate(_nmap(), default_registry.get_info("nmap"), SCOPE, Settings(allow_active_testing=False))
    assert d.type is DecisionType.DENY


def test_nmap_requires_approval_when_armed() -> None:
    d = evaluate(_nmap(), default_registry.get_info("nmap"), SCOPE, Settings(allow_active_testing=True))
    assert d.type is DecisionType.REQUIRE_APPROVAL


def test_out_of_scope_target_denied_even_when_armed() -> None:
    a = Action(action_id="a1", tool_name="nmap", args={"target": "example.com"})
    d = evaluate(a, default_registry.get_info("nmap"), SCOPE, Settings(allow_active_testing=True))
    assert d.type is DecisionType.DENY


def test_nmap_schema_rejects_raw_or_unknown_args() -> None:
    with pytest.raises(ValidationError):
        NmapArgs(target="scanme.nmap.org", raw="-oN /etc/passwd")  # type: ignore[call-arg]


def test_nuclei_rate_limit_is_bounded() -> None:
    NucleiArgs(target="scanme.nmap.org", rate_limit=10)  # ok
    with pytest.raises(ValidationError):
        NucleiArgs(target="scanme.nmap.org", rate_limit=99)
