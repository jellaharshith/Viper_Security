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


@pytest.mark.parametrize("ports", ["22", "22,80,443", ",".join(str(p) for p in range(1, 33))])
def test_nmap_accepts_the_same_ports_the_vm_accepts(ports) -> None:
    assert NmapArgs(target="scanme.nmap.org", ports=ports).ports == ports


@pytest.mark.parametrize("ports", [
    "", " ", "1-1000", "80;id", "0", "65536", "22,", ",22", "22,,80", "22, 80", "-p22", "22\n80",
    ",".join(str(p) for p in range(1, 34)),  # 33 ports: over the VM cap
])
def test_nmap_rejects_ports_the_vm_would_reject(ports) -> None:
    with pytest.raises(ValidationError):
        NmapArgs(target="scanme.nmap.org", ports=ports)


def test_every_nmap_field_carries_a_format_hint_for_the_planner() -> None:
    props = NmapArgs.model_json_schema()["properties"]
    assert "range" in props["ports"]["description"].lower()
    assert "allowed_hosts" in props["target"]["description"]


def test_nuclei_default_rate_limit_is_within_the_vm_bounds() -> None:
    assert 1 <= NucleiArgs(target="scanme.nmap.org").rate_limit <= 10


# --- v1 review #9: validation must reject exactly what the VM rejects (the ORIGINAL args are dispatched) ---

@pytest.mark.parametrize("kwargs", [
    {"service_detection": "true"}, {"service_detection": 1}, {"skip_discovery": "yes"},
    {"skip_discovery": 0},
])
def test_nmap_booleans_are_strict(kwargs) -> None:
    with pytest.raises(ValidationError):
        NmapArgs(target="scanme.nmap.org", **kwargs)


def test_an_explicit_null_ports_is_rejected_but_omitting_it_is_fine() -> None:
    assert NmapArgs(target="scanme.nmap.org").ports is None
    with pytest.raises(ValidationError):
        NmapArgs(target="scanme.nmap.org", ports=None)
    with pytest.raises(ValidationError):
        NmapArgs.model_validate({"target": "scanme.nmap.org", "ports": None})


@pytest.mark.parametrize("rate", ["5", True, 5.0, 5.5])
def test_nuclei_rate_limit_is_a_strict_int(rate) -> None:
    with pytest.raises(ValidationError):
        NucleiArgs(target="scanme.nmap.org", rate_limit=rate)
