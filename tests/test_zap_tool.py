import pytest
from pydantic import ValidationError

from viper.policy.models import RiskLevel
from viper.tools.real import ZapBaselineArgs, zap_baseline
from viper.tools.registry import default_registry


def test_zap_registered_as_active_real_tool() -> None:
    info = default_registry.get_info("zap_baseline")
    assert info.risk is RiskLevel.ACTIVE
    assert info.dry_run_only is False
    assert info.techniques == frozenset({"web-scan", "passive-scan", "spider"})
    assert zap_baseline.name == "zap_baseline"


def test_zap_args_schema_rejects_extras_and_bounds_duration() -> None:
    ok = ZapBaselineArgs(target="example.com")
    assert ok.max_duration_minutes == 5  # default
    ZapBaselineArgs(target="example.com", max_duration_minutes=15)
    with pytest.raises(ValidationError):
        ZapBaselineArgs(target="example.com", max_duration_minutes=0)
    with pytest.raises(ValidationError):
        ZapBaselineArgs(target="example.com", max_duration_minutes=99)
    with pytest.raises(ValidationError):
        ZapBaselineArgs(target="example.com", active_attack=True)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        ZapBaselineArgs()  # type: ignore[call-arg]  # target required
