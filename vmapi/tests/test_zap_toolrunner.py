# ruff: noqa: S101 -- pytest assertions
import json
import sys

import pytest
from vmapi.toolrunner import TOOLS, build_command

ALLOWED = frozenset({"x.test"})


def test_zap_in_tools() -> None:
    assert "zap_baseline" in TOOLS


def test_zap_build_command_routes_to_probe_script() -> None:
    cmd = build_command("zap_baseline", {"target": "x.test", "max_duration_minutes": 5},
                        "x.test", ALLOWED)
    assert cmd[0] == sys.executable
    assert cmd[1].endswith("/zap_baseline.py") and cmd[2] == "--args-json"
    payload = json.loads(cmd[3])
    assert payload == {"target": "x.test", "max_duration_minutes": 5}


def test_zap_defaults_duration_when_absent() -> None:
    cmd = build_command("zap_baseline", {"target": "x.test"}, "x.test", ALLOWED)
    assert json.loads(cmd[3])["max_duration_minutes"] == 5


@pytest.mark.parametrize("bad", [0, 16, 99, "5", 5.0, True])
def test_zap_rejects_bad_duration(bad: object) -> None:
    with pytest.raises(ValueError):
        build_command("zap_baseline", {"target": "x.test", "max_duration_minutes": bad},
                      "x.test", ALLOWED)


def test_zap_rejects_extra_args_and_target_mismatch() -> None:
    with pytest.raises(ValueError):
        build_command("zap_baseline", {"target": "x.test", "active_attack": True}, "x.test", ALLOWED)
    with pytest.raises(ValueError):
        build_command("zap_baseline", {"target": "x.test"}, "other.test", ALLOWED)
