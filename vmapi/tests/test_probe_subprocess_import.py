"""Reproduces a real VM failure: toolrunner.spawn() runs each probe as a subprocess with a
scrubbed env (no PYTHONPATH) and cwd="/", exactly like nmap/nuclei. in-process imports in
test_probes.py never exercise that path, so `from vmapi.probes._common import ...` resolving
fine inside pytest hid the fact that the script 500s with ModuleNotFoundError on the real VM."""
# ruff: noqa: S101 -- pytest assertions

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PROBES_DIR = Path(__file__).resolve().parents[1] / "probes"
MINIMAL_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/root"}


@pytest.mark.parametrize(
    "script",
    ["otp_2fa_probe.py", "upload_bypass_probe.py", "injection_probe.py", "zap_baseline.py"],
)
def test_probe_script_imports_without_the_vmapi_package_on_path(script: str) -> None:
    result = subprocess.run(  # noqa: S603 -- fixed interpreter + local script, no shell
        [sys.executable, str(PROBES_DIR / script), "--args-json", "{}"],
        capture_output=True, text=True, timeout=15, env=MINIMAL_ENV, cwd="/",
    )
    assert "ModuleNotFoundError" not in result.stderr, result.stderr
