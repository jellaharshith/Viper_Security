"""spawn()'s env is a fixed minimal dict (PATH/LANG/HOME) with no passthrough at all, so
VIPER_EXEC_ALSCO_TEST_SESSION_FILE (session_headers()) and VIPER_EXEC_ALSCO_ACCEPT_EXPIRED_CERT
(build_client()) never actually reached a spawned probe - confirmed live on the VM: the env var
was set in /etc/viper/vmapi.env and visible to the vmapi service itself, but the probe subprocess
still saw CERTIFICATE_VERIFY_FAILED because spawn() never forwards it. Only these two exact,
named VIPER_EXEC_ALSCO_* variables may cross into the child; nothing else (especially not the
bearer token) is in this allowlist.
"""
# ruff: noqa: S101 -- pytest assertions

from __future__ import annotations

import sys

import pytest
from vmapi.toolrunner import spawn


def test_spawn_forwards_the_accept_expired_cert_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIPER_EXEC_ALSCO_ACCEPT_EXPIRED_CERT", "1")
    code = "import os,sys; sys.stdout.write(os.environ.get('VIPER_EXEC_ALSCO_ACCEPT_EXPIRED_CERT', ''))"
    proc = spawn([sys.executable, "-c", code])
    out = proc.stdout.read().decode()
    proc.wait(timeout=10)
    assert out == "1"


def test_spawn_forwards_the_test_session_file_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIPER_EXEC_ALSCO_TEST_SESSION_FILE", "/etc/viper/alsco-session.json")
    code = "import os,sys; sys.stdout.write(os.environ.get('VIPER_EXEC_ALSCO_TEST_SESSION_FILE', ''))"
    proc = spawn([sys.executable, "-c", code])
    out = proc.stdout.read().decode()
    proc.wait(timeout=10)
    assert out == "/etc/viper/alsco-session.json"


def test_spawn_never_forwards_unrelated_or_sensitive_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIPER_EXEC_API_TOKEN", "super-secret-token")
    monkeypatch.setenv("SOME_RANDOM_VAR", "x")
    proc = spawn([sys.executable, "-c",
                  "import os,sys; sys.stdout.write(repr(sorted(os.environ)))"])
    out = proc.stdout.read().decode()
    proc.wait(timeout=10)
    assert "VIPER_EXEC_API_TOKEN" not in out
    assert "SOME_RANDOM_VAR" not in out
    assert "PATH" in out and "LANG" in out and "HOME" in out
