"""Offline static checks only: never execute the VM bootstrap or any scanner."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "vm-bootstrap.sh"


def script_text() -> str:
    assert SCRIPT.is_file(), "the root-run VM bootstrap must exist"
    return SCRIPT.read_text(encoding="utf-8")


def test_bootstrap_fails_closed_and_never_pipes_downloads_to_a_shell():
    text = script_text()
    assert "set -euo pipefail" in text
    assert not re.search(r"\|\s*(?:sh|bash)\b", text)


def test_nuclei_archive_is_checked_before_installation():
    text = script_text()
    assert "NUCLEI_VERSION=${NUCLEI_VERSION:-3.3.10}" in text
    assert "checksums.txt" in text
    assert "sha256sum -c" in text
    assert text.index("sha256sum -c") < text.index("/usr/bin/nuclei")
    assert "-update-templates -ud /opt/viper/nuclei-templates -duc" in text


def test_service_and_templates_use_separate_privileges():
    text = script_text()
    unit = text.split("[Service]", 1)[1].split("[Install]", 1)[0]
    assert "User=viper-vmapi" in unit
    assert "User=root" not in unit
    assert "Group=viper-vmapi" in unit
    assert "WorkingDirectory=/opt/viper" in unit
    assert "KillMode=control-group" in unit
    assert "--shell /usr/sbin/nologin" in text
    assert "chown -R root:root /opt/viper/nuclei-templates" in text
    assert "chmod -R u=rwX,go=rX /opt/viper/nuclei-templates" in text


def test_credentials_are_not_printed_or_passed_in_curl_arguments():
    text = script_text()
    assert not re.search(r"(?im)^\s*(?:echo|printf)\b[^\n]*\$(?:\{)?(?:TOKEN|KEY)\b", text)
    assert not re.search(r"(?im)^\s*print\([^\n]*(?:token|private_key)", text)
    assert "set +x" in text
    assert "secrets.token_hex(32)" in text
    assert "0o640" in text
    assert "VIPER_EXEC_EGRESS_ALLOWLIST" in text
    assert "VIPER_EXEC_NUCLEI_TEMPLATES=/opt/viper/nuclei-templates" in text
    assert '--config "$work_dir/health.curl"' in text
    assert "--output /dev/null" in text


def test_bootstrap_shell_syntax_when_bash_is_available():
    script_text()
    bash = shutil.which("bash")
    if bash is None:
        git_bash = Path("C:/Program Files/Git/bin/bash.exe")
        if git_bash.is_file():
            bash = str(git_bash)
    if bash is None:
        pytest.skip("bash is not installed; syntax check unavailable")
    result = subprocess.run(  # noqa: S603 -- trusted shell, syntax check only; never runs the script
        [bash, "-n", SCRIPT.as_posix()], capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
