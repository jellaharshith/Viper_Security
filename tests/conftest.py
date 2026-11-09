"""Suite-wide isolation: tests must never write reports into the real data/ directory."""

import pytest


@pytest.fixture(autouse=True)
def _isolated_report_dir(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("VIPER_REPORT_DIR", str(tmp_path_factory.mktemp("reports")))


@pytest.fixture(autouse=True)
def _isolated_from_the_developers_dotenv(monkeypatch):
    """A developer's real .env (live VM URL/token, active testing on) must never change test behaviour.

    Environment variables outrank the .env file in Settings, so pin the execution-plane switches to their safe
    defaults. Tests that need other values set them explicitly with monkeypatch.setenv afterwards.
    """
    monkeypatch.setenv("VIPER_ALLOW_ACTIVE_TESTING", "false")
    monkeypatch.setenv("VIPER_EXEC_API_URL", "")
    monkeypatch.setenv("VIPER_EXEC_API_TOKEN", "")
    monkeypatch.setenv("VIPER_EXEC_EGRESS_ALLOWLIST", "")
