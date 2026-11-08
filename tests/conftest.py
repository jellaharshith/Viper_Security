"""Suite-wide isolation: tests must never write reports into the real data/ directory."""

import pytest


@pytest.fixture(autouse=True)
def _isolated_report_dir(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("VIPER_REPORT_DIR", str(tmp_path_factory.mktemp("reports")))
