import importlib
import json

import pytest

from viper.cli import main

PLANES = ["llm", "training", "rag", "agents", "policy", "tools", "execution"]


@pytest.mark.parametrize("name", PLANES)
def test_boundary_modules_import(name: str) -> None:
    importlib.import_module(f"viper.{name}")


def test_cli_health_ok(capsys) -> None:
    assert main(["--health"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "OK"
