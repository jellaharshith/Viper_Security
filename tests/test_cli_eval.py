import json

import pytest

from viper import cli
from viper.config import Settings
from viper.eval import runner


@pytest.mark.parametrize(
    ("dataset_args", "expected"),
    [([], "v1"), (["--dataset", "v1"], "v1"), (["--dataset", "v2"], "v2")],
)
def test_eval_run_selects_dataset_and_saves_report(monkeypatch, tmp_path, dataset_args, expected):
    """Catch an ignored selection or a changed default at the CLI/runner boundary."""
    settings = Settings(_env_file=None)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)

    # Avoid live Ollama/KB calls; retain the real parser, command and report writer.
    def offline_eval(received_settings, tag, skip_llm=False, only=None, dataset_version="v1"):
        assert received_settings is settings
        assert skip_llm is True
        assert only == {"def-3", "definition"}
        return {
            "meta": {
                "tag": tag, "created": "2026-11-07T00:00:00+00:00",
                "dataset_version": dataset_version,
            },
            "retrieval": {"overall": {}, "calibration": {}},
        }

    monkeypatch.setattr(runner, "run_eval", offline_eval)
    monkeypatch.chdir(tmp_path)
    assert cli.main([
        "eval", "run", "--tag", "dataset-test", "--skip-llm",
        "--only", "def-3,definition", *dataset_args,
    ]) == 0
    report = json.loads(
        (tmp_path / "eval/results/dataset-test-2026-11-07.json").read_text(encoding="utf-8")
    )
    assert report["meta"]["dataset_version"] == expected


def test_eval_run_rejects_unknown_dataset_before_evaluation(monkeypatch, capsys):
    def unexpected_settings():
        pytest.fail("invalid dataset must be rejected before settings or services are loaded")

    monkeypatch.setattr(cli, "get_settings", unexpected_settings)
    with pytest.raises(SystemExit) as exc:
        cli.main(["eval", "run", "--tag", "invalid", "--dataset", "v3"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
