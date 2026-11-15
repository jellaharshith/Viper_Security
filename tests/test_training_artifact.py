import json
from pathlib import Path

import pytest

from viper.training.artifact import AdapterError, render_modelfile, verify_adapter


def _adapter(tmp_path: Path, base: str = "foundation-sec:8b") -> Path:
    d = tmp_path / "adapter"
    d.mkdir()
    (d / "adapter_config.json").write_text(json.dumps({"base_model_name_or_path": base}),
                                           encoding="utf-8")
    (d / "adapter_model.safetensors").write_bytes(b"\x00\x01")
    return d


def test_verify_adapter_reads_base_and_checks_files(tmp_path: Path) -> None:
    manifest = verify_adapter(_adapter(tmp_path))
    assert manifest.base_model == "foundation-sec:8b"
    assert manifest.has_weights is True


def test_verify_adapter_rejects_incomplete_dir(tmp_path: Path) -> None:
    d = tmp_path / "bad"
    d.mkdir()
    with pytest.raises(AdapterError):
        verify_adapter(d)  # no adapter_config.json


def test_render_modelfile_emits_from_and_params() -> None:
    text = render_modelfile(gguf_path="/models/cand.gguf", base_label="viper-sec-cand",
                            temperature=0.2, num_ctx=8192)
    assert text.splitlines()[0] == "FROM /models/cand.gguf"
    assert "PARAMETER temperature 0.2" in text
    assert "PARAMETER num_ctx 8192" in text
