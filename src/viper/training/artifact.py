"""QLoRA artifact handling: verify a trained adapter and emit an Ollama Modelfile for the candidate.

The heavy steps (loading the base model, merging the adapter, exporting GGUF) run on Colab with a
GPU; this module holds the deterministic, offline parts that gate and package that output:
``verify_adapter`` checks a downloaded adapter directory is well-formed and reports its base model,
and ``render_modelfile`` produces the Ollama ``Modelfile`` that makes a merged GGUF swappable behind
``viper.llm.client`` for evaluation against the frozen baseline (M4 gate).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_CONFIG = "adapter_config.json"
_WEIGHTS = ("adapter_model.safetensors", "adapter_model.bin")


class AdapterError(RuntimeError):
    """The adapter directory is missing required files or is malformed."""


@dataclass(frozen=True)
class AdapterManifest:
    path: Path
    base_model: str
    has_weights: bool


def verify_adapter(adapter_dir: Path) -> AdapterManifest:
    """Validate a QLoRA adapter directory and return its manifest (base model + weights present)."""
    adapter_dir = Path(adapter_dir)
    config_path = adapter_dir / _CONFIG
    if not config_path.is_file():
        raise AdapterError(f"missing {_CONFIG} in {adapter_dir}")
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise AdapterError(f"{_CONFIG} is not valid JSON: {exc}") from exc
    if not isinstance(config, dict):
        raise AdapterError(f"{_CONFIG} must be a JSON object")
    base = str(config.get("base_model_name_or_path", "")).strip()
    if not base:
        raise AdapterError("adapter_config.json has no base_model_name_or_path")
    has_weights = any((adapter_dir / name).is_file() for name in _WEIGHTS)
    if not has_weights:
        raise AdapterError(f"no adapter weights ({' or '.join(_WEIGHTS)}) in {adapter_dir}")
    return AdapterManifest(path=adapter_dir, base_model=base, has_weights=has_weights)


def render_modelfile(
    *, gguf_path: str, base_label: str, temperature: float = 0.2, num_ctx: int = 8192,
    system: str = "",
) -> str:
    """Render an Ollama Modelfile for a merged GGUF candidate (for eval via viper.llm.client)."""
    _ = base_label  # recorded by the caller when it runs `ollama create <base_label> -f Modelfile`
    lines = [f"FROM {gguf_path}",
             f"PARAMETER temperature {temperature}",
             f"PARAMETER num_ctx {num_ctx}"]
    if system.strip():
        escaped = system.replace('"', '\\"')
        lines.append(f'SYSTEM "{escaped}"')
    return "\n".join(lines) + "\n"
