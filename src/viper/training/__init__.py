"""Training plane: QLoRA dataset building and adapter artifact handling (M4, gated).

See docs/plans/m4-qlora-gate.md. Heavy training runs on Colab (notebooks/qlora_finetune.ipynb);
this package holds the offline, deterministic parts: dataset building with a held-out-eval guard
(dataset.py) and adapter verify / Ollama Modelfile emission (artifact.py).
"""
