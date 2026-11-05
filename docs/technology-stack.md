# Technology Stack

Status: **Chosen** = used now; **Planned** = per milestone; **Verify** = must be checked before use.

| Area | Choice | Status | Notes |
|---|---|---|---|
| Language | Python 3.12 | Chosen | Installed |
| Config | pydantic-settings | Chosen | Typed, `.env`, secrets as `SecretStr` |
| Logging | stdlib JSON formatter | Chosen | No extra dependency |
| Quality | pytest, ruff, mypy | Chosen | Run via `tasks.ps1 check` |
| Inference | Ollama + GGUF (CPU) | Planned M1 | Ollama already installed |
| Chat model | Foundation-Sec-1.1-8B-Instruct, Q4_K_M GGUF (4.92 GB, official `fdtn-ai` build) | **Chosen (M1), verified 2026-11-04** | Llama 3.1 Community License + Cisco Apache-2.0 changes (per NOTICE.md). Baseline vs alternatives in M2 |
| Embedded vector DB | Qdrant local mode (`qdrant-client`) | Chosen (M1) | No Docker |
| Embeddings | `nomic-embed-text` via Ollama (274 MB, 768-dim) | Chosen (M1) | CPU-friendly; no extra ML dependency |
| HTTP | httpx | Chosen (M1) | Ollama client + CISA fetch |
| Agents | LangGraph | Planned M5 | |
| API | FastAPI | Planned M5/M6 | Authenticated, TLS |
| DB | PostgreSQL | Planned M5/M6 | Not needed before |
| Training | Colab, PEFT, TRL, bitsandbytes | Planned M4 | Checkpoints to Google Drive |
| Export | llama.cpp (merge -> GGUF -> quantize) | Planned M4 | Required to run in Ollama |
| Scheduler | GitHub Actions | Planned M3 | Pushes to a persistent Qdrant |
| Tools (VM) | Nmap, ZAP, Nuclei; Burp manual | Planned M6 | Verify each license/AUP |
| Remote GUI | Guacamole or noVNC | Planned M6 | Never public without strong auth |

## Cost
M0-M3 are $0. M4 is Colab free (ephemeral) or Pro (~$10/mo, verify current price). M6 is on-demand only. Keep total under ~$50/mo.

## Licensing watch-list
Model (likely Llama-derived terms: verify), Nmap (custom license), data sources (NVD, CISA KEV, MITRE ATT&CK, OWASP: check terms before any redistribution). Personal use is lower risk than open-source/SaaS release.
