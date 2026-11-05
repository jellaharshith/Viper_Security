# Technology Stack

Status: **Chosen** = used now; **Planned** = per milestone; **Verify** = must be checked before use.

| Area | Choice | Status | Notes |
|---|---|---|---|
| Language | Python 3.12 | Chosen | Installed |
| Config | pydantic-settings | Chosen | Typed, `.env`, secrets as `SecretStr` |
| Logging | stdlib JSON formatter | Chosen | No extra dependency |
| Quality | pytest, ruff, mypy | Chosen | Run via `tasks.ps1 check` |
| Inference | Ollama + GGUF (CPU) | Planned M1 | Ollama already installed |
| Base model | Cisco Foundation-Sec-8B family | **Verify** | Confirm chat variant and license first |
| Embedded vector DB | Qdrant local mode | Planned M1 | No Docker |
| Embeddings | small local model (e.g. bge-small class) | Verify M1 | CPU-friendly |
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
