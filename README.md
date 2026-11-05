# Viper

Personal, human-controlled cybersecurity AI assistant for **authorized** testing. Hybrid design: Colab for training, laptop for local inference/agents, a separate cloud VM for security tools. See `docs/architecture.md`.

**Status:** M1 - local chat with cited answers over CISA KEV. No security tool runs yet.

## Setup (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt -e .
copy .env.example .env
.\tasks.ps1 check     # lint + types + tests
.\tasks.ps1 health    # redacted config
```

## Rules
Never commit `.env`. Active testing is off by default. No scans without documented authorization and approval.

Docs: `docs/` (architecture, roadmap, stack, security, evaluation, progress).

## Using the M1 chat (needs Ollama running)
```powershell
ollama pull nomic-embed-text
ollama pull hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF:Q4_K_M   # ~4.9 GB
# put VIPER_OLLAMA_MODEL=<that model name> in .env
.\.venv\Scripts\python.exe -m viper.cli ingest-kev        # downloads + indexes CISA KEV
.\.venv\Scripts\python.exe -m viper.cli chat "What is CVE-2021-44228?"
.\.venv\Scripts\python.exe -m viper.cli chat               # interactive
```
Answers cite numbered sources. If nothing relevant is found, the answer is labelled UNVERIFIED.
A CVE that is not in KEV is reported as such without asking the model. CPU-only: expect ~1 minute per answer.
