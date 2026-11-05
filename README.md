# Viper

Personal, human-controlled cybersecurity AI assistant for **authorized** testing. Hybrid design: Colab for training, laptop for local inference/agents, a separate cloud VM for security tools. See `docs/architecture.md`.

**Status:** M0 foundation only. No model or security tool runs yet.

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
