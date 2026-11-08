<div align="center">

# Viper

**A human-controlled AI copilot for authorized penetration testing and bug-bounty research.**

It plans a test, asks you to approve it, runs approved tools on a separate cloud VM, turns the raw output into
validated findings, and writes a report where every claim traces back to a tamper-evident audit log.

[![CI](https://github.com/jellaharshith/Viper_Security/actions/workflows/ci.yml/badge.svg)](https://github.com/jellaharshith/Viper_Security/actions/workflows/ci.yml)
[![Security](https://github.com/jellaharshith/Viper_Security/actions/workflows/security.yml/badge.svg)](https://github.com/jellaharshith/Viper_Security/actions/workflows/security.yml)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-green)](LICENSE)
![Status](https://img.shields.io/badge/status-M7%20complete-brightgreen)

</div>

> [!WARNING]
> Viper is for **authorized** testing only: your own systems, intentionally vulnerable labs, or targets with written
> permission. Active testing is **off by default** and every active action needs an explicit human approval.
> See [Responsible use](#responsible-use).

## Why Viper

Most "AI pentest" tools let a model decide what to attack. Viper does the opposite: **the model proposes, deterministic
code decides, and a human approves.**

| Principle | How it is enforced |
|---|---|
| The model never grants permission | `viper.policy` is plain code. LLM text cannot raise a risk level, add a target, or approve itself. |
| Default-deny scope | Anything outside the engagement scope file is refused, and re-checked on the VM. |
| Human in the loop | Active actions pause at an approval checkpoint bound to the exact tool, arguments, scope revision and expiry. |
| Findings are evidence, not guesses | `confirmed` is set only from parser evidence in real tool output, never from LLM text. |
| Traceable | Reports cite audit events by hash. The audit log is a SHA-256 hash chain; findings are re-derived from audited output digests. |
| Safe to stop | Pause, take over, or emergency-stop a running job (the whole process tree is killed and verified). |

## How it works

```mermaid
flowchart LR
    U([You]) -->|request| P[Planner<br/>LLM proposes]
    P --> G{{Policy gate<br/>deterministic}}
    G -->|needs approval| A[/Human approval/]
    A --> X[Execution client<br/>2nd policy check]
    X -->|TLS + bearer token| V[(Cloud VM<br/>vmapi: nmap, nuclei)]
    V -->|stdout| X
    X --> N[Analyze<br/>parse + validate]
    N --> R[Traceable report]
    G -.-> L[(Audit log<br/>hash chain)]
    A -.-> L
    X -.-> L
    N -.-> L
    R -.-> L
```

- **Local plane** (your laptop, CPU only): chat with cited RAG answers, the LangGraph agent, the policy engine.
- **Execution plane** (a separate cloud VM, no public IP): the only place security tools run. Reached over an
  IAP-tunnelled SSH port-forward; bound to loopback with TLS and a bearer token.
- **Knowledge pipeline**: weekly gated RAG refresh from CISA KEV, MITRE ATT&CK and the OWASP Top 10.

Full design: [`docs/architecture.md`](docs/architecture.md) and [`docs/security-design.md`](docs/security-design.md).

## Status

| ID | Milestone | State |
|---|---|---|
| M0 | Foundation: skeleton, config, logging, tests, docs | Done |
| M1 | Local chat + cited RAG | Done |
| M2 | Evaluation harness + baseline | Done |
| M3 | Weekly RAG automation with gates and rollback | Done |
| M4 | QLoRA fine-tune (gated by M2) | Decided: do not train |
| M5 | LangGraph agents + policy engine | Done |
| M6 | Cloud execution plane: approve, watch, take over, pause, emergency-stop | Done, live-validated |
| M7 | Pentest copilot: planner, finding validation, traceable report | Done, live-validated |

M7 was validated end to end on 2026-11-08 against the authorized lab host `scanme.nmap.org`: an approved `nmap`
scan produced two confirmed findings, each citing the audit event that produced it, and the audit chain verified.
See [`docs/development-progress.md`](docs/development-progress.md).

## Quick start

Requires Python 3.12+. The local model runs through [Ollama](https://ollama.com).

```powershell
git clone https://github.com/jellaharshith/Viper_Security.git
cd Viper_Security
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt -e .
copy .env.example .env          # then edit; never commit .env
.\tasks.ps1 check               # ruff + mypy + pytest
.\tasks.ps1 health              # redacted config
```

On macOS/Linux use `source .venv/bin/activate` and call `viper ...` (or `python -m viper.cli ...`) directly.

### Ask a question (cited RAG)

```powershell
ollama pull nomic-embed-text
ollama pull hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF:Q4_K_M   # ~4.9 GB
# set VIPER_OLLAMA_MODEL=<that model name> in .env
python -m viper.cli ingest-kev
python -m viper.cli chat "What is CVE-2021-44228?"
```

Answers cite numbered sources; if nothing relevant is retrieved they are labelled `UNVERIFIED`.

### Run an agent workflow (dry-run by default)

```powershell
# 1. plan: from a JSON plan file, or let the local model propose one with --llm
python -m viper.cli agent run --scope projects/lab-scanme/scope.yaml `
    --plan projects/lab-scanme/plan.json --thread lab1
# 2. approve the pending action (shows tool, arguments and hash first)
python -m viper.cli agent resume --scope projects/lab-scanme/scope.yaml --thread lab1 --decision ALLOW
# 3. read the report and verify the audit trail
python -m viper.cli report --thread lab1
python -m viper.cli audit verify --project lab-scanme
```

Without an execution plane configured, approved actions run as **dry-run stubs** and nothing touches the network.
To run real tools, deploy the execution plane with
[`docs/plans/m6-gcloud-vm-setup.md`](docs/plans/m6-gcloud-vm-setup.md) and set the `VIPER_EXEC_*` variables
(see [`.env.example`](.env.example)). Real execution additionally requires `VIPER_ALLOW_ACTIVE_TESTING=true`.

## Command reference

| Command | Purpose |
|---|---|
| `viper --health` | Print the redacted configuration |
| `viper chat [question]` | Cited RAG chat (one-shot or interactive) |
| `viper ingest-kev` | Download and index CISA KEV |
| `viper kb update \| status \| rollback` | Gated knowledge-base lifecycle |
| `viper eval build \| run \| compare` | Evaluation framework |
| `viper agent run --plan FILE \| --llm` | Start a policy-gated agent run |
| `viper agent resume --decision ALLOW\|DENY` | Answer a pending approval |
| `viper report --thread ID` | Print a finished run's traceable report |
| `viper audit verify \| anchor --project ID` | Verify the hash chain and anchors; anchor the head |
| `viper exec watch \| pause \| stop --job ID` | Stream, pause or emergency-stop a running job |
| `viper exec takeover \| release --project ID` | Take or release exclusive control of the VM |

## Project layout

```text
src/viper/
  agents/       LangGraph agent: planner, graph, audit log, evidence binding, anchoring
  policy/       Deterministic scope engine and approval binding (no I/O)
  tools/        Tool registry: nmap and nuclei (real), dry-run stubs
  execution/    Remote executor, fail-safe factory, exclusive-control lock
  findings/     Finding schema and nmap/nuclei parsers
  report/       Traceable Markdown report renderer
  rag/          Ingestion, embeddings, retrieval, gated updates, vector stores
  llm/          Ollama client
  eval/         Evaluation harness
vmapi/          VM-side Exec API (FastAPI), standalone and independently tested
projects/       Engagement scopes and plans (lab-scanme)
db/migrations/  Supabase / pgvector schema
docs/           Architecture, ADRs, plans, runbooks, templates
tests/          Unit and integration tests (offline)
```

## Documentation

| Start here | |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Planes, components, data entities, control states |
| [`docs/security-design.md`](docs/security-design.md) | Threat model and controls |
| [`docs/implementation-roadmap.md`](docs/implementation-roadmap.md) | Milestones and dependencies |
| [`docs/development-progress.md`](docs/development-progress.md) | What was built and validated, milestone by milestone |
| [`docs/adr/`](docs/adr) | Architecture decision records (0001-0010) |
| [`docs/plans/`](docs/plans) | Per-milestone specs and the cloud runbook |
| [`docs/requirements.md`](docs/requirements.md) | Original product requirements |

## Development

```powershell
.\tasks.ps1 test     # pytest (offline; no network, no live targets)
.\tasks.ps1 lint     # ruff
.\tasks.ps1 types    # mypy --strict
.\tasks.ps1 check    # all of the above
```

CI runs lint, strict types and the test suite on Python 3.12 and 3.13 (Linux) and 3.12 (Windows). A separate
workflow runs a secret scan and a dependency audit on every pull request and weekly. The test suite never touches
the network or a real target. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible use

Only test systems you own or have **written authorization** to test. Record that authorization in the scope file
(`evidence_ref`). Never enable active testing against a target you are not permitted to test. Intrusive and
exploitation techniques are permanently denied by policy. The authors accept no liability for misuse.

Found a vulnerability in Viper itself? See [SECURITY.md](SECURITY.md).

## License

[Unlicense](LICENSE): public domain.
