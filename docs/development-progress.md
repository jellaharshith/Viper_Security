# Development Progress

## Status: M1 built and live-tested on branch m1/local-chat-rag (PR pending); M2 next

### 2026-11-04
- Architecture reviewed; hybrid three-plane design adopted.
- Hardware checked: Ryzen 5 PRO 8540U, 14.7 GB RAM, integrated GPU (CPU-only inference). Python 3.12, Git, Ollama present; no Docker.
- Scaffolded project: config, JSON logging, CLI `--health`, module boundaries for all planes.
- Found and fixed a bug via tests: `Path` setting was not JSON-serializable in `--health`.
- Verification: ruff clean, mypy strict clean, 12 tests passed, `--health` OK with token masked.

### Open items
- Verify Foundation-Sec-8B variants and license (start of M1).
- Choose embedding model.
- Not yet run: anything involving a model, Qdrant, cloud, or security tools.

### Rollback
Everything is in git; each milestone is a commit.

### 2026-11-04 (GitHub + CI)
- Connected `origin` (private repo), rebased M0 onto remote `main` (which held only `LICENSE`, Unlicense). Branch renamed `master` -> `main`.
- Added `ci.yml`, `security.yml`, Dependabot, CODEOWNERS, PR template, `.gitattributes` on branch `ci/github-actions`. YAML validated locally; **not yet run on GitHub** until pushed and checked.
- ADR 0002 records the CI/CD and scanning choices.

### 2026-11-05 (M1: local chat + cited RAG)
- Verified model facts from primary sources (see model-evaluation-plan.md). Pulled Foundation-Sec-1.1-8B-Instruct Q4_K_M and nomic-embed-text into Ollama.
- Built Ollama client, CISA KEV connector (https + cisa.gov host only, schema-validated), embedded Qdrant store (deterministic ids), grounded answer pipeline, CLI (`ingest-kev`, `chat`).
- Live: ingested 1,768 KEV records; Log4Shell, Palo Alto and off-topic questions behave as designed. 38 tests, ruff and mypy strict clean.
- Found by live testing, fixed: dense retrieval missed an exact CVE id (Log4Shell) - added exact-ID lookup; named CVEs now answer only from their own record; CVE absent from KEV is reported without calling the model; citation checker now also catches `[Source: N]`.
- Bugs of my own caught along the way: unserializable Path in `--health`; two escape-sequence slips in generated code (regex ``, f-string newline) caught by tests/linters.

### Known limitations (inputs to M2 evaluation)
- `min_score=0.55` does not separate relevant from irrelevant: unrelated records scored 0.68-0.72. Needs calibration on a labelled set.
- The citation check verifies a cited number exists, not that the claim is supported by that source. Spot-checks passed (ransomware claim verified), but unproven at scale.
- Only CISA KEV is indexed; no NVD/ATT&CK/OWASP yet, no chunking of long documents.
- ~1 min per answer on this CPU. No streaming output.
- Not yet verified: GitHub CI on the M1 branch.
