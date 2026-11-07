# Development Progress

## Status: M1 merged. M2 (evaluation harness + baseline) built and run on branch m2/eval-harness; PR pending

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

### 2026-11-05 (M2: evaluation harness + baseline)
- Built `viper.eval` (cases, retrieval metrics + calibration, answer checks, runner, report compare), frozen held-out datasets (130 retrieval, 22 answer cases), CLI `viper eval build|run|compare`. 59 tests; ruff and mypy strict clean.
- Findings from running it (details: model-evaluation-plan.md, ADR 0003):
  1. My first retrieval set had ambiguous gold answers (shared titles); rebuilt with unique records only.
  2. Synthetic calibration (cutoff 0.717, "perfect") was misleading: realistic questions score lower. Rejected; chose 0.65 using grouped natural/off-topic/adjacent questions.
  3. nomic task prefixes: recall@4 97% -> 99%, but raised all scores; adopted as index `v2p` (v1 kept for rollback).
  4. Requiring citations everywhere regressed JSON answers to 0/3 (overall 86% -> 77%); caught only because the full eval was re-run. Scoped to the semantic path: overall 90.9%.
- Process notes: several bugs were escape-sequence slips in generated code (regex ``, f-string newlines, dataset-line wrapping); caught by tests/linters, not by inspection. Large heredocs and nested escapes are unreliable here; use file-write tools for code.
- Not done: comparison against other models (needs approval for downloads); NVD/ATT&CK/OWASP ingestion; weekly automation (M3).
- Not verified: GitHub CI on the M2 branch.

## M3a - Gated KB update pipeline (2026-11-05, branch `m3/rag-automation`)
Built and verified live: registry-based promotion/rollback, staging collection, validation + retrieval gates,
incremental embedding (unchanged records reuse vectors). 66 tests pass. Real run: 1768 fetched / 1768 reused /
0 embedded, recall@4 0.99 vs 0.99, promoted, rolled back, chat verified after rollback. See ADR 0004.

Remaining in M3 (needs decisions): scheduling/persistent Qdrant, extra sources (MITRE ATT&CK, OWASP, NVD),
dataset v2 so the gate covers them.

## M3b/c/d - Multi-source KB, dataset v2, pgvector backend (2026-11-06, branch `m3/integration`)
Built by three parallel lanes (Claude subagent, Codex, Antigravity), each in its own worktree; the lead re-ran
pytest/ruff/mypy for every lane and merged A -> C -> B. 127 tests pass; ruff and mypy strict clean.
- **M3b** (`rag/sources.py`, `attack.py`, `owasp.py`): MITRE ATT&CK v20.1 (706 active techniques) and OWASP Top 10 2025
  (40 chunks, pinned to a commit SHA). A failed source is carried over from the live collection and flagged;
  shrink validation is per source. Exact-ID lookup now covers ATT&CK ids.
- **M3c** (`eval/build.py`, `runner.py`, ADR 0005): dataset v2 builders, per-source recall gate. v1 datasets are
  hash-pinned and untouched. The v2 files were built from fixtures and must be rebuilt from the live index.
- **M3d** (`rag/pgstore.py`, `db/migrations/0001_kb.sql`, ADR 0006): pgvector store and transactional registry,
  RLS on with no policies, no ANN index. Selected with `VIPER_STORE=pgvector` + `VIPER_DATABASE_URL`
  (`rag/backend.py` is the only place that chooses the backend).

### Live verification (2026-11-06)
- **Supabase over HTTPS** (`VIPER_STORE=supabase`, `rag/reststore.py`): reads `SUPABASE_URL` and `SUPABASE_SECRET_KEY`
  from `.env`; setup SQL is `db/migrations/0001_kb.sql` + `0002_kb_rest.sql`, run once in the SQL editor.
  18/18 live checks passed (round trip, exact search score 1.0, bootstrap/promote/rollback, history, invalid names
  refused) and the publishable key got HTTP 401 on every read, insert and function call.
- **Real knowledge base in Supabase**: 2,515 records (KEV 1,769, ATT&CK 706, OWASP 40), staged recall@4 0.99,
  promoted, rolled back and re-promoted. Chat answers served from Supabase: `What is T1059.001?` returns the exact
  record (score 1.00); `What is SQL injection?` is now grounded in OWASP A05:2025 (a known M2 failure). `--health`
  masks the secret key.
- **Local Qdrant**: live ATT&CK + OWASP dry run passed gates (recall@4 0.99 vs 0.99); the staged collection was not promoted.
- Found by the live run, not by tests: Supabase resets the connection on ~800 KB request bodies, so upserts are batched
  by payload size (<= ~200 KB) and retried.

- **Dataset v2 rebuilt from the live index** (751 ATT&CK/OWASP retrieval cases + 62 answer cases; v1 untouched).
  Retrieval-only eval against Supabase, 846 queries, recall@4 **0.948** overall: CISA KEV 0.99 (no regression vs v1),
  MITRE ATT&CK 0.941 (706), OWASP Top 10 0.975 (40). Weakest style: ATT&CK `hint` queries 0.918, OWASP prevention 0.90.
  Report: `eval/results/v2-supabase-retrieval-only-2026-11-06-2026-11-07.json`. Answer cases (LLM) not run yet.
  Caveat: "description" queries are verbatim passage text, an easy test; synthetic calibration suggests 0.673 but ADR 0003
  showed synthetic calibration misleads, so `min_score` stays 0.65 until recalibrated on realistic questions.

- **Full v2 answer evaluation (Colab T4, same chat model, live Supabase index)**: 51/62 passed (82.3%), invalid-citation
  rate **0%**, mean 9.3 s/answer. Retrieval reproduced the local run exactly (recall@4 0.948), so the cloud run is comparable.
  Report: `eval/results/v2-colab-t4-full-2026-11-07.json`. By group: off-domain 16/16, safety 4/4, JSON 3/3, missing-CVE 3/3,
  KEV facts 6/6, KEV natural 11/12, general 1/3, definitions 7/15.
  - Against the v1 baseline on the 19 shared cases: 1 regression (`general-1`, HTTPS/TLS: an ATT&CK record now mentions
    HTTPS, so the answer is attributed to sources instead of labelled unverified), 1 improvement (`general-2`, the XSS acronym).
  - The 8 failing definition cases are mostly **stale expectations, not model errors**: `def-5` (OWASP Top 10 categories) and
    `def-7` (ATT&CK technique for phishing) are now correctly answered from the new sources, and `def-10` (zero-day) is
    grounded in a KEV record. The buffer overflow / MFA / public-key / password-manager / security-report cases attach
    topically related ATT&CK or OWASP records above `min_score = 0.65`: with three sources the cutoff separates less well.
  - `nat-4` (Citrix Bleed, new in v2) answered "not in the sources" and cited none: a retrieval miss to investigate.
  - Flipped expectations `def-12` and `def-xss` (SQL injection, XSS) need human review, as do the safety cases.

### Not done / not verified
- The direct-Postgres store (`VIPER_STORE=pgvector`) has still never run against a real database.
- `min_score` recalibration on realistic questions (the definition cases above show 0.65 is now too permissive), and a human
  decision on which definition expectations should flip, are pending.
- Three flipped expectations in `answers_v2.jsonl` (SQL injection, XSS acronym, XSS definition) await human review.
- Open choices: OWASP edition 2025 (vs 2021), ATT&CK size cap 70 MB (plan said ~60 MB).
- GitHub CI has not been confirmed on PR #9.
