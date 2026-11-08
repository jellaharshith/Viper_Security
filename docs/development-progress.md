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
- **M3e** (`eval/retrieval.py`, ADR 0007): `min_score` 0.65 -> **0.70**, calibrated on realistic top-1 scores from the live
  index (grounded 0.763-0.887, off-domain max 0.612, adjacent definitions up to 0.822). `def-3` (MFA) and `def-13` (password
  manager) flipped to grounded; `answers_v2.jsonl` hash changed, so `eval compare` against older reports warns (expected).
  Known limits: `general-2` (XSS acronym, 0.698) regresses below the cutoff; `nat-4` (Citrix Bleed) stays a miss because the
  KEV text never says "Bleed" and the record ranks 5th (0.751) at top_k=4; an external alias table is a future task.

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

- **M3e retrieval-only re-run at `min_score = 0.70` (2026-11-07, live Supabase, Ollama nomic-embed-text, dataset v2)**:
  recall@4 **0.948** (unchanged: `min_score` does not affect retrieval metrics), CISA KEV recall@4 **0.99**, ATT&CK 0.941,
  OWASP 0.975. Report: `eval/results/m3e-minscore-0-70-retrieval-only-2026-11-07.json`. Invalid citations are **not
  measured** here (`--skip-llm`); the last measured value is 0% from the Colab run at 0.65. A full answer run at 0.70 is
  still needed to confirm the predicted ~53-54/62.

### Not done / not verified
- The direct-Postgres store (`VIPER_STORE=pgvector`) has still never run against a real database.
- A full LLM answer run at `min_score = 0.70` (only retrieval-only was re-run); `def-5` flip proposed, awaiting a decision.
- Three flipped expectations in `answers_v2.jsonl` (SQL injection, XSS acronym, XSS definition) await human review.
- Open choices: OWASP edition 2025 (vs 2021), ATT&CK size cap 70 MB (plan said ~60 MB).
- GitHub CI has not been confirmed on PR #9.

## M3e close-out and M5 (2026-11-07)
- **M3 done.** Full v2 answer eval on Colab T4 at `min_score` 0.70: **58/62 (93.5%)**, 0% invalid citations (was 51/62 at 0.65).
  Remaining failures: `general-2` (known cutoff regression, ADR 0007) and `general-0`, `def-2`, `def-4` (missing "unverified" label: a prompt problem).
  Report: `eval/results/v2-colab-t4-full-minscore-0-70-2026-11-07.json`. CI on PR #9: green (7 passed, 1 skipped).
- **M4 gate decided: do not train.** See `docs/plans/m4-qlora-gate.md`; fix labelling with prompting and re-measure on Colab first.
- **M5 built (dry-run only, no live targets), branch `m5/build`:** pure deny-by-default policy engine (`viper.policy`), single-use expiring
  action-bound approvals, tool registry with dry-run stubs (`viper.tools`), sanitized hash-chained audit log (`viper.agents.audit`),
  LangGraph graph with interrupt/resume and a second policy check before dispatch (`viper.agents.graph`), SQLite checkpoints.
  CLI: `viper agent run|resume --scope scope.yaml --plan plan.json --thread T`, `viper audit verify --project P`.
  Decisions: SQLite checkpoints, OS-user approver, YAML scope, approval for ACTIVE only, audit log in `data/audit/`. 247 tests pass.
  Not done: an LLM-backed planner (a JSON plan file stands in), CLI repair command for a damaged audit log, external anchoring of the audit head (M6).

## M6 — Cloud Kali execution plane, headless-first (2026-11-07)
Built by a three-agent herdr crew (claude-m6 client, codex-m6 VM server, agy-m6 docs) with the
coordinator wiring and merging. **Headless execution plane built and wired in dry-run; the paid GCP
Kali VM and the one live scan are a gated on-demand step** (see `docs/plans/m6-gcloud-vm-setup.md`).
- **Orchestrator client** (`src/viper/execution/remote.py`, `factory.py`): `RemoteExecutor` posts an
  approved `Action` to the VM Exec API over TLS (verifying the VM CA), re-checks the target against the
  client-side egress allowlist before any byte leaves, binds a durable dispatch claim, polls to a
  terminal state, and returns a `DryRunResult(simulated=False)`. `make_executor()` is the fail-safe
  selector: it returns `DryRunExecutor` **unless** `allow_active_testing` **and** `exec_api_url` **and**
  a non-empty token **and** an existing CA cert are all present — so the default config can never reach
  real execution.
- **VM server** (`vmapi/`): FastAPI bound to 127.0.0.1 only, bearer-token auth on every route, a
  per-tool argument allowlist (nmap/nuclei; no shell, no output redirection, exact in-scope target),
  jobs spawned in their own process group so `/jobs/{id}/stop` SIGKILLs the whole tree and verifies it,
  `/stream` for watch, `/pause` SIGSTOPs. 27 passed / 3 POSIX-only skipped on Windows (must run on the
  Linux VM before deploy).
- **Exclusive control** (`src/viper/execution/control.py`): one holder per project on SQLite; a human
  `takeover()` preempts the agent, which then refuses to dispatch (`graph.execute` acquires `agent`
  first). Reentrant for the agent, race-free (the INSERT is the compare-and-set).
- **Real tools** (`src/viper/tools/real.py`): `nmap` and `nuclei` registered as `ACTIVE`,
  `dry_run_only=False`, with parameter schemas mirroring the vmapi allowlist. The policy engine
  therefore DENIES them unless `allow_active_testing` is on, and REQUIRES human approval when it is.
  Verified end-to-end: a disarmed `nmap` scan of `scanme.nmap.org` is denied with an intact audit chain.
- **CLI**: `viper exec watch|pause|stop` (VM-backed) and `viper exec takeover|release` (control lock).
- **Config**: `exec_api_ca_cert`, `exec_egress_allowlist` (+ `egress_hosts()`); `exec_api_url`,
  `exec_api_token`, `allow_active_testing` already existed. Default config stays fully dry-run.
- Verification: 276 src tests + 27 vmapi tests pass, ruff and mypy clean. Target for the gated run is
  `scanme.nmap.org` (`projects/lab-scanme/scope.yaml`), reached over a gcloud IAP tunnel (no public port).
- Not done: the live VM run itself (gated on user go), noVNC desktop take-over (deferred), external
  audit-head anchoring (still open), real-execution audit event naming (reuses `tool_dry_run` for now).
