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
Built by three parallel lanes, each in its own worktree; the lead re-ran
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
Built by a three-agent herdr crew (lane-A-m6 client, lane-B-m6 VM server, lane-C-m6 docs) with the
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

## M6 LIVE VALIDATION — 2026-11-08 (definition of done met)
Provisioned a real headless GCP execution plane and ran the five verbs end-to-end against the
authorized target `scanme.nmap.org`, then tore everything down (total cost a few cents).
- **Infra:** spot `e2-medium` Ubuntu 22.04 VM (`--no-address`, no public IP), Cloud NAT for egress-only
  internet, IAP-SSH-only firewall; `vmapi` under systemd bound to `127.0.0.1:8443` (TLS + bearer token);
  reached from the workstation via an **SSH port-forward over IAP** (`-L 8443:localhost:8443`) — the
  `start-iap-tunnel` method fails here because the server binds loopback by design.
- **Pre-deploy gate:** the VM lane's 3 Linux-only process-tree-kill tests (plus the rest) — **30 passed on the VM**.
- **The five verbs, live:**
  1. *Approve* — `nmap` (ACTIVE) paused at the approval checkpoint; `agent resume --decision ALLOW`.
  2. *Watch* — `viper exec watch` streamed real nmap output: `scanme.nmap.org (45.33.32.156)` 22/tcp ssh,
     80/tcp http open, scanned in 7.53s; run reported `COMPLETED executed=1`.
  3. *Take over* — `viper exec takeover` → the agent's next run returned `REJECTED executed=0`.
  4. *Pause* — a running scan went `running → paused` (SIGSTOP).
  5. *Emergency-stop* — `viper exec stop` → `killed, exit_code -9` (SIGKILL whole process group, verified).
- **Audit:** `viper audit verify --project lab-scanme` → `audit log OK` (intact hash chain:
  plan_proposed → policy REQUIRE_APPROVAL → approval_requested → approval_granted → approval_consumed →
  tool_dry_run → run_completed).
- **Teardown:** VM + NAT + router + firewall deleted; `.env` reset to `VIPER_ALLOW_ACTIVE_TESTING=false`.
- Follow-ups unchanged: noVNC desktop take-over (deferred); real-exec audit event is still named
  `tool_dry_run`; external audit-head anchoring still open.

## M7 BUILD — 2026-11-08 (offline definition of done met; live run pending)
Three-agent herdr crew on branch `m7/pentest-copilot` (lane-A-m7 parsers + stream capture, lane-B-m7
report + anchoring + security review, lane-C-m7 docs; coordinator wiring). 465 tests, ruff + mypy clean.
- **Findings** (`viper.findings`): Finding schema v1; deterministic nmap/nuclei parsers. `confirmed` only
  from parser evidence, never from LLM text. Bounded, control/bidi-neutralised, shell-quoted repro.
- **LLM planner** (`agents/planner.py`): opt-in `agent run --llm`; strict fail-closed parsing, size and
  decode budgets, plain-token action ids. Verified against the real Foundation-Sec-1.1-8B model
  (61 s, no egress): it proposed nmap + kb_answer; policy denied the ACTIVE scan (active testing off).
- **Evidence model** (`agents/evidence.py`): real dispatch writes `tool_dispatch` (intent) then
  `tool_result` (SHA-256 output digest, simulated/truncated flags). Findings are re-derived from the
  AUDITED results only; missing/duplicated/edited/unaudited checkpoint results become report
  warnings, never a clean report. Closes the M6 follow-up on real-exec event naming.
- **Report**: traceable Markdown with audit-hash citations, Analysis warnings and Denied actions;
  saved to `data/reports/<thread>.md` (exclusive create; thread ids cannot be reused).
- **Anchoring**: `viper audit anchor` (mock) + `audit verify` anchor verdicts (CONSISTENT_ONLY,
  VERIFIED, UNVERIFIED, TAMPERED, MALFORMED, MISMATCH) with chain coverage. Real TSA/Rekor receipts stay
  UNVERIFIED until a trusted offline verifier is wired in (documented limitation).
- **Security review**: an independent reviewer covered `376c255..HEAD` (10 medium findings), all fixed; re-review found
  7 fixed / 3 partial + 4 residuals, all fixed in round 5.
- **Not done**: noVNC takeover and multi-job dispatch stay deferred (see live validation below for the run).

## M7 LIVE VALIDATION - 2026-11-08 (definition of done met)
Re-provisioned the execution plane per the runbook, ran the full copilot workflow against the authorized
lab host `scanme.nmap.org` only, then deleted everything (total cost: minutes of one spot e2-medium).
- **Infra:** spot `e2-medium` Ubuntu 22.04 (`--no-address`), Cloud Router + NAT, IAP-only SSH firewall,
  `vmapi` under systemd on 127.0.0.1:8443 (TLS + bearer token), reached by an SSH port-forward over IAP.
  The pre-existing `kali-vm` in the project was not touched.
- **Workflow:** `agent run` (plan) paused at the approval checkpoint; `agent resume --decision ALLOW`
  dispatched `nmap -sT -sV -p 22,80,443 scanme.nmap.org`; output was captured from the job stream,
  digest-committed, parsed, and rendered. Result: `COMPLETED executed=1`.
- **Traceable report:** 2 confirmed findings (22/tcp ssh OpenSSH 6.6.1p1; 80/tcp http Apache 2.4.7), each with
  the raw nmap line as evidence and a citation to the `tool_result` audit event (seq 32) bound to that exact
  action. 443/tcp was not open, so no finding was produced for it.
- **Audit:** chain `plan_proposed -> policy REQUIRE_APPROVAL -> approval_requested -> approval_granted ->
  approval_consumed -> tool_dispatch -> tool_result(digest) -> run_completed -> findings_generated ->
  report_generated`; `viper audit verify` OK; mock anchor `CONSISTENT_ONLY` covering seq 0-35.
- **Runbook bugs found and fixed:** (1) the systemd unit ran `uvicorn app:app` but `app.py` imports
  `vmapi.auth`, so it must run from `/opt/viper` as `vmapi.app:app`; (2) the VM env var is
  `VIPER_EXEC_EGRESS_ALLOWLIST`, not `...TARGET_ALLOWLIST` (an empty allowlist makes every job a 422);
  (3) the port-forward must use PuTTY-only flags on Windows; (4) Step 8 CLI invocations were wrong.
  First attempt failed closed (`RemoteJobError`, nothing reached the target) and was recorded in the audit log.
- **Teardown verified:** tunnel process stopped, VM + NAT + router + firewall rule deleted, `.env` restored
  with `VIPER_ALLOW_ACTIVE_TESTING` unset, cert and token deleted. Only the user's own `kali-vm` remains.
- **Follow-ups:** external TSA/Rekor anchoring needs a trusted offline verifier; noVNC takeover; nuclei is
  not installed on the Ubuntu image (apt has no nuclei), so only nmap was exercised live.

## V1 BUILD - 2026-11-08 (offline definition of done met; live-validated, see below)
Four-session herdr crew on branch `v1/finish` (lane-A-v1 scope reader + rehearsal test, lane-B-v1 VM `nuclei`
profile + bootstrap + security review, lane-C-v1 weekly workflow + docs, coordinator planner/CLI/wiring).
718 tests + 64 VM-API tests, ruff and mypy clean.
- **Planner <-> VM consistency:** `NmapArgs.ports` is validated exactly like the VM; arguments are strict (no
  `"true"`/`1` booleans, no `"5"` rates, no explicit null ports) because the ORIGINAL args are dispatched; the
  planner prompt carries the exact allowed hosts and argument formats, and a real-tool target must be an exact
  egress host, so a bad plan fails at plan time instead of after a human approved it.
- **Live nuclei profile:** `-passive` is gone. Frozen argv: JSONL, tags `tech,misconfig`, excluded tags
  `dos,fuzz,intrusive,bruteforce,rce,sqli,xss`, severities `info,low,medium`, `-pt http`, `-rl`, `-c 5`,
  `-timeout 10`, `-retries 0`. The template directory comes only from `VIPER_EXEC_NUCLEI_TEMPLATES` on the VM,
  never from request arguments. All 15 flags were checked against the pinned nuclei 3.3.10 documentation.
- **Scope reader:** `viper scope draft` (model drafts a scope + ambiguities from pasted program rules) and
  `viper scope approve --confirm <project>`. A draft carries `status: DRAFT`, which the strict `Scope` model
  rejects, so an agent can never run on it. Approval validates in memory, appends the `scope_approved` audit
  event, then publishes the file all-or-nothing (fsynced temp file + exclusive link). Rehearsed against the real
  Foundation-Sec model on the lab host's usage rules: a single-host scope, DoS and repetitive scanning forbidden,
  and the right ambiguities raised (are tools other than Nmap allowed; what is "hammering").
- **Weekly KB refresh:** `.github/workflows/kb-weekly.yml` (schedule + manual only, read-only permissions,
  SHA-pinned actions, checksum-verified Ollama archive, one queueing concurrency group). It needs the repository
  secrets `SUPABASE_URL` and `SUPABASE_SECRET_KEY`; without them it ends cleanly. Staging collections get a random
  suffix so concurrent runs cannot share one.
- **Reproducible VM:** `deploy/vm-bootstrap.sh` (unprivileged `viper-vmapi` user, checksum-verified nuclei,
  root-owned templates, TLS + token never printed) with static safety tests.
- **Independent security review:** 9 findings in the first pass (scope-draft IP aliases and public-suffix wildcards,
  scope written before its audit event, unverified Ollama archive, workflow concurrency, nuclei not protocol-
  restricted, runbook `User=root`, ambiguities displacing mandatory warnings, client/VM validation drift) plus 4
  residuals in the re-review (partial scope write, bootstrap allowlist newline injection, README/CHANGELOG
  accuracy). All fixed and re-verified.
- **Deferred to v1.1 (docs/v1-scope.md):** OWASP ZAP, noVNC desktop, real RFC-3161 anchoring, scope rate-limit
  fields, SSH takeover shell, NVD source, PostgreSQL operational tables, multi-job dispatch.

## V1 LIVE VALIDATION - 2026-11-08/09 (what the real run changed)
A real GCP VM (spot e2-medium, no public IP, NAT, IAP-only) bootstrapped with `deploy/vm-bootstrap.sh`; the local
Foundation-Sec model planned each scan and the human approval checkpoint was used. The run found four problems the
offline suite could not, all fixed here:
1. **Template install was a silent no-op.** The bootstrap ran `nuclei -update-templates ... -duc`; `-duc` makes the update
   do nothing, so the VM had 0 templates and nuclei would have "succeeded" with no results. Fixed: no `-duc` on that
   step, plus a guard that fails the bootstrap if fewer than 1,000 templates are installed.
2. **A shared public sandbox throttles nuclei.** Against `scanme.nmap.org` the first nuclei run hit I/O timeouts and
   nuclei marked the host unresponsive (zero output, exit 0). Nmap-style benign scanning of that host is fine; template
   scanning it is the "do not hammer" case its rules describe (and which the scope reader flagged as an ambiguity). Nuclei
   was therefore validated against a web server on the VM's own loopback instead.
3. **The nuclei profile was too big for the job limit.** `tech,exposure,misconfig` is ~8,290 requests (~28 min at 5 req/s)
   and the VM API killed the job at its hard 300 s limit (`killed`, exit -9). The run failed closed: audited `run_failed`,
   nmap findings kept, nothing reported as clean. Measured on the VM: `tech,misconfig` = 1,636 requests, `tech` = 860.
   Fixed: the `exposure` tag (the bulk of the requests, and the most intrusive part) is dropped, and the VM API now has a
   per-tool wall-clock limit (nmap 300 s, nuclei 900 s) chosen from the program name only.
4. **Real-model scope reader worked in the loop:** it drafted the scope for the self-owned loopback target, a human
   approved it with `--confirm`, and the agent then planned and ran under that scope.
5. **Re-running the bootstrap is safe**, which was itself tested live: the idempotent re-run kept the existing token and
   certificate, found the templates current, restarted the service and passed its authenticated health check. A CRLF copy
   of the script breaks bash on the VM (`set: pipefail`), so a test now fails if the script ever contains a carriage return.
6. **Test isolation:** the live `.env` (active testing on, a VM URL and token) flipped five unit tests to the remote
   executor. No traffic reached the VM (the client egress check refuses first), but tests must never depend on a developer
   `.env`, so `tests/conftest.py` now pins the execution-plane variables to their safe defaults.

**Result (definition of done met).** Two approved AI-planned runs on the live VM, each paused at the human approval
checkpoint and ended `COMPLETED`:
- `scanme.nmap.org` (published sandbox, nmap only): ports 22/ssh (OpenSSH 6.6.1p1) and 80/http (Apache 2.4.7), 2 confirmed
  findings, each citing its `tool_result` audit event.
- the VM's own loopback web server (scope drafted by the real model, approved by a human): nmap found 22 and 80, and
  nuclei (the frozen `tech,misconfig` HTTP profile, 900 s limit, ~5 minutes) found 4 confirmed findings: `waf-detect`,
  `tech-detect`, `http-missing-security-headers` and `nginx-eol`, each citing audit event seq 28.
- `viper audit verify` OK for both project logs and a mock anchor recorded (`CONSISTENT_ONLY`, not external proof).
- Teardown verified: tunnel stopped; VM, NAT, router and firewall rule deleted; `.env` restored; certificate, token and
  scratch files deleted. Only the owner's own `kali-vm` remains in the project.
- Follow-ups for v1.1: richer remediation text and references for nuclei findings (real nuclei JSON carries little of it for
  many templates), evidence rendering that is easier to read than HTML-escaped JSON, and a reviewed HTTP template subset.
