# Plan — M3b/c/d: MITRE ATT&CK + OWASP Top 10 sources, dataset v2, and a Supabase (pgvector) backend

## Context
M0–M2 are done; M3a (gated, versioned KEV update with atomic promote/rollback, branch `m3/rag-automation`, commit 4c99b6c) is pushed and verified live. The user answered the open M3 questions:
1. Wants an **alternative to a Qdrant Cloud account** and asks whether **Supabase** works.
2. Wants **MITRE ATT&CK and OWASP Top 10 next**.

Why it matters: ATT&CK/OWASP contain *definitions*, which should fix the known M2 failures (SQL injection / XSS questions get unrelated KEV sources attached). The M2 gate only measures KEV questions, so new sources need a bigger frozen dataset first.

## Answer to "can we use Supabase?" — Yes
Supabase is Postgres with the `pgvector` extension, so it can hold the KB and the promote/rollback pointer. Fit: ~1,768 KEV + ~700 ATT&CK + ~10–50 OWASP chunks × 768 dims ≈ 15 MB, far under the free tier's 500 MB. Caveats to design around:
- **Free projects pause after ~1 week of inactivity.** A weekly job keeps it awake; if it ever pauses, restore it. (Verify current free-tier limits at implementation time.)
- **Direct DB host is IPv6-only**; GitHub runners need the **session pooler** connection string.
- **Security:** the connection string is a secret (`VIPER_DATABASE_URL`, `SecretStr`, git-ignored `.env` / GitHub Actions secret). Tables get **RLS enabled with no public policies** and are never exposed through the anon/PostgREST key.
- **Supabase solves persistence, not embedding.** Embeddings still need Ollama (`nomic-embed-text`), so the weekly job still runs where Ollama runs (laptop Task Scheduler, or a runner that installs Ollama).
- Local embedded Qdrant stays the default; Supabase is a selectable backend (`VIPER_STORE=qdrant|pgvector`), so nothing regresses.

## Approach (3 stages, each its own branch/PR, each ends with an approval check)

### M3b — Multi-source ingestion (branch `m3b/attack-owasp`) — no external accounts
Reuse: `Document`/`Embedder` (`rag/types.py`), `parse_kev`/`fetch_kev` pattern (`rag/cisa_kev.py`: https + host allow-list, no redirects, schema validation, dedupe), `run_update`/`stage`/`validate` (`rag/update.py`), `KBRegistry` (`rag/registry.py`).
1. **`rag/sources.py`**: `Source` protocol (`name`, `fetch() -> list[Document]`); KEV becomes one source.
2. **`rag/attack.py`** — MITRE ATT&CK enterprise STIX JSON from `mitre-attack/attack-stix-data` (pinned release tag, host `raw.githubusercontent.com` only, size cap ~60 MB). Keep `attack-pattern` objects (techniques + sub-techniques), skip `revoked`/`x_mitre_deprecated`; id `attack:T1059.001`; text = id, name, tactics (kill-chain phases), platforms, description, detection; url = the `mitre-attack` external reference. Attribution per ATT&CK terms of use.
3. **`rag/owasp.py`** — OWASP Top 10 markdown from `OWASP/Top10` (pinned tag; edition to confirm live — 2021 vs 2025), fixed list of raw URLs (no directory crawling), chunked by heading (overview / description / prevention / example scenarios); id `owasp-top10:<edition>:A03:<chunk>`. Content is CC BY-SA 4.0 → keep attribution in `source`/docs.
4. **Exact-ID lookup generalised**: `extract_cves` → also ATT&CK ids (`T\d{4}(\.\d{3})?`), looked up via `store.get_many` (embeddings are poor at identifiers — same lesson as CVEs). Missing-ID message stays deterministic.
5. **`kb update` over all sources**: one new collection = union of sources. If one source fails to fetch, **carry over its records from the live collection** and flag it in the report (never drop knowledge because a download failed). `validate()` shrink check becomes per-source.
6. Tests use **fixture files, no network**: STIX sample (incl. revoked/deprecated/sub-technique), OWASP markdown sample, source-failure carry-over, ID extraction, per-source validation.

### M3c — Dataset v2 + recalibration (branch `m3c/dataset-v2`)
- Keep v1 files **immutable**; add `retrieval_attack_owasp.jsonl` (unique-name ATT&CK technique queries, OWASP category questions, seeded builder like `eval/build.py`) and `answers_v2.jsonl` (move the 12 natural questions + off-topic + security-adjacent definitions from ADR 0003 into the frozen set). `dataset_hash` already hashes all `eval/datasets/*.jsonl`, so `eval compare` warns that old and new scores differ.
- **Flip expectations deliberately and with human review**: "What is SQL injection / XSS?" should now be *grounded* by OWASP (previously a known failure); TLS-style definition questions stay a known limit unless covered.
- Re-run the M2 calibration (`calibrate`) on the realistic question groups; revisit `min_score = 0.65` (ADR 0003 said to) and record in ADR 0005. Per-source recall in the promotion gate (KEV / ATT&CK / OWASP each ≥ floor).
- Re-run full eval with the same chat model; save report; report honest deltas incl. any regression.

### M3d — Supabase pgvector backend (branch `m3d/pgvector`) — needs user actions
- `rag/pgstore.py`: `PgVectorStore` implementing the same methods as `VectorStore` (`upsert`, `search`, `get_many`, `export`, `count`, `drop`, `exists`, `view`) via `psycopg[binary]`; extract a small `Store` Protocol so `answer()`/`run_update()` are backend-agnostic.
- `db/migrations/0001_kb.sql`: `create extension vector`; `kb_docs(collection, id, text, source, url, title, meta jsonb, embedding vector(768), primary key(collection,id))`; `kb_registry` single-row table (active, previous, history jsonb) so **promote/rollback is one transaction**; RLS on, no policies. **No ANN index initially** (exact scan over a few thousand rows = perfect recall, avoids filtered-HNSW pitfalls); revisit if > ~50k rows.
- Config: `VIPER_STORE`, `VIPER_DATABASE_URL: SecretStr`; `redacted()` already masks secrets. `.env.example` documents it without a value.
- Tests: SQL logic against a throwaway local Postgres if available, otherwise unit tests with a fake connection; live check only against the user's Supabase project.
- Optional `weekly-kb-update.yml` (cron + `workflow_dispatch`, least-privilege, SHA-pinned actions, secret only in that job, installs Ollama + pulls `nomic-embed-text`, uploads the update report as an artifact, **never** runs training or active scans). Only added if the user picks the GitHub-runner scheduling option.

## User actions / approvals required (I will not do these unprompted)
- Create a **free** Supabase project and put the **session-pooler** connection string in `.env` (or approve me creating a free project via the connected Supabase tool; free tier = $0, but it is an account-level action → explicit approval first).
- Choose scheduling: laptop **Windows Task Scheduler** (I give the one command; user runs it) **or** GitHub Actions + Supabase.
- Merge the pending M2 and M3a PRs (CI on those branches is still unverified); then branch protection on `main`.

## Critical files
Modify: `src/viper/cli.py` (`cmd_kb`), `src/viper/rag/update.py` (per-source validate, carry-over), `src/viper/rag/pipeline.py` (ID extraction), `src/viper/config.py`, `src/viper/eval/{cases,runner,build}.py`, `docs/*`. New: `rag/{sources,attack,owasp,pgstore}.py`, `db/migrations/0001_kb.sql`, `tests/fixtures/*`, `eval/datasets/*_v2.jsonl`, `docs/adr/0005-*.md`, `0006-supabase-pgvector.md`.

## Verification
- Every stage: `pytest`, `ruff check`, `mypy src` green; fixture-based tests, no network in CI.
- M3b live: `viper kb update --no-promote` shows per-source counts (ATT&CK ≈ 600–700 non-revoked techniques/sub-techniques, OWASP ≈ tens of chunks), recall gate passes, then real promote → `chat "What is T1059.001?"` returns the exact record; `kb rollback` restores KEV-only.
- M3c: `eval run` before/after on the same model; `eval compare` table; SQL/XSS definition cases pass for the right reason (cited OWASP chunk), safety cases still human-reviewed, invalid-citation rate stays 0%.
- M3d: promote/rollback verified against the real Supabase project; confirm RLS blocks the anon key; confirm no secret appears in logs/`--health`.
- Update `development-progress.md`, roadmap, README; ADR for each decision; commit with the co-author trailer, push each branch, and state plainly that CI is unconfirmed until the user opens/merges the PR.

## Risks
- Large ATT&CK file (~40 MB) → size cap, one-time download, vectors reused afterwards.
- OWASP edition/licence (CC BY-SA) and ATT&CK terms → attribution kept in records and docs.
- Adding sources can lower KEV retrieval (more competing records) → per-source recall in the gate catches it.
- Citation presence remains a weak faithfulness signal; not solved here (listed in docs).
