# ADR 0004: Gated, versioned knowledge-base updates

Status: Accepted (2026-11-05)

## Context
The knowledge base must refresh weekly without a human watching, and a bad feed (truncated download, schema change,
embedding drift) must never degrade answers. Fine-tuning is unrelated and never runs automatically.

## Decision
- Every update builds a **new versioned collection** (`kb_<ver>_<timestamp>`) beside the live one. The live collection
  is never modified in place.
- A tiny **registry file** (`data/kb_registry.json`) names the live collection. Promotion and rollback are an atomic
  file swap (`os.replace`), so readers see the old or the new pointer, never a partial one.
- Gates, all in code: (1) structural validation (non-empty, unique ids, https urls, feed not >10% smaller than live);
  (2) retrieval recall@4 on the **frozen M2 dataset** must be >= 0.95 and no worse than live by more than 0.02.
  Failure drops the staged collection and leaves the live one untouched.
- Unchanged records (same content hash) reuse their stored vector, so a weekly run embeds only what changed.
- Commands: `viper kb update [--no-promote]`, `viper kb status`, `viper kb rollback`. Reports go to `data/kb_reports/`.

## Consequences / limits
- Verified live: dry run (1768 reused, 0 embedded, recall@4 0.99), real promote, rollback, chat still correct.
- The gate only measures retrieval on KEV-derived questions. When new sources (ATT&CK, OWASP, NVD) are added, the frozen
  dataset must grow (dataset v2) or the gate will not notice regressions there.
- Embedded Qdrant allows one client per folder: update and chat cannot run at the same time.
- **Automated weekly via GitHub Actions (`.github/workflows/kb-weekly.yml`):**
  The update is automated on a weekly schedule (`cron`) and via `workflow_dispatch` using the Supabase
  (`VIPER_STORE=supabase`) backend.
  - **Why Supabase makes a stateless runner safe:** In the local Qdrant backend, the live collection pointer
    and vector store require persistent local disk storage. With Supabase (`pgvector`), the active collection
    pointer resides directly in the database (`kb_registry` table), and all document vectors are stored remotely
    in versioned database tables. The GitHub-hosted runner is completely stateless: it only needs to run an ephemeral
    Ollama instance to compute embeddings for new or modified records and evaluate the retrieval quality gate
    (`recall@4 >= 0.95`). When gates pass, promotion updates the live pointer in the database atomically.
    When gates fail, the staged collection is dropped and the database pointer remains unchanged. Even though
    the runner container is destroyed immediately after execution, no persistent state is lost.
  - If `SUPABASE_URL` or `SUPABASE_SECRET_KEY` are not configured in repository secrets, the workflow logs a notice
    and exits cleanly (green) without running the update. Failed gates exit with code 2 and visibly fail the CI run,
    while update reports (`data/kb_reports/**`) are uploaded as artifacts for inspection.
