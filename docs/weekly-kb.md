# Weekly Knowledge Base Refresh — Owner Guide

This 60-second guide explains how to enable and operate the automated weekly knowledge-base update for Viper.

---

## Overview

Viper maintains a cybersecurity knowledge base (CISA KEV, MITRE ATT&CK Enterprise techniques, OWASP Top 10) in a remote Supabase PostgreSQL database using `pgvector`.

The GitHub Actions workflow [`.github/workflows/kb-weekly.yml`](../.github/workflows/kb-weekly.yml) automatically checks for new records, embeds them using `nomic-embed-text` on an ephemeral Ollama runner, evaluates retrieval quality gates on the frozen dataset, and atomically promotes the updated collection if all gates pass.

---

## 1. Adding Repository Secrets

To enable the workflow, configure two repository secrets in GitHub:

1. Navigate to your GitHub repository: **Settings** -> **Secrets and variables** -> **Actions**.
2. Click **New repository secret**.
3. Add the following two secrets (exact names, matching your local `.env` file without a `VIPER_` prefix):
   - `SUPABASE_URL`: Your Supabase project URL (e.g., `https://xyzcompany.supabase.co`).
   - `SUPABASE_SECRET_KEY`: Your Supabase service role secret key.

> [!NOTE]
> `SUPABASE_URL` and `SUPABASE_SECRET_KEY` have no `VIPER_` prefix. These are the exact environment variable names read by `viper.config.Settings` and `viper.rag.reststore`.

---

## 2. Running the Workflow Manually

In addition to running automatically every Monday at 03:00 UTC, the workflow can be triggered on demand via `workflow_dispatch`:

1. In GitHub, go to the **Actions** tab.
2. In the left workflow list, select **Weekly Knowledge Base Update**.
3. Click the **Run workflow** dropdown on the right.
4. Select the branch (`main`) and click **Run workflow**.

---

## 3. Interpreting Workflow Run Outcomes

| Status | Outcome | What It Means |
|---|---|---|
| **Green** (Success) | `PROMOTED` | Secrets exist, new/changed records were embedded, retrieval quality gates cleared (`recall@4 >= 0.95`, regression <= 0.02), and the database pointer in `kb_registry` was atomically updated to the new collection. |
| **Green** (Notice / Skipped) | Skipped cleanly | `SUPABASE_URL` or `SUPABASE_SECRET_KEY` are not configured in repository secrets. The first step prints an informational notice and exits successfully with code 0 so CI is never red before you add credentials. |
| **Red** (Failure) | `REJECTED` | A quality gate failed (feed structural error, recall dropped below 0.95 floor, or recall regressed > 0.02 against active collection). The command exits with **exit code 2**, visibly failing the job. **The live index in Supabase remains untouched**; the staged collection was automatically dropped. |

---

## 4. Downloading the Update Report

Every run that executes `viper kb update` uploads an inspection artifact regardless of success or failure:

1. Click on the completed workflow run in the **Actions** tab.
2. Scroll to the **Artifacts** section at the bottom of the Summary page.
3. Download the **`kb-reports`** zip archive.

The archive contains JSON reports from `data/kb_reports/<timestamp>-<sources>.json` detailing:
- `active_before` and `staged` collection identifiers.
- Record counts: `fetched`, `reused` (content hash match, no re-embedding), `embedded`, and `removed`.
- Per-source record counts and any carried-over sources.
- Retrieval metrics: `recall_at_4_active` vs. `recall_at_4_staged`.
- Final decision (`PROMOTED` or `REJECTED: ...`) and any encountered problems.
