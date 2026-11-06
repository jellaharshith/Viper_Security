# ADR 0005: Dataset v2 and retrieval threshold recalibration plan

Status: Accepted (2026-11-06) for Dataset v2 structure; recalibration of min_score deferred until multi-source Ollama run.

## Context
M2 established the baseline evaluation harness with 130 synthetic retrieval cases and 22 end-to-end answer cases, setting a provisional `min_score = 0.65` based on nomic task prefixes (ADR 0003). As noted in ADR 0003 and `model-evaluation-plan.md`, that baseline had two key limitations:
1. The 12 realistic KEV questions used for threshold selection were hand-written and not part of the frozen dataset.
2. Security-adjacent definition questions (e.g., SQL injection, XSS) were misclassified as UNVERIFIED or pulled unrelated KEV CVEs because KEV lacks definitions.

With M3 introducing MITRE ATT&CK (Enterprise techniques) and OWASP Top 10 (category chunks), definitions are now indexed in the KB. The evaluation dataset must expand (Dataset v2) to measure multi-source retrieval and verify definition grounding, and the promotion gate must enforce per-source recall.

## Decisions

### 1. Frozen Dataset v2 structure
- **Immutability of v1**: `eval/datasets/retrieval.jsonl` and `answers.jsonl` are pinned and immutable (SHA-256 pinned in tests) to preserve baseline comparisons.
- **`eval/datasets/retrieval_attack_owasp.jsonl`**: Added held-out retrieval cases targeting MITRE ATT&CK techniques (title, description, tactic/platform hint) and OWASP Top 10 chunks (category, description, prevention, scenarios), plus negative calibration queries.
- **`eval/datasets/answers_v2.jsonl`**: Expands the frozen answer set to 62 cases by incorporating:
  - The 12 natural KEV questions from ADR 0003 (Log4j, EternalBlue, ProxyLogon, Citrix Bleed, MOVEit, Confluence, etc.).
  - The 16 off-topic queries from ADR 0003 (`expect_grounded: false`, `expect_unverified: true`).
  - The 14 security-adjacent definition queries from ADR 0003.
  - The v1 baseline fact, missing CVE, JSON, and safety cases.

### 2. Deliberate Expectation Flips (Human Review Required)
In v1, general definition questions were expected to be UNVERIFIED because KEV contains no definition knowledge. With OWASP indexed, definition questions covering OWASP topics must now be grounded:
- **"What is a SQL injection?"** (`def-12`): Flipped from ungrounded/unverified to `expect_grounded: true`. Grounded by OWASP Top 10 Injection chunk (`owasp-top10:2025:A05:overview` / `description`).
- **"What does the acronym XSS stand for?"** (`general-2`): Flipped from `expect_unverified: true` to `expect_grounded: true`. Grounded by OWASP Injection chunk.
- **"What is cross-site scripting (XSS)?"** (`def-xss`): Flipped from ungrounded to `expect_grounded: true`. Grounded by OWASP Injection chunk.
- Each flipped case is explicitly tagged with `"review": "needs-human"` in `answers_v2.jsonl` and surfaced in evaluation reports under `needs_human_review`.
- General networking and protocol definitions not covered by KEV, ATT&CK, or OWASP (e.g. TCP vs UDP, HTTPS/TLS) remain `expect_unverified: true` as documented boundaries of the local KB.

### 3. Recalibration Plan for `min_score` (Deferred)
- **`min_score = 0.65` remains unchanged in code.** Speculative adjustment without live embeddings from all three feeds risks breaking recall or admitting noise.
- **Recalibration trigger and procedure**:
  1. Once Lane A (`m3b/attack-owasp`) ingests live ATT&CK and OWASP data into a versioned Qdrant/pgvector collection (~1,768 KEV + ~700 ATT&CK + ~40 OWASP chunks), run:
     `python -m viper.cli eval run --tag recalibration-v2 --skip-llm`
  2. Use `viper.eval.retrieval.calibrate` on the combined positive retrieval set (KEV + ATT&CK + OWASP) against the negative query set.
  3. Re-evaluate the score distribution across the 12 natural KEV queries, 16 off-topic queries, and 14 definitions.
  4. If the separating threshold between realistic queries and negatives has shifted due to increased index density, update `Settings.min_score` in `.env` and record the empirical distribution in a subsequent ADR.

### 4. Per-Source Recall Quality Gate
- In addition to structural validation (non-empty, HTTPS URLs, max shrink), the promotion gate (`run_update`) must verify recall@4 independently for each indexed knowledge source:
  - `cisa-kev`: recall@4 >= 0.95 (and regression <= 0.02 against active collection)
  - `mitre-attack`: recall@4 >= 0.95
  - `owasp-top10`: recall@4 >= 0.95
- A drop in one source's recall cannot be masked by high recall in another.

## Consequences / Limits
- `dataset_hash` covers all `eval/datasets/*.jsonl` files. Adding `retrieval_attack_owasp.jsonl` and `answers_v2.jsonl` changes the fingerprint, causing `viper eval compare` to correctly warn that datasets differ.
- Full end-to-end evaluation on `answers_v2` requires local Ollama inference (~15–20 min on CPU for 62 cases).
- Human review is required to approve flipped expectations before CI gates enforce 100% pass rate on them.
