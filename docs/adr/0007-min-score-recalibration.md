# ADR 0007: `min_score` recalibration to 0.70 with three sources

Status: Accepted (2026-11-06)

## Context
ADR 0005 deferred recalibration until the index held KEV, ATT&CK and OWASP together. It now does
(live Supabase index `kb_v2p_20261106235608`, 2515 records, nomic-embed-text). Top-1 scores per group
(evidence: `eval/results/minscore-realistic-top10-2026-11-06.json`, commit `2a7cc35`):

| Group | n | min | median | max |
|---|---|---|---|---|
| grounded nat-0..11 | 12 | 0.763 | 0.856 | 0.887 |
| def-12, def-xss, general-2 (grounded) | 3 | 0.698 | 0.799 | 0.799 |
| off-domain off-0..15 | 16 | 0.477 | 0.552 | 0.612 |
| definition/adjacent (should be unverified) | 15 | 0.622 | 0.712 | 0.822 |
| safety | 4 | 0.652 | 0.683 | 0.803 |

`calibrate()` returns 0.763, which is exactly the lowest natural score: no margin, fitted on 12 positives.

## Decision
1. `Settings.min_score` goes from 0.65 to **0.70**. It keeps every natural KEV source with a 0.063 margin,
   rejects all off-domain queries, and removes roughly half of the adjacent-question noise.
2. Not tuned to 0.69: that would rescue `general-2` (top-1 0.698) by fitting one case.
   **`general-2` (XSS acronym) is a known regression**: still expected grounded, now expected to miss.
3. `def-3` (MFA, 0.802) and `def-13` (password manager, 0.822) flip to `expect_grounded: true`
   (tagged `needs-human`): their top records (T1111, T1555.005) are on topic and no cutoff separates
   them from nat-4/nat-7 anyway.
4. `def-12`, `def-xss`, `general-2` stay grounded. `def-5/7/10` are unchanged pending human review.
5. `nat-4` (Citrix Bleed) is a **known limit**. CVE-2023-4966's KEV text never says "Bleed" or
   "session hijack"; it ranks 5th (0.751) behind Citrix Session Recording CVEs. Neither top_k=5 nor a
   keyword lookup fixes this cleanly. A future task is a nickname-to-CVE alias table built from an
   *external* source, never from the eval list (that would leak the held-out test).

## Consequences
- Predicted end-to-end score 53/62 (was 51/62); to be confirmed by a full answer eval.
- `answers_v2.jsonl` changed, so its dataset hash changed; `eval compare` against older runs warns, as expected.
- Higher cutoffs (0.72-0.76) were rejected: they trade margin for matching stale expectations.
