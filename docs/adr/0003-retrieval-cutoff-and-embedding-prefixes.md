# ADR 0003: Embedding prefixes and similarity cutoff

Status: Accepted (2026-11-05), revisit when more sources are indexed.

## Context
M1 shipped `min_score = 0.55` without evidence. The M2 baseline (`eval/results/baseline-fsec-1-1-minscore-0-55-*.json`)
showed general-knowledge questions being labelled "grounded" because unrelated KEV records scored above 0.55, and one
answer cited an unrelated CVE as support for a TLS claim.

## Evidence
1. A cutoff calibrated on synthetic queries (built from the records' own text) was 0.717 with "perfect" separation.
   Realistic natural-language questions scored lower: 4 of 12 legitimate questions fell below 0.717
   (lowest 0.566, a correct Log4j match). The synthetic calibration was **optimistic and rejected**.
2. `nomic-embed-text` expects `search_query:` / `search_document:` prefixes. With them: recall@4 97% -> 99%,
   but every score rose, including irrelevant ones (highest negative 0.705 -> 0.752). The prefix helps recall; it does not
   by itself separate relevant from irrelevant.
3. On the prefixed index, by question group:

| cutoff | realistic KEV questions kept (of 12) | off-topic rejected (of 16) | security-adjacent definitions rejected (of 14) |
|---|---|---|---|
| 0.60 | 12 | 15 | 3 |
| 0.65 | 12 | 16 | 7 |
| 0.70 | 10 | 16 | 12 |
| 0.75 | 9 | 16 | 12 |
| 0.78 | 6 | 16 | 14 |

## Decision
- Use task prefixes (index version `v2p`).
- Set `min_score = 0.65`: keeps every realistic question, rejects all clearly off-topic ones.
- Named CVE ids bypass the cutoff entirely (exact-id lookup added in M1).

## Consequences / limits
- Security-adjacent *definition* questions ("What is a SQL injection?") are still often matched to KEV records.
  Cosine similarity measures topical closeness, not whether the KB can answer. Expected to improve once OWASP and
  MITRE ATT&CK (which contain definitions) are indexed; re-calibrate then.
- The realistic-question set is small (n=12, hand-written). Treat 0.65 as provisional; grow the set in M3.
- Changing `kb_version` or prefixes requires re-indexing; the old `v1` collection is kept for rollback.
