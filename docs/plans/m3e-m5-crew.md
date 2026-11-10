# Plan — M3e close-out + M5 spec, run by a three-agent herdr crew

Saved 2026-11-06. Base branch for every lane: `m3/integration` @ `cccde34` (PR #9).

## Context
M3 (ATT&CK + OWASP sources, dataset v2, Supabase backend) is built and mostly verified live. Still open:
`min_score` too permissive with three sources, `nat-4` (Citrix Bleed) retrieval miss, flipped eval expectations
needing human review, the direct-Postgres store (`VIPER_STORE=pgvector`) never run against a real DB, and GitHub CI
on PR #9 unconfirmed (`gh` is not installed locally). Decision: two agents finish M3, a third writes the M5 spec in parallel.

## Crew setup
- herdr 0.9.5. Layout: coordinator (lead agent) full-width on top; three agents in bottom columns (~85 cols each).
- Every agent runs **by-permission** (default approval mode, no bypass and no auto mode); the user approves in each pane.
- Comms: shared board `C:\Users\STSC\Desktop\viper-wt\coord\board.md` (outside every repo) + coordinator relay with
  `herdr agent prompt <name> ... --wait`. Briefs: `coord\brief-{lane-A-m3,lane-B-m3,lane-C-m5}.md`.
- Send prompts from Bash (`herdr agent prompt <name> "$(cat brief.md)"`). PowerShell 5.1 mangles embedded quotes.
- Rules: agents write only under their own board heading + Questions/Handoffs; never push, merge, or print `.env` values;
  commit locally with a co-author trailer; stop and post when done or blocked.

| herdr name | Kind | Worktree · branch | Work |
|---|---|---|---|
| (coordinator) | lead | main repo | layout, relay, merge lanes into `m3/integration`, final verification |
| `lane-A-m3` | agent A | `viper-wt/m3e-recal` · `m3e/recalibrate` | `min_score` recalibration + ADR 0007; `nat-4` |
| `lane-B-m3` | agent B | `viper-wt/m3e-pg` · `m3e/pgvector-ci` | `rag/pgstore.py` fake-connection hardening; local CI; cross-review |
| `lane-C-m5` | agent C | `viper-wt/m5-spec` · `m5/spec` | Docs only: `docs/plans/m5-agents-policy.md` + ADR 0008 (Proposed) |

`.env` copied (git-ignored) into `m3e-recal` and `m3e-pg` only. Tests use the main venv:
`C:\Users\STSC\Desktop\Viper\.venv\Scripts\python -m pytest -q` (pytest `pythonpath=["src"]`).

## User decisions (2026-11-06)
- **`min_score = 0.70`** (from 0.65). Do not tune it to 0.69: `general-2` (XSS acronym, top-1 0.698) becomes a known
  regression recorded in ADR 0007. Evidence: per-group top-1 scores in commit `2a7cc35`
  (`eval/results/minscore-realistic-top10-2026-11-06.json`): nat 0.763–0.887, off-domain 0.477–0.612,
  adjacent 0.622–0.822. Predicted 53/62 (was 51/62).
- **`nat-4` → option (c), known limit.** Root cause: the KEV text for CVE-2023-4966 never says "Bleed" or "session
  hijack"; it ranks 5th (0.751), outranked by Citrix *Session Recording* CVEs. A future task is a nickname→CVE alias
  table built from an **external** source (not the eval list, which would leak the held-out test).
- Expectations: keep `def-12`, `def-xss`, `general-2` **grounded**; **flip `def-3` (MFA) and `def-13` (password manager)
  to grounded**; `def-5/7/10` → lane-A-m3 **proposes with evidence**, and the user decides case by case.

## Status at save time
- Agent panes **closed** (w1:p8, w1:p9, w1:pA no longer exist). Worktrees and the board are intact.
- `lane-A-m3`: evidence commit `2a7cc35` only; the user's decisions were **not yet delivered** (the relay prompt
  stalled while that pane was in `/auto-mode-setup`). No code changed yet.
- `lane-B-m3`: **uncommitted, unreviewed** work in `m3e-pg`: `rag/pgstore.py` (71 lines changed),
  `tests/test_pgstore.py` (128 lines changed; 173+/32− across 3 files), ADR 0006 (driver diagnostics omitted on query/commit/rollback failures; registry
  closes an owned connection on failed initial refresh). The local CI result has not been reported yet.
- `lane-C-m5`: started reading; **no files written** in `m5-spec`.

## To-do
- [x] Create worktrees `m3e-recal`, `m3e-pg`, `m5-spec` off `m3/integration`
- [x] Create board + briefs; split panes; start the three agents
- [x] lane-A-m3: live score distributions + nat-4 root cause (`2a7cc35`)
- [x] User checkpoint: cutoff, nat-4, expectation flips
- [ ] Restart the crew (same layout, by-permission) and resend the briefs
- [ ] lane-A-m3: apply decisions (min_score 0.70, flip def-3/13), ADR 0007 (distribution, general-2 regression,
      nat-4 known limit, dataset-hash change), retrieval-only eval, pytest/ruff/mypy, commit
- [ ] lane-A-m3: propose def-5/7/10 flips with cited record ids + scores → **user decides**
- [ ] lane-B-m3: finish + commit the pgstore hardening; report local CI (ruff, mypy, pytest as in `ci.yml`)
- [ ] lane-B-m3: cross-review `m3e/recalibrate`; lane-A-m3 fixes findings
- [ ] lane-C-m5: M5 spec + ADR 0008 draft (graph/state, deny-by-default policy, approval interrupts, append-only audit
      log, no live targets, PR-sized steps, verified LangGraph API citations)
- [ ] lane-B-m3: security/policy review of the M5 spec; lane-C-m5 revises
- [ ] Coordinator: merge `m3e/recalibrate` + `m3e/pgvector-ci` into `m3/integration`; pytest/ruff/mypy green; live
      retrieval eval (recall@4 ≥ 0.948, KEV ≥ 0.99, invalid citations 0%)
- [ ] Update `development-progress.md` + roadmap; push only with the user's OK
- [ ] User: confirm CI on PR #9 (or install `gh`); optionally add `VIPER_DATABASE_URL` for a live pgvector run
- [ ] Optional: full v2 answer eval (Colab notebook) with the new cutoff
- [ ] Later task: nickname→CVE alias table from an external source

## Restart recipe
```bash
herdr pane split --current --direction down --cwd C:/Users/STSC/Desktop/viper-wt/m3e-recal --no-focus   # → A
herdr pane split --pane A --direction right --cwd C:/Users/STSC/Desktop/viper-wt/m3e-pg --no-focus      # → B
herdr pane split --pane B --direction right --cwd C:/Users/STSC/Desktop/viper-wt/m5-spec --no-focus     # → C
herdr pane resize --pane A --direction left --amount 0.17
herdr agent start lane-A-m3 --kind claude --pane A ; herdr agent start lane-B-m3 --kind codex --pane B ; herdr agent start lane-C-m5 --kind agy --pane C
```
Startup gotchas seen: Codex update offer and SessionStart hook review (`~\.codex\hooks.json`), agy folder trust.
agy loses its herdr name after the trust prompt (`herdr agent rename <pane> lane-C-m5`); herdr can show agy as idle
while it works, so read the pane before assuming it's stalled.
