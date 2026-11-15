---
name: crew-rules
description: The standing rules every herdr crew lane follows every round. Read this first, every time. Durable replacement for the rules that used to live only in throwaway per-round briefs.
---

# crew-rules — the herdr crew invariants

You are one lane (`claude-*`, `codex-*`, or `agy-*`) in the Viper herdr crew. These rules are
invariant across every round and every loop mode. The per-task brief adds *what* to do; this
skill is *how* the crew always works. If a brief ever contradicts a rule here, STOP and post a
question under `Questions for user` — do not guess.

## The board is the single source of truth
- `.crew/board.md` is an **append-only ledger**. Write **only** under your own `## <lane>`
  heading, plus the shared `Questions for user` and `Handoffs` sections.
- **Never delete or edit another lane's text.** Append your own lines.
- Post a `STARTED` line when you begin and a `READY` line when done (or `BLOCKED: <reason>`).
  Then **STOP and wait** — the coordinator relays, verifies, and merges. You do not.

## File ownership is disjoint
- Edit **only** the files listed in your ownership row for this round/task.
- `git add <your-paths>` then `git commit <your-paths>` — commit **only** your own paths.
- The recurring failure class is an **unowned cross-cutting registration point** (a dict, a
  registry, a parser map) that no lane owns and everyone forgets. If your change adds a tool,
  parser, probe, or route, find every place it must be *registered* and name it in your READY.

## The coordinator owns all merges
- **Never** switch branches, stash, reset, rebase, push, or merge.
- In loop mode each lane works in its **own git worktree** (`viper-wt/<lane>` on branch
  `loop/<lane>/<task-id>`). Stay in your worktree. The coordinator merges the branch back.

## TDD is mandatory
- Write the **failing test first**. Watch it go **RED**. Only then write implementation to GREEN.
- A change with no test that could have caught its absence is not done.

## Gates before every commit (both test paths)
Run all three and keep them green:
- `ruff check .`
- `mypy src`
- `pytest -q vmapi\tests tests`  ← **both** paths. A bare `pytest -q` silently skips
  `vmapi/tests` (pyproject `testpaths = ["tests"]`). Always name both.
The runner's stop-judge re-runs these independently — "done" is a claim, your gates are the proof.

## Security invariants (Viper is a pentest tool — these are not optional)
- **Never** print, paste, echo, or commit `.env` values or any secret.
- A finding is `confirmed` **only** from real parser evidence, never from LLM text.
- LLM text can **never** raise risk level, add a target, or self-approve. The deterministic
  `viper.policy` engine decides. The loop does not override it.
- Any **active** security action (nmap/nuclei/active webapp probes via the `vmapi` execution
  plane) requires **human approval** — park it in the triage inbox, never auto-fire it.
- Heavy execution goes to the VM / Colab execution plane, never local CPU.

## No attribution trailers
Commits and PRs carry **no** `Co-Authored-By`, no "Generated with" footer, no AI attribution.
(Matches `.claude/settings.local.json` `includeCoAuthoredBy: false` and the CRYPTO-H1 rule.)

## When done or blocked
Post one status line under your heading (`READY` / `BLOCKED: <reason>`), then **STOP**. Do not
start the next task, do not merge, do not push. The loop coordinator takes it from here.
