# Loop Engineering for Viper

> "You shouldn't be prompting coding agents anymore. You should be designing loops that prompt
> your agents." — the framing behind Addy Osmani's
> [*Loop Engineering*](https://addyosmani.com/blog/loop-engineering/) (2026).

This repo already had a crew of three coding agents (claude / codex / agy) coordinating through
`.crew/board.md`, driven round-by-round by a human in the top pane. That is a loop with a human as
its engine. **Loop engineering** is the move of turning that human-driven cadence into a system
that finds the work, hands it out, checks it, and records what is done — so the human designs the
loop instead of running every turn of it.

The runnable layer lives in [`.crew/loop/`](.crew/loop/README.md). This doc is the *why*.

## Osmani's six primitives, mapped to Viper

| Primitive | Osmani | Here |
|---|---|---|
| **Automations** | scheduled discovery that triages without you | `crew-loop.ps1` with four modes; each cycle runs a discovery step that appends tasks to `queue.json`. Cadence via `-Loop`, a Scheduled Task, or `/loop`. |
| **Worktrees** | parallel agents on isolated branches so they can't collide | `crew-worktree.ps1` → `git worktree add viper-wt/<lane>__<task> -b loop/<lane>/<task>`. |
| **Skills** | `SKILL.md` so the agent doesn't re-derive the project each cycle | `.crew/loop/skills/crew-rules.md` (the durable crew RULES) + per-mode skills. Previously these rules lived only in throwaway per-round briefs; `AGENTS.md`/`CLAUDE.md` now point at them. |
| **Connectors** | MCP to real tools | existing Supabase MCP (`.mcp.json`); `gh` for PRs; **herdr** as the agent-dispatch connector (`herdr agent prompt/list/wait`). |
| **Maker / checker** | split the one who writes from the one who checks | maker lane (claude/agy) drafts via TDD; the **checker** lane (codex, never the maker) independently re-runs the gates and the real probe. |
| **State on disk** | "the agent forgets, the repo doesn't" | `board.md` (human ledger) + `queue.json` (machine) + `state.md` (append-only cycle log). |

Plus the two parts Osmani stresses are the hard ones:

- **Independent stop-judge.** `crew-judge.ps1` passes a task only when *all three* hold: gates
  green (`ruff` / `mypy` / `pytest -q vmapi\tests tests`), the checker posted `APPROVED`, and the
  per-mode verifiable condition is true. Anything else parks. "Done is a claim, not a proof."
- **Human triage inbox.** `.crew/loop/triage/` collects everything the loop can't verifiably
  finish, so full-auto never forces a bad PR.

## What "full-auto" means here (and what it must never mean)

Decisions locked for this repo: full-auto **to PR** for code work, worktree per lane, herdr as the
coordinator's dispatch backend.

Viper is a penetration-testing tool whose core invariant is that `viper.policy` — deterministic
code — decides risk and approval; LLM text can never raise risk, add a target, or self-approve. The
loop **respects that boundary rather than routing around it**:

- Code modes (`probe-dev`, `ci-triage`, `test-quality`) run full-auto and end at a PR, which is the
  review surface.
- `engagement` may auto-run **passive** steps only. Any **active** action parks for human approval
  and is never dispatched. (Verified: an active-action task reaches triage with zero dispatch.)
- Heavy execution goes to the VM / Colab execution plane, never local CPU.

## The failure modes Osmani names, and the guardrails here

- *Unverified "done"* → the stop-judge re-runs gates; the maker never grades its own homework.
- *Comprehension debt* → the PR is the read surface; triage cards summarize what parked and why.
- *Re-deriving context each cycle* → the durable `crew-rules` skill.
- *Parallel file collisions* → a worktree per lane.
- *Cognitive surrender* → the loop parks on uncertainty by default (an unimplemented condition
  returns "not done"), forcing a human to define what success means before anything ships.

## Where a human still decides

The per-mode "verifiably done" predicate (`Test-TaskCondition` in `crew-judge.ps1`) is the one
place the loop's judgment is deliberately human-authored — it decides what the full-auto loop is
allowed to ship. Until it's defined, every task safely parks.
