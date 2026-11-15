# `.crew/loop` — the herdr crew loop

Loop engineering for Viper: a runnable layer that automates the coordinator role a human used to
play in the top pane. It drives the three crew agents (claude / codex / agy) through **herdr**
across four modes, isolates each lane in a **git worktree**, verifies with an **independent
stop-judge**, opens PRs full-auto for code work, and parks anything unverifiable — or any
approval-required active security action — in a **triage inbox**.

Design rationale and the Addy Osmani mapping: see `../../LOOP_ENGINEERING.md`.

## Run it

```powershell
# one dry cycle (no git/dispatch/PR side effects) — safe to try anytime
.\.crew\loop\crew-loop.ps1 -Mode test-quality -Once -DryRun

# a real single cycle for one mode
.\.crew\loop\crew-loop.ps1 -Mode ci-triage -Once

# continuous, every 30 min
.\.crew\loop\crew-loop.ps1 -Mode ci-triage -Loop -IntervalMinutes 30
```

Modes: `probe-dev` | `ci-triage` | `engagement` | `test-quality`.
Cadence can also come from a Windows Scheduled Task or `/loop 30m .\.crew\loop\crew-loop.ps1 -Mode ci-triage`.

## Pieces

| File | Role |
|---|---|
| `crew-loop.ps1`      | the runner: discover → worktree → brief → dispatch → judge → PR/triage → state |
| `crew-dispatch.ps1`  | dispatch adapter (herdr → wezterm → tmux → manual; `noop` for tests). `-Probe`, `-ListAgents` |
| `crew-worktree.ps1`  | `git worktree` per lane (`viper-wt/<lane>__<task>` on `loop/<lane>/<task>`) |
| `crew-judge.ps1`     | the stop-judge: gates **and** checker verdict **and** per-mode condition |
| `crew-pr.ps1`        | pushes the branch + `gh pr create`; refuses attribution footers |
| `discover/<mode>.ps1`| per-mode discovery → task records |
| `skills/crew-rules.md` | the durable crew RULES (what per-round briefs used to re-derive) |
| `skills/<mode>.md`   | per-mode discovery guidance |
| `skills/herdr-reference.md` | vendored `herdr --skill` (the dispatch backend's contract) |
| `queue.json` / `state.md` | machine + human state (append-only, like `board.md`) |
| `briefs/` (gitignored) | generated per-task briefs |
| `triage/`            | the human inbox (committed) |
| `tests/run-tests.ps1`| portable assertion suite (no Pester needed) |

## The herdr seam

Dispatch auto-probes a backend (`crew-dispatch.ps1 -Probe`). On this machine it resolves to
**herdr** and uses `herdr agent prompt <pane|name> <msg> --wait`. Live agents are discovered via
`herdr agent list` (`crew-dispatch.ps1 -ListAgents`) — `../panes.txt` is only a hint and goes stale
between sessions. If a required agent isn't live, the task parks instead of firing into a dead pane.

## Safety

- `viper.policy` is authoritative. The loop never overrides it. **Active** security actions
  (nmap/nuclei/active probes via `vmapi`) are parked for human approval, never auto-fired.
- Full-auto applies to **code work only** (probe-dev / ci-triage / test-quality end at a PR).
- "Done is a claim, not a proof": the stop-judge re-runs gates independently; the checker lane
  (codex) is never the maker.
- No attribution trailers on commits/PRs (`crew-pr.ps1` enforces this mechanically).
