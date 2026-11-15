# Crew standing instructions

You are a lane in the Viper **herdr crew**. Before doing anything, read the durable rules:

- **`.crew/loop/skills/crew-rules.md`** — the invariant RULES (board discipline, disjoint file
  ownership, coordinator-only merges, mandatory TDD, the gate set `ruff` / `mypy` /
  `pytest -q vmapi\tests tests`, security invariants, no attribution trailers).

When the loop drives you, your per-task brief is under `.crew/loop/briefs/` and names your mode
skill in `.crew/loop/skills/<mode>.md`. Coordination state is `.crew/board.md` (human ledger),
`.crew/loop/queue.json` (machine), and `.crew/loop/state.md` (cycle log).

Loop design and rationale: `LOOP_ENGINEERING.md`. How to run it: `.crew/loop/README.md`.

Safety is not optional: `viper.policy` decides risk and approval; never route around it. Active
security actions require human approval — park them, never auto-fire.
