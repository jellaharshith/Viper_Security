---
name: loop-engagement
description: Discovery for the engagement loop mode. Advances a projects/*-h1 pentest scope — PASSIVE discovery only; active scans park for human approval.
---

# engagement discovery

Goal: advance a real authorized engagement (`projects/alsco-h1/`, `projects/crypto-h1/`,
`projects/lab-scanme/`) — **safely**.

HARD SAFETY RULE: this mode may auto-run only **passive** steps (scope parsing, drafting probe
plans, writing up already-collected evidence, report rendering). Any **active** action
(nmap/nuclei/active webapp probe via `vmapi`) is emitted as a **triage card requiring human
approval**, never dispatched by the loop. `viper.policy` will refuse unapproved active actions
anyway — the loop respects that boundary rather than fighting it.

Sources: the engagement's scope + plan files under `projects/<name>-h1/`; findings already in the
audit log awaiting write-up.

Done-condition (passive tasks only): the artifact (plan draft, findings write-up, report) is
produced, cites audit events by hash where applicable, and renders without error.

Maker: `agy` (docs/write-ups) or `claude` (report plumbing). Checker: `codex` (verifies no
active action leaked in, confirms citations resolve to real audit hashes).
