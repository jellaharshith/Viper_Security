---
name: loop-probe-dev
description: Discovery for the probe-dev loop mode. Finds the next security-probe / tool-development task to hand the crew.
---

# probe-dev discovery

Goal: drive the v1.2 backlog and open probe work to completion as PRs.

Sources, in priority order:
1. `docs/v1-scope.md` §3 (v1.2 backlog) — unstarted items (ZAP integration, expanded nuclei
   profile, per-run scanner metrics, etc.).
2. `CHANGELOG.md` `[Unreleased]` — items started but lacking tests or a parser/registration.
3. Open GitHub issues labelled `probe` or `tool` (`gh issue list`).

Each discovered task MUST specify: the owned file paths, the registration points that must be
updated (parser map in `src/viper/agents/evidence.py`, `_PARSERS`, tool registry in
`src/viper/tools/registry.py`), and a **verifiable done-condition** (new tests pass AND the
probe fires against a lab target). A task missing a verifiable condition is not emitted — it
goes to triage for a human to sharpen.

Maker: `agy` or `claude` (TDD the parser + probe). Checker: `codex` (runs the real probe, audits
the registration points — this is exactly the class that silently broke in CRYPTO-H1).
