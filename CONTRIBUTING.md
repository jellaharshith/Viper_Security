# Contributing to Viper

Thanks for helping. Viper's value is its **safety guarantees**, so changes are judged first on whether they keep them.

## Ground rules

- **Authorized testing only.** Never add code, docs or tests that scan a target you are not permitted to test. Tests
  must run fully offline: no network, no live targets, no real subprocess scans.
- **Policy is code, not prompts.** The model may propose; `viper.policy` decides. Do not give model text any path to
  permission, scope, risk level or approval.
- **Do not weaken controls** (scope, approvals, egress allowlist, audit chain, dry-run default). If a change touches
  them, say why in the pull request.
- **Never commit secrets.** `.env`, `secrets/`, tokens and keys are git-ignored; CI runs a secret scan.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt -e .
.\tasks.ps1 check        # ruff + mypy + pytest; must be green before you open a PR
```

On macOS/Linux: `source .venv/bin/activate`, then `ruff check .`, `mypy src`, `pytest -q`.

## Workflow

1. Branch from `main` (`feat/...`, `fix/...`, `docs/...`).
2. Write the failing test first, then the change (TDD). Hostile-input tests are expected for anything that parses
   tool output, model output or user input.
3. Keep changes focused; update `docs/` (and `docs/development-progress.md` for milestone work).
4. Open a pull request using the template. CI (lint, types, tests, secret scan, dependency audit) must pass.
5. Significant design choices get an ADR in `docs/adr/` (copy the style of an existing one).

## Style

- Python 3.12+, `ruff` (line length 110) and `mypy --strict` are enforced.
- Prefer small pure functions. I/O at the edges. Fail closed: an unknown input is refused, not guessed.
- Errors shown to a user print the exception **class only**, never details that could leak data.

## Reporting bugs and ideas

Use the issue templates. For security problems follow [SECURITY.md](SECURITY.md) instead.
