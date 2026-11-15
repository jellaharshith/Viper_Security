---
name: loop-ci-triage
description: Discovery for the ci-triage loop mode. Osmani's canonical morning automation — scans CI/test failures and open issues, drafts fixes.
---

# ci-triage discovery

Goal: turn red CI and failing tests into reviewed fix PRs.

Sources:
1. Latest CI run on `main` (`gh run list --branch main`, `gh run view <id> --log-failed`).
2. Local gate failures: `.\tasks.ps1 check` output (ruff / mypy / pytest).
3. Failing or skipped tests from `pytest -q vmapi\tests tests` (parse the summary).
4. Open issues labelled `bug`.

Each task targets the **narrowest** owned files that fix one failure. Done-condition: the
previously-failing gate/test is GREEN and no other test regressed. Failures the loop cannot
localize to a small owned set → triage card (human decides scope).

Maker: `claude` (surgical fix, TDD the regression). Checker: `codex` (re-runs the full gate set
in the lane worktree, confirms no collateral breakage).
