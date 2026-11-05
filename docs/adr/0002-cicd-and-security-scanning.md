# ADR 0002: CI/CD and security scanning
Status: Accepted (2026-11-04)

## Context
Private GitHub repo (`jellaharshith/Viper_Security`), personal budget, no `gh` CLI. CodeQL needs GitHub Advanced Security on private repos, and Windows runners cost 2x minutes.

## Decision
- CI on Linux (Python 3.12 and 3.13): ruff, mypy strict, pytest. Windows runs only on push to `main`.
- One aggregate `ci-pass` job is the single required check for branch protection.
- Security: gitleaks (full history), pip-audit, ruff bandit rules, Dependabot (pip + actions).
- All third-party actions pinned to commit SHAs with a version comment; `permissions: contents: read` by default.
- Training never runs in Actions (Colab only). No live security scans from Actions, ever.
- Workflows are added per milestone (see `implementation-roadmap.md`).

## Consequences
Cheap and private-repo friendly. No code-scanning (CodeQL) until the repo is public or has GHAS. SHA pins need Dependabot to stay current.

## Note
The remote repo's initial `LICENSE` is the Unlicense (public domain). Revisit before distributing: model licenses (e.g. Llama-derived terms) may be stricter than the project's own license.
