# Crypto.com HackerOne engagement — round 1

Status: **round 1 complete, write-up final.** Scope: `projects/crypto-h1/crypto-h1.scope.yaml`
(revision `dfd1eadac3dc`, supersedes `crypto-h1.scope.v1.yaml`/`f8b6de203f54` — `pay.crypto.com`
was added mid-round, see "What blocked/expanded recon" below).

## Question

Can Viper, built out with two new detection-only tools by a three-agent `herdr` crew and
independently re-verified by the coordinator, run a real, MITRE-ATT&CK-framed assessment against
a live, high-stakes HackerOne program (Crypto.com: $1,000,000 top bounty, real user funds, 24
assets across 5 tiers) while staying strictly inside a deliberately narrow, non-account,
non-fund-touching scope?

## Program & scope

- Program: `hackerone.com/crypto`. Signal requirement: -1.0 or higher (trial reports used below
  it, same mechanism as ALSCO).
- **Round 1 scope: 13 non-account-requiring hosts.** The 12 from the Low Bounty Tier and
  non-account Extreme-Not-Eligible tier (`js.crypto.com`, `developer.crypto.com`,
  `developer-api.crypto.com`, `developer-platform-api.crypto.com`, `travel.crypto.com`,
  `tickets.crypto.com`, `tax.crypto.com`, `experiences.crypto.com`, `web.crypto.com`, `og.com`,
  `nadex.com`, `merchant.crypto.com`), plus `pay.crypto.com` (added mid-round, narrowly — see
  below).
- **Deliberately excluded this round:** every account-requiring asset (the two "requires an
  account" Extreme-tier APIs, authenticated `crypto.com/exchange` flows — no KYC/login ever
  performed), both smart-contract assets (need Slither/Mythril-class tooling Viper doesn't have),
  both mobile apps (need APK/IPA tooling), and every program-excluded asset (wallet
  extension/app, GitHub source repos).
- Hard rules enforced throughout: no fund movement of any kind, no DoS, no user/staff targeting,
  no credential brute-forcing. `projects/crypto-h1/crypto-h1.draft.yaml`'s `ambiguities` records
  the full reasoning.

## Build (herdr crew, same model as the v1.1 feature round)

Three panes (`claude-crypto`, `codex-crypto`, `agy-crypto`) split disjoint work per
`.crew/board.md`'s "CRYPTO-H1 ROUND 1" section: two new tools (`secret_scan`,
`graphql_introspect`) built TDD/offline by `claude-crypto`; findings-parser wiring, `evidence.py`
registration, and deploy-script updates by `codex-crypto` (both deliberately briefed on the two
bug classes that broke silently in the ALSCO round — a parser never wired into `_PARSERS`, and a
deploy script that never learned about a new file — so they wouldn't recur unnoticed); the scope
draft, ATT&CK-mapped test plan (`docs/crypto-h1-plan.md`), and ADR 0013 by `agy-crypto`. All
three posted READY with gates green; the coordinator independently re-ran the full suite rather
than trusting the reports.

**That independent re-verification caught a real gap anyway**, same root cause as the known
bug classes: `scope_draft.py`'s `_TECHNIQUE_ALIASES` table was never updated for the two new
technique slugs. Every known technique needs a self-mapping alias entry or the scope *loader*
silently drops it from `permitted_techniques` — this would have made both new tools permanently
DENIED despite the scope file listing them correctly. Fixed (TDD, commit `c35d645`); nobody owned
this file in the brief, same pattern as `findings/models.py`'s `SourceTool`, which `codex-crypto`
itself caught and was authorized to fix mid-task.

## Methodology — MITRE ATT&CK mapping

| Phase | ATT&CK technique | Viper mechanism |
|---|---|---|
| Reconnaissance | T1595.002, T1596 | nmap service detection, nuclei `tech,misconfig` |
| Initial Access (detection only) | T1190 | `injection_probe` against a real discovered parameter |
| Discovery | T1518, T1087-adjacent | nuclei tech fingerprinting, `graphql_introspect` |
| Credential Access (read-only detection) | T1552.001 | `secret_scan` on public JS bundles |
| Exfiltration | — | never performed |

## Results

### Recon (all 12 original hosts, nmap + nuclei)

25 findings across 4 batched runs (`crypto-recon-1..4`), **all info-severity**: open ports
everywhere (expected), WAF detection (Cloudflare/CloudFront) on 6 of 12 hosts, missing
Subresource Integrity on `tax.crypto.com`, cookies without `HttpOnly`/`Secure` on
`experiences.crypto.com`. `developer.crypto.com`/`developer-api.crypto.com`/
`developer-platform-api.crypto.com` returned nothing on 80/443 — likely pure API-gateway
endpoints, not directly reachable this way.

**Lesson relearned:** the 15-minute approval-to-dispatch window applies to the *whole batch*
from the single pause moment, not per action. A 24-action plan (12 hosts × nmap+nuclei) only got
12 in before the back half expired (`crypto-recon-1`); batching at ~3 hosts (6 actions) stayed
inside the window every time after.

### Secret scanning (`secret_scan`, new this round)

Ran against the two real JS files `tax.crypto.com`'s own missing-SRI finding exposed
(`/gt.c62751d0.js`, `/src.6e507d4a.js`). **Found a real bug in the new tool via this live use,
not synthetic testing:** both files produced a HIGH-severity "exposed JWT" finding. Verified by
fetching the same public files directly and finding the exact matched text — both were false
positives: `geetest_holder.geetest_wind.geetest_fallback` (a GeeTest captcha library's own
property-access chain) and `swRegistration.pushManager.getSubscription` (the Push API). The old
regex matched any three dot-separated alphanumeric segments — exactly the shape of ordinary
minified-JS property access. Fixed (commit `7cf4a5f`) by requiring the real JWT header prefix
(`eyJ`, base64url of `{"`, the standard JWT-detection heuristic). Re-ran live after redeploy:
correctly 0 findings.

### GraphQL introspection (`graphql_introspect`, new this round)

`merchant.crypto.com` is a React SPA that serves an identical catch-all response for *every*
path — including a fake-looking `/graphql` — so its real GraphQL backend had to be found by
reading its own JS bundle (`/static/js/main.a1bb00b3.js`), which referenced
`https://pay.crypto.com/graphql`. That host wasn't in the original scope; added deliberately and
narrowly (new scope revision `dfd1eadac3dc`, `pay.crypto.com` permitted only
`port-scan`/`service-detection`/`passive-scan`/`graphql-introspection` — no injection-test or
secret-scan, given it's a payment subdomain). **Result: introspection is correctly disabled** —
a real 200 JSON response with no `data.__schema` key. Good security practice, not a finding.

### Injection testing (`injection_probe`, reused from ALSCO)

Found a real, confirmed query-parameter surface via recon: `tickets.crypto.com`'s
`/browse/{slug}?type=category&id=N&name=X` event-search feature (discovered by grepping its own
homepage HTML, not guessed). Ran `sqli_boolean` and `xss_reflected_marker` against both `id` and
`name`. Both SQLi probes were WAF-blocked (CloudFront 403) — reported as unconfirmed hypotheses
only, per the parser's design (a single-shot probe never auto-confirms SQLi). Neither XSS probe
showed a reflected-marker signal.

## Defects found and fixed during this round

1. **`scope_draft.py`'s technique-alias table never updated for the two new slugs** — would have
   silently denied both new tools despite a correctly-written scope file. Commit `c35d645`.
2. **`secret_scan`'s JWT regex matched ordinary JS property-access chains** — a real false
   positive found by running the tool against real content, not a synthetic test gap. Commit
   `7cf4a5f`.
3. A transient `RemoteJobError` on one nuclei dispatch (`og.com`) — retried clean on a fresh
   thread; the VM stayed healthy throughout, so this looks like a one-off network blip, not a
   repeatable bug.

## Audit trail

`data/audit/crypto-h1.jsonl` covers scope approval (both revisions) and 8 threads
(`crypto-recon-1..4`, `crypto-secrets-1..2`, `crypto-graphql-1`, `crypto-inj-1`). Reports for each
are in `data/reports/crypto-*.{md,json,sarif}`.

## Verdict / recommendation

Safety properties held: every dispatched action targeted an explicitly in-scope host under its
own narrowed technique set; the deliberate `pay.crypto.com` addition was documented before use,
not silently assumed; no account was created, no KYC performed, no fund movement attempted. Two
real defects in Viper were found and fixed by actually running it live against unpredictable
real-world content — the crew's offline tests, though thorough, could not have caught either one.

On the bug-bounty question itself: **no bounty-eligible vulnerability was found in round 1.**
Every confirmed finding is info-severity web hygiene (missing SRI, cookie flags, WAF/port
disclosure); the one high-severity finding that appeared was a tool false positive, now fixed;
GraphQL introspection and the one discovered injection surface both came back clean. Recommend
not spending a trial report on this round's results alone. If a future round is pursued: the
account-requiring assets and `crypto.com/exchange`'s authenticated surface are the highest-value
remaining targets, but require the operator's own authenticated session — never the
orchestrator's credentials or a created account.
