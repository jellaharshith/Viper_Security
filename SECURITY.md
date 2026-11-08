# Security policy

Viper is a security tool, so reports about it are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Use GitHub's private reporting instead:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability** (private advisory).

Include what you found, the affected component (for example `viper.policy`, `vmapi`, the audit log), steps to
reproduce, and the impact you expect. You will get an acknowledgement as soon as the maintainer sees it, and a fix or
mitigation plan after triage.

## What is in scope

Anything that weakens a control Viper promises. In particular:

- a way for model output, tool output or a request to **bypass policy, scope, or human approval**;
- **scope escape**: a job reaching a target that is not in the scope file or the egress allowlist;
- forging, truncating or silently dropping **audit events**, or making a report cite evidence that was not produced;
- the **Exec API** (`vmapi/`): authentication, argument allowlist, command construction, process control;
- **path traversal**, terminal-escape or Markdown injection through tool output or report rendering;
- leaking secrets (`.env`, bearer tokens, keys) into logs, reports or the audit log.

## What is out of scope

- Findings that require an attacker who already controls your machine or your cloud account.
- Vulnerabilities in third-party tools Viper drives (`nmap`, `nuclei`); report those upstream.
- Testing against systems you do not own. Do not scan third-party targets to "prove" an issue; a code-level proof of
  concept or a unit test is enough.

## Supported versions

Only the latest commit on `main` is supported.

## Safe-harbour

Good-faith research that follows this policy, stays within your own systems, and avoids privacy violations or service
disruption will not be pursued.
