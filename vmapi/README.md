# VM execution API

Linux-only Exec API v1. Independent of the main Viper package. From the repository
root, install `python -m pip install -r vmapi/requirements.txt`. Install trusted
Nmap and Nuclei binaries at `/usr/bin/nmap` and `/usr/bin/nuclei` separately.
Run as a dedicated unprivileged service account, using a clean home and trusted,
administrator-owned scanner configuration/templates. Do not run as root.

Set these environment variables in a service environment file readable only by
the service owner (never commit credentials):

- `VIPER_EXEC_API_TOKEN`: required bearer secret; missing/empty fails closed.
- `VIPER_EXEC_EGRESS_ALLOWLIST`: required comma-separated exact target hosts/IPs,
  e.g. `scanme.nmap.org`; empty denies all jobs. Loaded at startup.
- `VIPER_EXEC_API_TLS_CERT` / `VIPER_EXEC_API_TLS_KEY`: TLS certificate/key paths.

Launch **from the parent of `vmapi/`** with `python -m vmapi.app`. The launcher
fixes the listener to `127.0.0.1:8443`, TLS, and one worker. Never override the
listener with an externally reachable uvicorn command or run multiple workers:
the registry is process-local. Reach localhost through an SSH tunnel, verifying
the server certificate on the client. Run under systemd with `KillMode=control-group`
so service crashes also clean up jobs.

Every HTTP request requires `Authorization: Bearer <token>`, including health and
unknown routes. Interactive docs and OpenAPI routes are disabled. HTTP auth occurs
before request validation. Tokens are read from the environment on each request;
expiry/rotation is managed by the operator, not encoded in this opaque token.

## Contract and argument schema

`GET /health` returns `{"status":"ok","tools":["nmap","nuclei"]}`.
`POST /jobs` accepts exactly `job_id`, `tool`, `args`, `target`. For example:

```json
{"job_id":"scan-1","tool":"nmap","args":{"target":"scanme.nmap.org","ports":"80,443","service_detection":true,"skip_discovery":true},"target":"scanme.nmap.org"}
```

Both target fields are mandatory, must match exactly, and must be in the server's
allowlist. No URLs, CIDRs, files, target lists or wildcard hosts are accepted.
Job IDs contain 1–128 ASCII letters, digits, underscores or hyphens.

| Tool | Allowed argument keys | Fixed behavior |
|---|---|---|
| nmap | `target`; optional strict booleans `service_detection`, `skip_discovery`; optional `ports` string of up to 32 comma-separated ports (1–65535) | TCP connect `-sT`; booleans map to `-sV`, `-Pn` |
| nuclei | `target`; optional strict integer `rate_limit` (1–10, default 1) | Passive response processing; no Interactsh, updates, stdin or redirects |

Nuclei's `-passive` mode is offline HTTP response processing, not a general live
template scan; it may find nothing for hostname input. This slice deliberately
does not expose custom templates, workflows or intrusive execution. See the
[upstream flag reference](https://github.com/projectdiscovery/nuclei).
Neither tool accepts a raw argv/flags field, output flags or arbitrary strings.
Targets occur once in argv; execution uses no shell. Exact hostname validation
does not pin DNS resolution: an operator-managed egress firewall and trusted DNS
are required if network-level destination confinement is needed.

Creation returns 201 `{"job_id":"scan-1","state":"running"}`. Invalid tool,
argument or target returns 422; missing/bad auth 401; reused IDs 409; launch or
capacity failures 503. IDs are never reused during the service lifetime.

- `GET /jobs/{id}`: `job_id`, `state` (`running`, `paused`, `done`, `failed`,
  `killed`), `exit_code` (integer or null).
- `GET /jobs/{id}/stream`: `text/event-stream`, stdout and merged stderr as
  `data: <line>\n\n`; replay retained output then follow until capture finishes.
- `POST /jobs/{id}/pause`: SIGSTOP the process group, `{"state":"paused"}`.
- `POST /jobs/{id}/stop`: SIGKILL the group and verify termination before
  `{"state":"killed"}`. Repeating a successful stop is safe; completed jobs
  return 409. Verification failure returns 503, never a killed acknowledgement.

Unknown IDs return 404. Pausing a finished job returns 409. Resume is not part of
v1. Each child starts a new session (`start_new_session=True`, invokes Linux
`setsid(2)`) rather than unsafe threaded `preexec_fn=os.setsid`. Termination checks
all `/proc` group members, not just the leader. Exited zombies count as terminated;
their parent/init must reap them. A process deliberately escaping its session is
outside this group mechanism; trusted binaries and systemd cgroup containment
remain deployment requirements.

Jobs time out after 300 seconds (including paused time), are stopped if output
exceeds 1 MiB, and registry capacity is 128 jobs including completed jobs. Output
reads are capped at 64 KiB per event; invalid UTF-8 is replaced, CR/NUL escaped.
Restart only after jobs have stopped. Service shutdown stops unfinished jobs.
State/output disappear on restart; this server does not persist claims or audit.

## Offline verification

```sh
python -m pytest -q vmapi/tests/test_vmapi.py
python -m ruff check vmapi/
```

Tests mock the scanner command with Python subprocesses; no scanner or network
target is contacted. POSIX execution and whole-tree kill tests skip on Windows;
run the same suite on Linux before deployment. Missing FastAPI skips collection.
