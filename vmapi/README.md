# VM execution API

Linux-only Exec API v1. Independent of the main Viper package. From the repository
root, install `python -m pip install -r vmapi/requirements.txt`. Install trusted
Nmap and Nuclei binaries at `/usr/bin/nmap` and `/usr/bin/nuclei` separately.
Run as a dedicated unprivileged service account, using a clean home and trusted,
administrator-owned scanner configuration/templates. Do not run as root.

Set these environment variables in `/etc/viper/vmapi.env`, owned by
`root:viper-vmapi` with mode 640 (never commit credentials):

- `VIPER_EXEC_API_TOKEN`: required bearer secret; missing/empty fails closed.
- `VIPER_EXEC_EGRESS_ALLOWLIST`: required comma-separated exact target hosts/IPs,
  e.g. `scanme.nmap.org`; empty denies all jobs. Loaded at startup.
- `VIPER_EXEC_API_TLS_CERT` / `VIPER_EXEC_API_TLS_KEY`: TLS certificate/key paths.
- `VIPER_EXEC_NUCLEI_TEMPLATES`: trusted template directory, default
  `/opt/viper/nuclei-templates`. Must be an absolute Linux path with no leading
  dash, whitespace or control characters; invalid values refuse nuclei jobs (422).
  This setting is read from the VM environment, never from request arguments.

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

## Install Nuclei and trusted templates (operator only)

Ubuntu has no `nuclei` apt package. On the Linux amd64 VM, install a pinned
GitHub release and verify its archive against that release's checksums file
before installing it. These commands require operator-provisioned network
access; they are deployment instructions, never part of offline tests.

```bash
set -euo pipefail
sudo apt-get update
sudo apt-get install -y nmap python3-pip python3-venv curl unzip ca-certificates
(
  NUCLEI_VERSION=3.3.10
  NUCLEI_ARCHIVE="nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
  NUCLEI_RELEASE="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}"
  download_dir=$(mktemp -d)
  trap 'rm -rf -- "$download_dir"' EXIT
  cd "$download_dir"
  curl --fail --location --proto '=https' --proto-redir '=https' \
    -o "$NUCLEI_ARCHIVE" "$NUCLEI_RELEASE/$NUCLEI_ARCHIVE"
  curl --fail --location --proto '=https' --proto-redir '=https' \
    -o checksums.txt "$NUCLEI_RELEASE/nuclei_${NUCLEI_VERSION}_checksums.txt"
  awk -v asset="$NUCLEI_ARCHIVE" '$2 == asset {print; found++} END {if (found != 1) exit 1}' \
    checksums.txt > selected-checksum.txt
  sha256sum --check selected-checksum.txt
  unzip -q "$NUCLEI_ARCHIVE" nuclei
  sudo install -o root -g root -m 0755 nuclei /usr/bin/nuclei
)
sudo install -d -o root -g root -m 0755 /opt/viper/nuclei-templates
sudo /usr/bin/nuclei -update-templates -ud /opt/viper/nuclei-templates
sudo chown -R root:root /opt/viper/nuclei-templates
sudo chmod -R u=rwX,go=rX /opt/viper/nuclei-templates
```

Set the following in `/etc/viper/vmapi.env` alongside the bearer and TLS settings,
then restart the service. Run the service as an unprivileged account so templates
remain read-only to it. Template installation/refresh is a separate root operation;
stop jobs before refreshing and reapply ownership/permissions afterward. The
binary version is pinned; record the installed template revision for reproducibility.

```ini
VIPER_EXEC_NUCLEI_TEMPLATES=/opt/viper/nuclei-templates
```

Before the first scan, run `/usr/bin/nuclei -h | grep -i -- "-pt"` on the VM and
confirm the protocol/type selector spelling. If only `-type` is supported,
coordinate replacing that literal in the server, exact-argv test and docs before
scanning; retain the HTTP restriction. This offline change does not run the binary.

## Unprivileged service deployment

Create the `viper-vmapi` system user/group with no login shell and a clean home at
`/var/lib/viper-vmapi`. Keep code and the virtualenv `root:viper-vmapi`, readable
and executable by that group but never writable by it. Set the TLS key and
`/etc/viper/vmapi.env` to `root:viper-vmapi`, mode 640; the public certificate can
be mode 644 with the same ownership. Parent directories must permit traversal.
Keep `/opt/viper/nuclei-templates` root-owned, with directories mode 755 and
files mode 644. Both `nmap -sT` and Nuclei require no root privileges or capabilities.

Use `User=viper-vmapi`, `Group=viper-vmapi`,
`Environment=HOME=/var/lib/viper-vmapi`, `WorkingDirectory=/opt/viper`,
`EnvironmentFile=/etc/viper/vmapi.env` and `KillMode=control-group` in systemd.
The uvicorn process and scanner children run under this unprivileged account.
See the [VM runbook](../docs/plans/m6-gcloud-vm-setup.md#step-5-deploy-vmapi-under-systemd)
for account creation, installation, permissions and the complete unit.

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
| nuclei | `target`; optional strict integer `rate_limit` (1–10, default 1) | Live JSONL profile below; server-owned templates, tags and severity |

Nuclei uses this fixed live profile (an argv list, with the last value bound to
the exact allowlisted target):

```text
/usr/bin/nuclei -jsonl -silent -nc -duc -no-interactsh -disable-redirects
  -t TEMPLATES_DIR -tags tech,misconfig
  -etags dos,fuzz,intrusive,bruteforce,rce,sqli,xss -severity info,low,medium
  -pt http -rl RATE_LIMIT -c 5 -timeout 10 -retries 0 -u TARGET
```

`-pt http` restricts execution to HTTP templates. `-passive` is removed.
Findings are JSONL on stdout; merged stderr can contain
non-JSON diagnostic lines. Templates and tags are administrator-controlled so a
request cannot select arbitrary templates or broaden the scan profile. Keys such
as `templates`, `tags`, `severity`, `t`, `pt`, `type`, `protocols` and `-passive`
are rejected with 422.
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
