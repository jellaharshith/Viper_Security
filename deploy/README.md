# Execution VM bootstrap

`vm-bootstrap.sh` implements the [VM runbook](../docs/plans/m6-gcloud-vm-setup.md)
for a fresh Ubuntu 22.04 **amd64** VM with systemd. Run it explicitly as root on
the execution VM after provisioning IAP access and operator-controlled outbound
connectivity. It installs packages, downloads a pinned Nuclei release and its
checksums, installs templates, starts the API and calls its local health endpoint.
It does not perform a scan or provision cloud infrastructure/firewalls.

Copy the trusted repository's `vmapi/` directory to `/tmp/vmapi-upload` and this
script to `/tmp/vm-bootstrap.sh` using the runbook's IAP SCP transport. Keep those
uploads under the trusted operator's control until installation finishes. The
script installs the four runtime Python modules and `requirements.txt`; uploaded
virtualenvs, tests and credentials are not copied into the service directory.

```bash
# On the VM; default exact target is scanme.nmap.org.
sudo bash /tmp/vm-bootstrap.sh
# Or supply comma-separated exact hostnames/IPs authorized for this VM:
sudo bash /tmp/vm-bootstrap.sh scanme.nmap.org
# Override the pinned binary version explicitly if the reviewed deployment requires it:
sudo env NUCLEI_VERSION=3.3.10 bash /tmp/vm-bootstrap.sh scanme.nmap.org
```

The archive must match exactly one entry in its release's checksum file; missing
or mismatched checksums abort before installation. There is no download-to-shell
pipeline. Nuclei templates are updated by root with `-duc` and made read-only to
the service. The template revision and Python dependency resolution may change
between runs; record the installed versions/revision for assessment reproducibility.

Rerunning preserves a valid existing bearer token and TLS certificate/key pair,
updates code/dependencies/binary/templates, reapplies ownership and permissions,
and restarts the service. An invalid existing token, expired certificate or partial
key/certificate pair fails rather than silently replacing credentials. Existing
jobs are stopped before updates; rerun only when no assessment is active. A failure
after stopping the service may leave it stopped until the problem is corrected
and bootstrap is rerun.

The system user `viper-vmapi` has no login shell. Code and the virtualenv are
`root:viper-vmapi` and not writable by the service. The environment file and TLS
private key are `root:viper-vmapi`, mode 0640. Templates remain `root:root` and
read-only to the service; Nmap TCP connect and Nuclei need no root capabilities.
The API binds only `127.0.0.1:8443` with TLS, one worker and
`KillMode=control-group`. The final authenticated health check uses a root-only
temporary curl configuration, never prints the token, and never exposes it in argv.
Retrieve credentials through your existing secure operator channel; never paste
them into logs or commits. The public certificate may be copied for client trust.

Before the first scan, confirm the protocol flag spelling using
`/usr/bin/nuclei -h | grep -i -- "-pt"`. The frozen server argv uses `-pt http`.
If this binary exposes only `-type`, coordinate changing that literal in the
server, tests and docs before scanning; retain the HTTP restriction.

Offline verification (does not run the bootstrap or contact a target):

```powershell
.venv/Scripts/python -m pytest -q tests/test_deploy_script.py
```

Tests inspect safety requirements and run `bash -n` if Bash is installed. They
do not validate package downloads, systemd startup or a real Ubuntu deployment;
those remain part of the coordinator's separately authorized live validation.
