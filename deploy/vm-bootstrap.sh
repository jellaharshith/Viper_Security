#!/usr/bin/env bash
# Run explicitly as root on the Ubuntu 22.04 amd64 execution VM, never on the workstation.
set +x
set -euo pipefail
umask 077

die() { echo "bootstrap: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run as root"
[[ $# -le 1 ]] || die "usage: bash vm-bootstrap.sh [comma-separated-exact-hosts]"
[[ $(uname -m) == x86_64 ]] || die "this release archive requires amd64"
NUCLEI_VERSION=${NUCLEI_VERSION:-3.3.10}
[[ $NUCLEI_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid NUCLEI_VERSION"
EGRESS_ALLOWLIST=${1:-scanme.nmap.org}
UPLOAD_DIR=/tmp/vmapi-upload
for module in app.py auth.py jobs.py toolrunner.py requirements.txt; do
  [[ -f "$UPLOAD_DIR/$module" && ! -L "$UPLOAD_DIR/$module" ]] || die "missing trusted upload: $module"
done
[[ ! -L "$UPLOAD_DIR" && ! -L /opt/viper && ! -L /opt/viper/vmapi ]] || die "symlink deployment path"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y nmap python3-venv openssl curl unzip ca-certificates

# Refuse env-file injection, URLs, networks and non-host entries before configuring the service.
python3 - "$EGRESS_ALLOWLIST" <<'PY'
import ipaddress
import re
import sys
import unicodedata

allowlist = sys.argv[1]
if '%' in allowlist or any(char.isspace() or unicodedata.category(char).startswith('C')
                           for char in allowlist):
    raise SystemExit('bootstrap: allowlist must not contain whitespace, controls or scoped IPv6')
for host in allowlist.split(','):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not re.fullmatch(
            r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
            r'(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*', host
        ):
            raise SystemExit('bootstrap: allowlist requires comma-separated exact hosts/IPs')
PY

getent group viper-vmapi >/dev/null || groupadd --system viper-vmapi
if id viper-vmapi >/dev/null 2>&1; then
  [[ $(id -gn viper-vmapi) == viper-vmapi ]] || die "existing user has the wrong primary group"
  [[ $(getent passwd viper-vmapi | cut -d: -f6) == /var/lib/viper-vmapi ]] || die "existing user has the wrong home"
  [[ $(getent passwd viper-vmapi | cut -d: -f7) == /usr/sbin/nologin ]] || die "existing user has a login shell"
else
  useradd --system --gid viper-vmapi --create-home \
    --home-dir /var/lib/viper-vmapi --shell /usr/sbin/nologin viper-vmapi
fi
install -d -o viper-vmapi -g viper-vmapi -m 0700 /var/lib/viper-vmapi
install -d -o root -g root -m 0755 /opt/viper
install -d -o root -g viper-vmapi -m 0750 /opt/viper/vmapi
install -d -o root -g viper-vmapi -m 0755 /etc/viper /etc/viper/certs

# Reruns update only after existing jobs have been terminated by systemd's cgroup cleanup.
if systemctl is-active --quiet viper-vmapi.service; then
  systemctl stop viper-vmapi.service
fi
for module in app.py auth.py jobs.py toolrunner.py requirements.txt; do
  install -o root -g viper-vmapi -m 0640 "$UPLOAD_DIR/$module" "/opt/viper/vmapi/$module"
done
python3 -m venv /opt/viper/vmapi/.venv
/opt/viper/vmapi/.venv/bin/python -m pip install -r /opt/viper/vmapi/requirements.txt
chown -R root:viper-vmapi /opt/viper/vmapi
chmod -R u=rwX,g=rX,o= /opt/viper/vmapi

work_dir=$(mktemp -d /tmp/viper-bootstrap.XXXXXXXX)
trap 'rm -rf -- "$work_dir"' EXIT
archive="nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
release="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}"
(
  cd "$work_dir"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --output "$archive" "$release/$archive"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --output checksums.txt "$release/nuclei_${NUCLEI_VERSION}_checksums.txt"
  awk -v asset="$archive" '$2 == asset {print; found++} END {if (found != 1) exit 1}' \
    checksums.txt > selected-checksum.txt
  sha256sum -c selected-checksum.txt
  unzip -q "$archive" nuclei
  install -o root -g root -m 0755 nuclei /usr/bin/nuclei
)
install -d -o root -g root -m 0755 /opt/viper/nuclei-templates
/usr/bin/nuclei -update-templates -ud /opt/viper/nuclei-templates -duc
chown -R root:root /opt/viper/nuclei-templates
chmod -R u=rwX,go=rX /opt/viper/nuclei-templates

# Preserve an existing certificate/key pair; never silently rotate the client's trust anchor.
if [[ -e /etc/viper/certs/vmapi-key.pem || -e /etc/viper/certs/vmapi-cert.pem ]]; then
  [[ -f /etc/viper/certs/vmapi-key.pem && -f /etc/viper/certs/vmapi-cert.pem ]] || die "incomplete TLS pair"
  openssl x509 -in /etc/viper/certs/vmapi-cert.pem -noout -checkend 0 >/dev/null
  openssl pkey -in /etc/viper/certs/vmapi-key.pem -check -noout >/dev/null 2>&1
else
  openssl req -x509 -newkey rsa:4096 -sha256 -days 90 -nodes \
    -keyout /etc/viper/certs/vmapi-key.pem -out /etc/viper/certs/vmapi-cert.pem \
    -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>/dev/null
fi
chown root:viper-vmapi /etc/viper/certs/vmapi-key.pem /etc/viper/certs/vmapi-cert.pem
chmod 0640 /etc/viper/certs/vmapi-key.pem
chmod 0644 /etc/viper/certs/vmapi-cert.pem

# Atomic restricted env-file creation; preserve a valid existing token on reruns.
# Python writes the secret directly to disk, never to stdout or a command-line argument.
python3 - "$EGRESS_ALLOWLIST" <<'PY'
import grp
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

path = Path('/etc/viper/vmapi.env')
if path.is_symlink():
    raise SystemExit('bootstrap: env file must not be a symlink')
if path.exists():
    tokens = [line.split('=', 1)[1] for line in path.read_text().splitlines()
              if line.startswith('VIPER_EXEC_API_TOKEN=')]
    if len(tokens) != 1 or not re.fullmatch(r'[0-9a-f]{64}', tokens[0]):
        raise SystemExit('bootstrap: existing env has an invalid token; refusing silent rotation')
    token = tokens[0]
else:
    token = secrets.token_hex(32)
fd, temporary = tempfile.mkstemp(prefix='.vmapi-env-', dir=path.parent)
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(f'VIPER_EXEC_API_TOKEN={token}\n')
        handle.write(f'VIPER_EXEC_EGRESS_ALLOWLIST={sys.argv[1]}\n')
        handle.write('VIPER_EXEC_NUCLEI_TEMPLATES=/opt/viper/nuclei-templates\n')
    os.chown(temporary, 0, grp.getgrnam('viper-vmapi').gr_gid)
    os.chmod(temporary, 0o640)
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY

cat > "$work_dir/viper-vmapi.service" <<'UNIT'
[Unit]
Description=Viper headless execution API
After=network.target

[Service]
Type=simple
User=viper-vmapi
Group=viper-vmapi
Environment=HOME=/var/lib/viper-vmapi
WorkingDirectory=/opt/viper
EnvironmentFile=/etc/viper/vmapi.env
ExecStart=/opt/viper/vmapi/.venv/bin/uvicorn vmapi.app:app --host 127.0.0.1 --port 8443 --ssl-keyfile /etc/viper/certs/vmapi-key.pem --ssl-certfile /etc/viper/certs/vmapi-cert.pem
Restart=on-failure
RestartSec=3
KillMode=control-group
PrivateTmp=true
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
install -o root -g root -m 0644 "$work_dir/viper-vmapi.service" /etc/systemd/system/viper-vmapi.service
systemctl daemon-reload
systemctl enable --now viper-vmapi.service

# A root-only temporary curl config keeps the bearer token out of argv and logs.
python3 - "$work_dir/health.curl" <<'PY'
import sys
from pathlib import Path

env = Path('/etc/viper/vmapi.env').read_text().splitlines()
token = next(line.split('=', 1)[1] for line in env if line.startswith('VIPER_EXEC_API_TOKEN='))
Path(sys.argv[1]).write_text(f'header = "Authorization: Bearer {token}"\n', encoding='utf-8')
PY
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 \
  --cacert /etc/viper/certs/vmapi-cert.pem --config "$work_dir/health.curl" \
  --output /dev/null https://127.0.0.1:8443/health
echo "bootstrap: authenticated loopback TLS health check passed; credentials remain in /etc/viper/vmapi.env"
