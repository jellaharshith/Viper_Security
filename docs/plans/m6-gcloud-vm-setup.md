# M6 Operator Runbook: Headless GCP Kali Execution Plane

This runbook provides step-by-step instructions for provisioning, configuring, operating, and tearing down an on-demand, headless Kali Linux execution VM on Google Cloud Platform (GCP).

---

## 1. Safety & Architecture Guarantees

- **Headless-First:** No graphical environment, VNC, or X11 desktop. Operations occur strictly through the headless Exec API (`vmapi`).
- **Zero Public Ingress:** The VM has **no external IP address** (`--no-address`). Communication with the VM API is routed exclusively through Google Cloud Identity-Aware Proxy (IAP) encrypted SSH tunneling.
- **Localhost Binding:** The `vmapi` service on the VM binds strictly to `127.0.0.1:8443`. It is never exposed on external or broadcast network interfaces.
- **Cost Capped (<$50/mo):** Provisioned as an `e2-medium` SPOT instance with automatic stop on preemption. Stopping the VM when idle drops compute charges to $0.
- **Strict Scope:** Authorized exclusively for `scanme.nmap.org` (Nmap's official scan-test host).

---

## 2. Prerequisites

The operator must have:
1. An active Google Cloud Platform account with billing enabled.
2. The `gcloud` CLI installed and authenticated on the local workstation:
   ```bash
   gcloud auth login
   ```
3. Permissions to manage Compute Engine instances and IAP tunnels (`roles/compute.instanceAdmin.v1` and `roles/iap.tunnelResourceAccessor`).

---

## 3. Step-by-Step Setup Guide

### Step 1: Set Project Defaults and Enable Required APIs
Set your active GCP project and default zone, then enable the Compute Engine and Identity-Aware Proxy APIs.

```bash
# Set your GCP project ID
gcloud config set project YOUR_GCP_PROJECT_ID

# Set target region and zone (choose a region physically close to you)
gcloud config set compute/region us-central1
gcloud config set compute/zone us-central1-a

# Enable Compute Engine and Identity-Aware Proxy services
gcloud services enable compute.googleapis.com iap.googleapis.com
```

---

### Step 2: Configure Firewall Rules (IAP SSH Ingress Only)
Create a firewall rule permitting ingress on TCP port 22 strictly from Google's IAP netblock (`35.235.240.0/20`). **Do not open port 8443 or any other port to the public internet.**

```bash
gcloud compute firewall-rules create allow-iap-ssh \
  --direction=INGRESS \
  --priority=1000 \
  --network=default \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges=35.235.240.0/20 \
  --description="Allow SSH exclusively through Google Cloud IAP"
```

---

### Step 3: Provision the Headless Spot Kali VM
Create the VM with `--no-address` (no external IP) and SPOT provisioning.

```bash
gcloud compute instances create viper-kali-lab \
  --image-family=kali-rolling \
  --image-project=kali-linux \
  --machine-type=e2-medium \
  --boot-disk-size=30GB \
  --boot-disk-type=pd-balanced \
  --no-address \
  --provisioning-model=SPOT \
  --instance-termination-action=STOP \
  --shielded-secure-boot \
  --shielded-vtpm \
  --metadata=enable-oslogin=TRUE \
  --tags=viper-execution-node
```

> [!NOTE]
> If the `kali-linux` image family requires marketplace license acceptance or is unavailable in your organization, use Ubuntu 22.04 LTS:
> ```bash
> gcloud compute instances create viper-kali-lab \
>   --image-family=ubuntu-2204-lts \
>   --image-project=ubuntu-os-cloud \
>   --machine-type=e2-medium \
>   --boot-disk-size=30GB \
>   --boot-disk-type=pd-balanced \
>   --no-address \
>   --provisioning-model=SPOT \
>   --instance-termination-action=STOP \
>   --shielded-secure-boot \
>   --shielded-vtpm \
>   --metadata=enable-oslogin=TRUE
> ```

---

### Step 4: Connect via IAP and Verify Scanner Tools
Establish an initial SSH session via the IAP tunnel to verify connectivity and tool availability:

```bash
gcloud compute ssh viper-kali-lab --tunnel-through-iap
```

Inside the VM terminal, install Nuclei from a pinned GitHub release (Ubuntu has
no `nuclei` apt package). This example targets the amd64 VM above and verifies
the archive against the same release's checksums file before installation:
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
nmap --version | head -n 1
/usr/bin/nuclei -version
# Before the first scan, confirm that this binary supports the frozen protocol flag:
/usr/bin/nuclei -h | grep -i -- "-pt"
```

Template installation requires operator-provisioned egress. Perform it only as
root, outside jobs, and record the installed template revision. The service must
run as an unprivileged account with read-only access to this root-owned directory.
Stop jobs before template refreshes and reapply ownership and permissions afterward.
Confirm the help output identifies `-pt` as the protocol/type selector before
dispatching any scan. If the installed binary exposes only `-type`, stop and
coordinate changing that one literal in the server, exact-argv test and docs;
do not drop the HTTP restriction.

Add `VIPER_EXEC_NUCLEI_TEMPLATES=/opt/viper/nuclei-templates` to
`/etc/viper/vmapi.env` when creating it in Step 5. Nuclei jobs reject relative
paths, leading dashes, whitespace and control characters. Requests accept only
`target` and optional integer `rate_limit` (1–10); templates, tags and severity
are server-controlled. The live argv is:

```text
/usr/bin/nuclei -jsonl -silent -nc -duc -no-interactsh -disable-redirects
  -t /opt/viper/nuclei-templates -tags tech,misconfig
  -etags dos,fuzz,intrusive,bruteforce,rce,sqli,xss -severity info,low,medium
  -pt http -rl RATE_LIMIT -c 5 -timeout 10 -retries 0 -u TARGET
```

There is no `-passive` flag. Stdout findings are JSONL; merged stderr may include
non-JSON diagnostics. These installation commands are instructions for deployment;
offline verification does not download binaries/templates or contact live targets.

---

### Step 5: Deploy `vmapi` Under systemd

#### 1. Create an Unprivileged Service Account and Directories
While connected to the VM:
```bash
sudo useradd --system --user-group --create-home \
  --home-dir /var/lib/viper-vmapi --shell /usr/sbin/nologin viper-vmapi
sudo install -d -o root -g root -m 0755 /opt/viper
sudo install -d -o root -g viper-vmapi -m 0750 /opt/viper/vmapi
sudo install -d -o root -g viper-vmapi -m 0755 /etc/viper /etc/viper/certs
```

Create the account once; if it already exists, verify its home, group and no-login
shell before continuing. Both `nmap -sT` and Nuclei run without root privileges
or Linux capabilities. Keep application code and the virtualenv administrator-owned;
the service needs read/execute access only. Templates remain `root:root` with
directories mode 755 and files mode 644, so this account cannot modify them.

#### 2. Copy `vmapi` Code from Local Workstation
From a **local workstation** terminal in `C:\Users\STSC\Desktop\Viper`:
```bash
gcloud compute scp --recurse --tunnel-through-iap vmapi viper-kali-lab:/tmp/vmapi-upload
```

#### 3. Install Application and Virtual Environment on VM
Back in the **VM SSH session**:
```bash
sudo cp -r /tmp/vmapi-upload/* /opt/viper/vmapi/
rm -rf /tmp/vmapi-upload

# Create dedicated virtualenv
sudo python3 -m venv /opt/viper/vmapi/.venv
sudo /opt/viper/vmapi/.venv/bin/pip install --upgrade pip
sudo /opt/viper/vmapi/.venv/bin/pip install -r /opt/viper/vmapi/requirements.txt
sudo chown -R root:viper-vmapi /opt/viper/vmapi
sudo chmod -R u=rwX,g=rX,o= /opt/viper/vmapi
```

#### 4. Generate TLS Certificate and Key on VM
Generate a self-signed certificate bound to `localhost` and `127.0.0.1`:
```bash
sudo openssl req -x509 -newkey rsa:4096 -sha256 -days 90 -nodes \
  -keyout /etc/viper/certs/vmapi-key.pem \
  -out /etc/viper/certs/vmapi-cert.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

sudo chown root:viper-vmapi /etc/viper/certs/vmapi-key.pem /etc/viper/certs/vmapi-cert.pem
sudo chmod 640 /etc/viper/certs/vmapi-key.pem
sudo chmod 644 /etc/viper/certs/vmapi-cert.pem
```

#### 5. Generate Bearer Token and Secret Environment File
```bash
# Generate high-entropy bearer token
TOKEN=$(openssl rand -hex 32)
echo "=== YOUR TOKEN (COPY THIS FOR LOCAL .env): ==="
echo "$TOKEN"
echo "=============================================="

# Write restricted environment file
sudo bash -c "umask 077; cat <<EOF > /etc/viper/vmapi.env
VIPER_EXEC_API_TOKEN=${TOKEN}
VIPER_EXEC_EGRESS_ALLOWLIST=scanme.nmap.org
VIPER_EXEC_NUCLEI_TEMPLATES=/opt/viper/nuclei-templates
EOF"

sudo chown root:viper-vmapi /etc/viper/vmapi.env
sudo chmod 640 /etc/viper/vmapi.env
```

#### 6. Configure systemd Service
Create `/etc/systemd/system/viper-vmapi.service`:
```bash
sudo bash -c 'cat <<EOF > /etc/systemd/system/viper-vmapi.service
[Unit]
Description=Viper Headless Remote Execution API Server
After=network.target

[Service]
Type=simple
User=viper-vmapi
Group=viper-vmapi
Environment=HOME=/var/lib/viper-vmapi
WorkingDirectory=/opt/viper
EnvironmentFile=/etc/viper/vmapi.env
ExecStart=/opt/viper/vmapi/.venv/bin/uvicorn vmapi.app:app --host 127.0.0.1 --port 8443 --ssl-keyfile /etc/viper/certs/vmapi-key.pem --ssl-certfile /etc/viper/certs/vmapi-cert.pem
Restart=always
RestartSec=3
KillMode=control-group
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF'
```

Keep `User=viper-vmapi` when adapting or replacing this unit; the API and scanner
children must use the unprivileged account. `KillMode=control-group` cleans up
scanner children if the service stops or crashes. Never grant the account write
access to `/opt/viper/vmapi`, `/usr/bin/nuclei` or the template directory.

#### 7. Enable and Start the Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now viper-vmapi.service

# Verify service is running
sudo systemctl status viper-vmapi.service --no-pager
```

#### 8. Verify Local Health Endpoint on VM
```bash
curl --cacert /etc/viper/certs/vmapi-cert.pem \
  -H "Authorization: Bearer ${TOKEN}" \
  https://127.0.0.1:8443/health
```
Expected output:
```json
{"status":"ok","tools":["nmap","nuclei"]}
```

Exit the VM SSH session (`exit`).

---

### Step 6: Fetch Certificate and Configure Local Workstation

#### 1. Download VM Certificate to Local Workstation
From the local Windows PowerShell terminal:
```powershell
New-Item -ItemType Directory -Force -Path secrets
gcloud compute scp --tunnel-through-iap viper-kali-lab:/etc/viper/certs/vmapi-cert.pem secrets/vm-ca.pem
```

#### 2. Configure Local `.env`
Add the following configuration lines to your git-ignored `.env` file in the Viper project root:
```ini
VIPER_EXEC_API_URL=https://localhost:8443
VIPER_EXEC_API_TOKEN=<THE_TOKEN_GENERATED_IN_STEP_5>
VIPER_EXEC_API_CA_CERT=./secrets/vm-ca.pem
VIPER_EXEC_EGRESS_ALLOWLIST=scanme.nmap.org
VIPER_ALLOW_ACTIVE_TESTING=true
```

---

### Step 7: Open Local IAP Tunnel
Run the IAP tunnel in a dedicated terminal window on your local workstation:

```powershell
# vmapi binds 127.0.0.1 by design, so forward over an IAP-tunnelled SSH session. (start-iap-tunnel
# targets the NIC, not loopback, and does NOT reach vmapi.) gcloud on Windows drives PuTTY, so use
# only PuTTY flags here (-N, -L); OpenSSH-style -o options make putty.exe exit 1.
gcloud compute ssh viper-kali-lab --zone us-central1-a --tunnel-through-iap -- -N -L 8443:localhost:8443
```
Keep this terminal open while executing commands.

In another terminal, test connectivity through the local tunnel:
```powershell
curl.exe --cacert ./secrets/vm-ca.pem -H "Authorization: Bearer <TOKEN>" https://localhost:8443/health
```
Expected response:
```json
{"status":"ok","tools":["nmap","nuclei"]}
```

---

### Step 8: Gated Live Execution against `scanme.nmap.org`

Execute the lab workflow using the authorized scope file:

```powershell
# 1. Start agent thread with lab-scanme scope
$env:PYTHONPATH="src"
.venv\Scripts\python -m viper.cli agent run --scope projects/lab-scanme/scope.yaml --plan projects/lab-scanme/plan.json --thread lab1

# 2. Review the pending active action, then resume
.venv\Scripts\python -m viper.cli agent resume --scope projects/lab-scanme/scope.yaml --thread lab1 --decision ALLOW

# 3. Stream live scan stdout
.venv\Scripts\python -m viper.cli exec watch --job nmap-scanme-1

# 4. If emergency stop is needed:
.venv\Scripts\python -m viper.cli exec stop --job nmap-scanme-1

# 5. Verify the audit log integrity
.venv\Scripts\python -m viper.cli audit verify --project lab-scanme
```

---

## 4. Cost Control & Teardown Guide

### Stop VM (Compute Paused, Disk Retained)
When testing is paused, stop the VM immediately. Compute billing drops to **$0/hour**; you only incur nominal persistent disk storage charges (~$1.50/month for 30GB).

```bash
gcloud compute instances stop viper-kali-lab
```

To resume testing later:
```bash
gcloud compute instances start viper-kali-lab
```

---

### Complete Teardown (Zero Recurring Cost)
When M6 evaluation is complete, remove all cloud resources to ensure zero ongoing billing:

```bash
# 1. Delete the execution VM
gcloud compute instances delete viper-kali-lab --quiet

# 2. Delete the IAP firewall rule
gcloud compute firewall-rules delete allow-iap-ssh --quiet

# 3. Remove local certificate copy and reset active testing flag
Remove-Item -Force secrets/vm-ca.pem
```

In `.env`, reset active testing:
```ini
VIPER_ALLOW_ACTIVE_TESTING=false
```

Verify in GCP that no instances remain:
```bash
gcloud compute instances list
```

---

## 5. Lessons from the M7 live run (2026-11-08)

- **Action ids are single-use.** The executor burns `dispatch:<action_id>` even when the VM rejects the
  request (for example a 422), so after any failed attempt use a new action id and thread id.
- **Teardown order:** stop the SSH port-forward process first, then delete the VM, the NAT, the router
  and the `allow-iap-ssh` rule. Verify with `compute instances/routers/firewall-rules/disks list`.
- **Never reuse a pre-existing VM** in the project for this; create `viper-kali-lab` and delete it after.
