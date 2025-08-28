# Create an "addons" scaffold with CI, policy-as-code, IaC stubs, docs, and ops scripts
import os, zipfile, json, textwrap, pathlib

base = "/mnt/data/zt-mysql-addons"
os.makedirs(base, exist_ok=True)

def write(path, content, mode=0o644):
    p = pathlib.Path(base) / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    os.chmod(p, mode)

# 1) GitHub Actions CI
ci_yml = r"""
name: ci

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

permissions:
  contents: read

jobs:
  scan-and-verify:
    runs-on: ubuntu-22.04
    env:
      COSIGN_EXPERIMENTAL: "true"
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install scanners
        run: |
          curl -sSL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | bash
          sudo mv gitleaks /usr/local/bin/
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo bash -s -- -b /usr/local/bin
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo bash -s -- -b /usr/local/bin
          curl -sSfL https://get.opa.dev | sudo sh -s -- -b /usr/local/bin
          pip install semgrep

      - name: Secrets scan (gitleaks)
        run: gitleaks detect -v --redact --source . --config .gitleaks.toml || (echo "::error::gitleaks found issues"; exit 1)

      - name: SAST (semgrep)
        run: semgrep ci --config .semgrep.yml

      - name: SBOM (syft) and vuln scan (grype)
        run: |
          syft dir:. -o json > sbom.json
          grype sbom:sbom.json -o table || true
        continue-on-error: true

      - name: Policy-as-code (Conftest/OPA) on MySQL config evidence
        run: |
          if [ -f evidence/mysql_vars.json ]; then
            conftest test --policy policy evidence/mysql_vars.json
          else
            echo "No evidence/mysql_vars.json found; skipping policy tests"
          fi

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: ci-artifacts
          path: |
            sbom.json
            ./.semgrep.yml
            ./.gitleaks.toml
            ./policy/
            ./evidence/*
          if-no-files-found: warn
"""
write(".github/workflows/ci.yml", ci_yml)

# 2) Gitleaks & Semgrep baseline configs
gitleaks = r"""
title = "baseline"
[allowlist]
description = "Allow common false positives"
paths = [
  '''^docs/''',
  '''^policy/''',
  '''^iac/''',
]
"""
write(".gitleaks.toml", gitleaks)

semgrep = r"""
rules:
- id: python-dangerous-subprocess
  patterns:
  - pattern: subprocess.Popen(...)
  message: "Use of subprocess.Popen requires careful sanitization"
  severity: WARNING
  languages: [python]
- id: bash-curl-pipe-sh
  pattern: curl ... | sh
  message: "curl | sh detected"
  severity: ERROR
  languages: [bash]
"""
write(".semgrep.yml", semgrep)

# 3) OPA policies (Conftest) to validate MySQL hardening evidence
mysql_rego = r"""
package mysql.hardening

deny[msg] {
  input.require_secure_transport != "ON"
  msg := "require_secure_transport must be ON"
}

deny[msg] {
  input.local_infile != "OFF"
  msg := "local_infile must be OFF"
}

deny[msg] {
  input.skip_name_resolve != "ON"
  msg := "skip_name_resolve must be ON"
}

deny[msg] {
  not contains(input.sql_mode, "STRICT_ALL_TABLES")
  msg := "sql_mode must include STRICT_ALL_TABLES"
}

contains(str, substr) {
  indexof(str, substr) >= 0
}
"""
write("policy/mysql.rego", mysql_rego)

# 4) Evidence collector script to feed OPA
collector = r"""#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-evidence/mysql_vars.json}"
mkdir -p "$(dirname "$OUT")"
mysql -N -e "SHOW VARIABLES WHERE Variable_name IN ('require_secure_transport','local_infile','skip_name_resolve','sql_mode');" \
| awk -F'\t' 'BEGIN{print "{"}{printf "\"%s\":\"%s\",",$1,$2}END{print "\"_ts\":\""strftime("%Y-%m-%dT%H:%M:%SZ")"\"}"}' > "$OUT"
jq . "$OUT" >/dev/null
echo "$OUT"
"""
write("scripts/collect_mysql_vars.sh", collector, mode=0o755)

# 5) OpenSCAP scan helper
openscap = r"""#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-evidence/openscap}"
PROFILE="${PROFILE:-xccdf_org.ssgproject.content_profile_stig}"
mkdir -p "$OUT"
oscap xccdf eval --profile "$PROFILE" --results "$OUT/results.xml" --report "$OUT/report.html" /usr/share/xml/scap/ssg/content/*-ds.xml || true
echo "$OUT"
"""
write("scripts/openscap_scan.sh", openscap, mode=0o755)

# 6) Conftest test stub
test_stub = r"""
# Provide mysql_vars.json input to conftest. This is a placeholder for CI.
"""
write("policy/README.md", test_stub)

# 7) IaC Terraform minimal (VPC, subnet, host, firewall)
providers_tf = r"""
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}
"""
write("iac/terraform/providers.tf", providers_tf)

variables_tf = r"""
variable "project_id" { type = string }
variable "region"     { type = string }
variable "zone"       { type = string }
variable "network_name" { type = string  default = "zt-mysql-net" }
variable "subnet_cidr" { type = string  default = "10.10.0.0/24" }
variable "instance_name" { type = string default = "zt-mysql-vm" }
variable "machine_type" { type = string default = "e2-standard-4" }
variable "image" { type = string default = "ubuntu-2204-jammy-v20240710" }
variable "service_account_email" { type = string }
variable "allow_cidrs" { type = list(string) default = [] }
"""
write("iac/terraform/variables.tf", variables_tf)

main_tf = r"""
resource "google_compute_network" "net" {
  name = var.network_name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${var.network_name}-subnet"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.net.id
  private_ip_google_access = true
}

resource "google_compute_firewall" "ssh" {
  name    = "${var.network_name}-ssh"
  network = google_compute_network.net.name
  allow { protocol = "tcp" ports = ["22"] }
  source_ranges = var.allow_cidrs
}

resource "google_compute_firewall" "mysql" {
  name    = "${var.network_name}-mysql"
  network = google_compute_network.net.name
  allow { protocol = "tcp" ports = ["3306"] }
  source_ranges = var.allow_cidrs
}

resource "google_compute_instance" "vm" {
  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = var.image
      size  = 50
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet.name
    access_config {}
  }

  service_account {
    email  = var.service_account_email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot = true
    enable_vtpm        = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin = "TRUE"
  }
}
"""
write("iac/terraform/main.tf", main_tf)

outputs_tf = r"""
output "vm_name" { value = google_compute_instance.vm.name }
output "vm_ip"   { value = google_compute_instance.vm.network_interface[0].access_config[0].nat_ip }
output "network" { value = google_compute_network.net.name }
"""
write("iac/terraform/outputs.tf", outputs_tf)

# 8) Makefile
makefile = r"""
.PHONY: evidence openscap policy

evidence:
	./scripts/collect_mysql_vars.sh

openscap:
	./scripts/openscap_scan.sh

policy: evidence
	conftest test --policy policy evidence/mysql_vars.json
"""
write("Makefile", makefile)

# 9) Docs: threat model, controls map, architecture (Mermaid)
threat_model = r"""
# Threat Model (Concise)

## Assets
- Encrypted PII payloads
- Wrapped DEKs (KMS + PQ wrap)
- Audit chain head and events
- mTLS credentials

## Trust Boundaries
- Client/KMS boundary (DEK unwrap)
- DB boundary (ciphertext only)
- Logging/WORM boundary (off-host evidence)

## High-Level Risks
- Network eavesdropping → TLS1.3 + mTLS
- Privilege misuse → least-privilege + proc-only API
- Data exfil in DB → client-side encryption, no decrypt in SQL
- Audit tampering → append-only + global chain + WORM anchoring
- Misconfiguration → policy-as-code + proof suite
"""
write("docs/threat_model.md", threat_model)

arch = r"""
```mermaid
flowchart LR
A[Client\nAES-GCM + KMS + PQ wrap] -- mTLS --> B[MySQL VM\nTLS1.3+mTLS\nProc-only\nTenant ctx]
B -- ciphertext+IV/AAD+wrapped DEK --> D[(Storage)]
B -- chain head --> E[Syslog/Ops Agent]
E --> F[Cloud Logging]
F --> G[GCS WORM Bucket]
A <-- decrypt via KMS --> H[HSM-backed KMS]
"""
write("docs/architecture.md", arch)

controls_map = r"""
# Controls Mapping (Outline)
- AC (Access Control): least privilege, proc-only API, tenant isolation
- AU (Audit): append-only global chain, off-host anchoring, retention lock
- CM (Config Management): IaC + policy-as-code + CI evidence
- IA/SC (Identity/Sec): TLS1.3 mTLS, cert rotation, KMS authn
- SI (Monitoring): Ops Agent logs, alerts (chain gaps)
- Artifacts: proof_bundle.tar.gz; openscap report; sbom.json; CI logs.
"""
write("docs/controls_map.md", controls_map)

# 10) Ops scripts: backup/restore, chain verify, rotation placeholders

backup_sh = r"""#!/usr/bin/env bash
set -euo pipefail
DEST="${1:-/var/backups/securedb}"
mkdir -p "$DEST"
mysqldump --single-transaction --hex-blob securedb > "$DEST/securedb.sql"
mysql -e "SHOW BINARY LOGS" > "$DEST/binlogs.txt" || true
echo "$DEST"
"""
write("scripts/backup.sh", backup_sh, mode=0o755)

restore_sh = r"""#!/usr/bin/env bash
set -euo pipefail
SRC="${1:?}"
mysql < "$SRC/securedb.sql"
"""
write("scripts/restore.sh", restore_sh, mode=0o755)

chain_verify = r"""#!/usr/bin/env python3
import sys,hashlib,binascii,json
import mysql.connector
conn=mysql.connector.connect(host="127.0.0.1",user="auditor",password="Audit#ChangeMe!23",database="securedb",ssl_disabled=False)
cur=conn.cursor(dictionary=True)
cur.execute("SELECT id,HEX(prev_hash) ph,HEX(curr_hash) ch, table_name, action FROM audit_events ORDER BY id")
prev=None
ok=True
for r in cur:
if prev and prev!=r["ph"]:
ok=False; print("BREAK at",r["id"]); break
prev=r["ch"]
print("OK" if ok else "FAIL")
"""