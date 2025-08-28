
# Zero-Trust MySQL Deployment (mTLS, HSM KMS, PQ-Hybrid, Tamper-Evident Audit)

## 1. What this is
A production-grade deployment pattern for MySQL 8 on a hardened Linux VM that enforces:
- Transport: TLS 1.3 **mTLS**; `require_secure_transport=ON`; strong cipher suites.
- Identity & Access: least privilege, **proc-only writes**, tenant isolation bound to per-connection context.
- Data Protection: **client-side AES-256-GCM**; DEKs wrapped by an **HSM-backed KMS** (envelope encryption; e.g., GCP/AWS/Azure).
- Tamper Evidence: **append-only global hash-chained audit** with a one-minute **off-host anchor** to SIEM/logging → retention-locked object storage (WORM; e.g., GCS/S3/Azure Immutable).
- Host Hardening: firewall (UFW), fail2ban, locked server keys, secure MySQL config.
- Proofs: automated **test bench**, **evidence bundle**, and optional **OpenSCAP STIG/CIS** scan outputs.

The package includes outside-VM setup (PKI, KMS, WORM sink), a single **VM one-click** installer, a **PQ hybrid envelope** helper, and **proof-of-controls** scripts.

---

## 2. Threat model (concise)
- Attacker cannot read plaintext via network: TLS1.3 + mTLS required.
- App identities cannot read base tables or mutate data directly: only vetted stored procedures and tenant-scoped views are permitted.
- DBA or app identity cannot erase or silently alter history: audit is append-only and globally hash-chained; anchors off-host to WORM.
- Compromise of DB host alone does not recover plaintext: PII is **only** decrypted in clients with DEKs fetched from **HSM KMS**. The DB stores only ciphertext + IV/AAD + KMS-wrapped DEK (and optional PQ wrap).

Non-goals: this design does not claim to protect against OS root with live memory scraping in the client process, or a fully compromised KMS/account. Use standard enterprise controls for those planes.

---

## 3. Architecture & working logic

### 3.1 Components
- **Client**: performs AES-GCM encryption/decryption; obtains DEK via **GCP KMS (HSM)** Encrypt/Decrypt.
- **MySQL VM**: hardened MySQL 8 with TLS1.3 + mTLS; PROC API; tenant isolation; audit triggers and off-host anchor.
- **PKI (outside)**: local CA issuing server and client certificates for mTLS.
- **KMS & Logging**: HSM-backed KMS for DEK wrap; centralized logging/SIEM + retention-locked object storage for WORM anchoring.

### 3.2 Data flow (write)
1. Client gets KMS-wrapped DEK by calling `encrypt(kms_key, DEK)` (KMS never reveals CMK).
2. Client AES-GCM encrypts PII → ciphertext + IV + AAD.
3. Client calls stored procedure `app_create_user_encrypted(...)` with ciphertexts, IVs, AADs, and wrapped DEK.
4. DB stores values **without** any decrypt capability in SQL.
5. Audit triggers append an event; global chain head is recomputed and anchored off-host.

### 3.3 Data flow (read)
1. Client fetches ciphertext and metadata.
2. Client unwraps DEK via `decrypt(kms_key, wrapped_DEK)` in KMS.
3. Client AES-GCM decrypts locally and presents plaintext to the application.

### 3.4 Tenant isolation
Each connection sets the tenant via `security_set_tenant(<uuid>)`. All views and procedures validate `get_tenant()`; cross-tenant reads/writes are rejected.

### 3.5 Tamper-evident audit
Every DML is logged with before/after and actor. Each record includes `prev_hash` and `curr_hash = SHA-256(prev || payload)`. Two DB triggers prevent UPDATE/DELETE on the audit table. A systemd timer logs the **chain head** every minute to syslog, collected by Ops Agent and exported to **WORM** storage.

### 3.6 Quantum hardening (hybrid)
The schema holds an optional **PQ-wrapped** DEK (`pii_pq_wrapped_key`, `pq_alg`). The provided helper demonstrates **Kyber768** wrapping; the authoritative wrap remains **HSM KMS**. To operationalize PQ hybrid, supply an organizational Kyber public key and store the private key in an HSM. PQ wrapping is additive and not required for runtime decryption.

---

## 4. What makes it tamper-evident in this context
- **Zero-trust data plane**: app identities cannot bypass procedures; tenant isolation enforced on every call.
- **No plaintext in DB**: encryption/decryption happen at the client with HSM-backed keys.
- **Cryptographic accountability**: tamper-evident global audit chain anchored off-host to WORM.
- **Transport assurance**: TLS1.3 with certificate-based mutual auth.
- **Operational hardening**: minimal MySQL attack surface, firewall policy, intrusion throttling, anchored telemetry.
- **Provability**: `proof_suite.sh` generates a machine-verifiable evidence bundle for assessors.

---

## 5. Files & roles

### Outside the VM
- `outside/outside_pki.sh` – Creates CA, server cert, and client certs; outputs `pki_server.tar.gz` and client certs directory.
- `outside/outside_gcp_setup.sh` – Creates KMS key (HSM), WORM logging sink and retention-locked bucket.
- `outside/pq_envelope_cli.py` – Client-side AES-GCM + (optional) Kyber768 hybrid wrap.

### On the VM
- `vm/vm_oneclick.sh` – Configures TLS1.3, mTLS, MySQL hardening, users/roles, proc API, tenant isolation, audit + anchor, UFW & fail2ban.
- `vm/test_bench.sh` – Quick verification suite.
- `vm/proof_suite.sh` – Full proof-of-controls suite; produces `/tmp/proof_bundle.tar.gz`.

---

## 6. Deployment sequence

1. **PKI (workstation)**
   ```bash
   cd outside
   chmod +x outside_pki.sh
   ./outside_pki.sh
   # copy pki_server.tar.gz to VM: /tmp/pki_server.tar.gz
   ```

2. **KMS + WORM sink (workstation)**
   ```bash
   chmod +x outside_gcp_setup.sh
   PROJECT_ID=<id> BUCKET=gs://<worm_bucket> ./outside_gcp_setup.sh
   # default script targets GCP; substitute your cloud’s KMS/logging/WORM equivalents if not on GCP
   ```

3. **VM deploy**
   ```bash
   cd vm
   chmod +x vm_oneclick.sh
   sudo PKI_TAR=/tmp/pki_server.tar.gz ./vm_oneclick.sh
   ```

4. **Client-side encryption (workstation)**
   ```bash
   python3 -m pip install cryptography google-cloud-kms pyoqs
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
   python3 outside/pq_envelope_cli.py projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key> <tenant-uuid> "Alice Admin" "admin" "alice@acme.example" "+12025550101" "tenant=<tenant-uuid>"
   # Use the JSON to call app_create_user_encrypted(...) over mTLS.
   ```

5. **Verification**
   ```bash
   chmod +x test_bench.sh proof_suite.sh
   CLIENTS_DIR=/path/to/pki_artifacts/clients sudo -E ./test_bench.sh
   CLIENTS_DIR=/path/to/pki_artifacts/clients sudo -E ./proof_suite.sh
   # Evidence bundle: /tmp/proof_bundle.tar.gz
   ```

---

## 7. Operations playbooks (essentials)

### 7.1 Key rotation (envelope)
- Rotate CMK in KMS on schedule.
- For each record (or per-tenant DEK), decrypt DEK in KMS using old CMK, re-encrypt with new CMK, update `pii_wrapped_key` in DB.

### 7.2 Certificate rotation
- Re-run `outside_pki.sh` to issue new server/client certs.
- Replace `/opt/pki/server/*` atomically; `systemctl restart mysql`.
- Distribute new client certs; revoke old certs via CRL/OCSP if applicable.

### 7.3 Backup/restore
- Logical backups nightly + binlogs; store copies in WORM.
- Quarterly **restore drills**; after restore, verify `audit_events` chain continuity and re-anchor head.

### 7.4 HA/DR
- Prefer managed service for HA; or configure MySQL Group Replication in private subnets.
- Document RPO/RTO; test failover.

### 7.5 Monitoring & alerting
- Ops Agent shipping syslog/MySQL logs to Cloud Logging/SIEM.
- Alerts: failed mTLS handshakes, grant changes, schema drift, high ERR in proof runs, audit chain break detection, anchor gaps.

---

## 8. Security configuration reference

### MySQL (enforced)
- `require_secure_transport=ON`
- `ssl_cipher=TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`
- `local_infile=0`, `skip_name_resolve=ON`
- `sql_mode=STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION`
- Event scheduler enabled (anchor job)

### Network
- Default deny (UFW), 22 open, 3306 only to allowlisted CIDRs if remote access is needed.
- fail2ban active for SSH (and MySQL if logs support).

### Database roles
- `api_definer` (locked account) owns DEFINER routines and views.
- `app_user` can only `EXECUTE` API and `SELECT` tenant-scoped views.
- `auditor` can `SELECT` audit and call `security_set_tenant`.
- `migration` for DDL; no SUPER privileges.

---

## 9. Compliance evidence
Run `proof_suite.sh`. It checks:
- TLS enforced; **no-SSL connections blocked**; TLS1.3 handshake.
- mTLS client certificate validation.
- Hardened MySQL variables.
- Least privilege / proc-only writes.
- Tenant isolation.
- Audit **append-only** and chain integrity proof.
- (Optional) OpenSCAP/CIS hardening report included if `scripts/openscap_scan.sh` is run.
- FIPS/AppArmor/SELinux signals.
- Firewall and fail2ban status.
An evidence tarball is created for assessment workflows.

---

## 10. Parameters
- `vm_oneclick.sh`: `PKI_TAR=/tmp/pki_server.tar.gz`, `ALLOW_REMOTE=0|1`, `ALLOWED_CIDR="a,b,c"`
- `proof_suite.sh`/`test_bench.sh`: `CLIENTS_DIR=/path/to/pki_artifacts/clients`, `DB_HOST=ip`

---

## 11. Limitations
- PQ hybrid wrap is optional; the authoritative key protection is HSM KMS envelope encryption.
- A fully compromised client or KMS control plane can still expose plaintext.
- ATO requires independent assessment; this repository provides controls and evidence generation, not an authorization.

---

## 12. Support scripts
- `test_bench.sh`: smoke + denial tests.
- `proof_suite.sh`: generates `/tmp/proof_bundle.tar.gz` with outputs and checks.
- `anchor_head.sh` (installed by VM oneclick): emits chain head to syslog per minute.

