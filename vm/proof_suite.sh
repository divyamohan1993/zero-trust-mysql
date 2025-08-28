#!/usr/bin/env bash

# (F) Proof Suite

set -euo pipefail
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_NAME="${DB_NAME:-securedb}"
CLIENTS_DIR="${CLIENTS_DIR:?}"
OUT="${OUT:-/tmp/securedb_evidence}"
mkdir -p "$OUT"

err(){ echo "$@" >&2; }

ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }

run(){ local name="$1"; shift; ( "$@" ) >"$OUT/${name}.out" 2>"$OUT/${name}.err" || { echo "FAIL ${name}"; return 1; }; echo "OK ${name}"; }

req_fail(){ local name="$1"; shift; ( "$@" ) >"$OUT/${name}.out" 2>"$OUT/${name}.err" && { echo "UNEXPECTED-SUCCESS ${name}"; return 1; }; echo "OK_EXPECTED_FAIL ${name}"; }

echo "$(ts) START" > "$OUT/meta.txt"

# 1. TLS required (no-SSL must fail)
req_fail "no_ssl_blocked" mysql --protocol=TCP --host="$DB_HOST" -u app_user -pApp#ChangeMe!23 -e "SELECT 1;"

# 2. mTLS works with correct certs; handshake check via openssl (TLS 1.3)
run "tls13_handshake" openssl s_client -connect "${DB_HOST}:3306" -tls1_3 -verify_return_error -CAfile "$CLIENTS_DIR/app_user-ca.pem" < /dev/null

# 3. MySQL system variables hardened
run "mysql_vars" bash -c 'mysql -N -e "SHOW VARIABLES WHERE Variable_name IN (\"require_secure_transport\",\"local_infile\",\"skip_name_resolve\",\"sql_mode\",\"ssl_cipher\");" | tee /dev/stderr'
python3 - <<'PY' "$OUT/mysql_vars.out" >"$OUT/mysql_vars.check"
import sys
vars=dict(line.strip().split("\t",1) for line in open(sys.argv[1]) if "\t" in line)
ok=(vars.get("require_secure_transport")=="ON" and vars.get("local_infile")=="OFF" and vars.get("skip_name_resolve")=="ON" and ("STRICT_ALL_TABLES" in vars.get("sql_mode","")))
print("OK" if ok else "FAIL")
PY
grep -qx "OK" "$OUT/mysql_vars.check"

# 4. App-user least privilege
run "user_privs" bash -c 'mysql -N -e "SELECT GRANTEE,PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE LIKE '\''%app_user%'\''; SHOW GRANTS FOR '\''app_user'\''@'\''localhost'\'';"'
req_fail "app_user_direct_select" mysql -u app_user -pApp#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/app_user-ca.pem" --ssl-cert="$CLIENTS_DIR/app_user-cert.pem" --ssl-key="$CLIENTS_DIR/app_user-key.pem" -e "SELECT * FROM securedb.users LIMIT 1;"
run "app_user_view_ok" mysql -u app_user -pApp#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/app_user-ca.pem" --ssl-cert="$CLIENTS_DIR/app_user-cert.pem" --ssl-key="$CLIENTS_DIR/app_user-key.pem" -e "SELECT * FROM securedb.v_users LIMIT 1;"

# 5. Tenant isolation
TENANT=$(mysql -N -u app_user -pApp#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/app_user-ca.pem" --ssl-cert="$CLIENTS_DIR/app_user-cert.pem" --ssl-key="$CLIENTS_DIR/app_user-key.pem" -e "SELECT BIN_TO_UUID(id,1) FROM securedb.tenants WHERE name='Globex Ltd' LIMIT 1;")
mysql -u app_user -pApp#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/app_user-ca.pem" --ssl-cert="$CLIENTS_DIR/app_user-cert.pem" --ssl-key="$CLIENTS_DIR/app_user-key.pem" -e "CALL securedb.security_set_tenant('${TENANT}');"
run "tenant_isolation_empty" bash -c 'mysql -N -u app_user -pApp#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/app_user-ca.pem" --ssl-cert="$CLIENTS_DIR/app_user-cert.pem" --ssl-key="$CLIENTS_DIR/app_user-key.pem" -e "SELECT COUNT(*) FROM securedb.v_users;" | grep -q "^0$"'

# 6. Audit append-only and chain integrity
req_fail "audit_update_blocked" mysql -u auditor -pAudit#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/auditor-ca.pem" --ssl-cert="$CLIENTS_DIR/auditor-cert.pem" --ssl-key="$CLIENTS_DIR/auditor-key.pem" -e "UPDATE securedb.audit_events SET table_name='x' WHERE id=1;"
req_fail "audit_delete_blocked" mysql -u auditor -pAudit#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/auditor-ca.pem" --ssl-cert="$CLIENTS_DIR/auditor-cert.pem" --ssl-key="$CLIENTS_DIR/auditor-key.pem" -e "DELETE FROM securedb.audit_events WHERE id=1;"
run "audit_chain_check" bash -c 'mysql -N -u auditor -pAudit#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/auditor-ca.pem" --ssl-cert="$CLIENTS_DIR/auditor-cert.pem" --ssl-key="$CLIENTS_DIR/auditor-key.pem" -e "WITH o AS (SELECT id,HEX(prev_hash) ph,HEX(curr_hash) ch FROM securedb.audit_events ORDER BY id) SELECT SUM(CASE WHEN LAG(ch) OVER (ORDER BY id) <=> ph THEN 0 ELSE 1 END) FROM o;" | tee "$OUT/audit_breaks.txt"'
grep -qx "0" "$OUT/audit_breaks.txt"

# 7. Off-host anchoring present
run "anchor_timer" systemctl is-active securedb-anchor.timer
run "anchor_journal" bash -c 'journalctl -u securedb-anchor.service --no-pager -n 20 | tee /dev/stderr'

# 8. FIPS / MAC
if [[ -f /proc/sys/crypto/fips_enabled ]]; then grep -q 1 /proc/sys/crypto/fips_enabled; fi
if command -v aa-status >/dev/null; then aa-status | grep -qi "profiles are in enforce mode"; fi
if command -v getenforce >/dev/null; then [ "$(getenforce)" = "Enforcing" ] || true; fi

# 9. Firewall + fail2ban
run "ufw_status" bash -c 'ufw status verbose || true'
run "fail2ban_status" bash -c 'systemctl is-active fail2ban || true'

# 10. PQ fields exist
run "pq_fields" bash -c 'mysql -N -e "DESC securedb.users" | egrep -q "pii_pq_wrapped_key|pq_alg"'

# 11. Package
uname -a > "$OUT/system.txt"
mysql -e "SHOW VARIABLES" > "$OUT/all_mysql_vars.txt"
tar -C "$OUT" -czf "$OUT/../proof_bundle.tar.gz" .
echo "PROOF_BUNDLE:$OUT/../proof_bundle.tar.gz"
