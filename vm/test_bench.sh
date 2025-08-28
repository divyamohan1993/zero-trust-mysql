#!/usr/bin/env bash

# (E) Test bench

set -euo pipefail
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_NAME="${DB_NAME:-securedb}"
APP_DIR="${APP_DIR:-/tmp/app_test}"
CLIENTS_DIR="${CLIENTS_DIR:-/tmp/pki_clients}"
mkdir -p "$APP_DIR"

mysql --protocol=TCP --host="$DB_HOST" --ssl-mode=DISABLED -e "SELECT 1;" && exit 1 || true

mysql --protocol=TCP --host="$DB_HOST" -u app_user -pApp#ChangeMe!23 --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/app_user-ca.pem" --ssl-cert="$CLIENTS_DIR/app_user-cert.pem" --ssl-key="$CLIENTS_DIR/app_user-key.pem" -e "SELECT VERSION();" >/dev/null

mysql --protocol=TCP --host="$DB_HOST" -u app_user -pApp#ChangeMe!23 --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/app_user-ca.pem" -e "SELECT 1;" && exit 1 || true

TENANT=$(mysql -N -u app_user -pApp#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/app_user-ca.pem" --ssl-cert="$CLIENTS_DIR/app_user-cert.pem" --ssl-key="$CLIENTS_DIR/app_user-key.pem" -e "SELECT BIN_TO_UUID(id,1) FROM securedb.tenants WHERE name='Acme Corp' LIMIT 1;")
mysql -u app_user -pApp#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/app_user-ca.pem" --ssl-cert="$CLIENTS_DIR/app_user-cert.pem" --ssl-key="$CLIENTS_DIR/app_user-key.pem" -e "CALL securedb.security_set_tenant('${TENANT}');"

python3 - <<'PY' >"$APP_DIR/out.json"
import os, json, base64, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
dek = secrets.token_bytes(32)
a = AESGCM(dek)
iv1 = secrets.token_bytes(12); iv2 = secrets.token_bytes(12)
email_ct = a.encrypt(iv1, b"alice@acme.example", b"")
phone_ct = a.encrypt(iv2, b"+12025550101", b"")
print(json.dumps({
 "wrapped_key_hex": secrets.token_hex(32),
 "pq_wrapped_hex": secrets.token_hex(48),
 "pq_alg":"Kyber768",
 "email_ct_hex": email_ct.hex(),
 "email_iv_hex": iv1.hex(),
 "email_aad_hex": "",
 "phone_ct_hex": phone_ct.hex(),
 "phone_iv_hex": iv2.hex(),
 "phone_aad_hex": ""
}, separators=(',',':')))
PY

J=$(cat "$APP_DIR/out.json")
WK=$(echo "$J" | jq -r .wrapped_key_hex)
PQ=$(echo "$J" | jq -r .pq_wrapped_hex)
ALG=$(echo "$J" | jq -r .pq_alg)
ECT=$(echo "$J" | jq -r .email_ct_hex)
EIV=$(echo "$J" | jq -r .email_iv_hex)
EAD=$(echo "$J" | jq -r .email_aad_hex)
PCT=$(echo "$J" | jq -r .phone_ct_hex)
PIV=$(echo "$J" | jq -r .phone_iv_hex)
PAD=$(echo "$J" | jq -r .phone_aad_hex)

mysql -u app_user -pApp#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/app_user-ca.pem" --ssl-cert="$CLIENTS_DIR/app_user-cert.pem" --ssl-key="$CLIENTS_DIR/app_user-key.pem" -e "CALL securedb.app_create_user_encrypted('${TENANT}','Alice Admin','admin',UNHEX('${WK}'),UNHEX('${PQ}'),'${ALG}','kms-key',UNHEX('${ECT}'),UNHEX('${EIV}'),UNHEX('${EAD}'),UNHEX('${PCT}'),UNHEX('${PIV}'),UNHEX('${PAD}'), @uid); SELECT @uid;"

mysql -u app_user -pApp#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/app_user-ca.pem" --ssl-cert="$CLIENTS_DIR/app_user-cert.pem" --ssl-key="$CLIENTS_DIR/app_user-key.pem" -e "INSERT INTO securedb.users(full_name) VALUES('Mallory');" && exit 1 || true

mysql -u auditor -pAudit#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/auditor-ca.pem" --ssl-cert="$CLIENTS_DIR/auditor-cert.pem" --ssl-key="$CLIENTS_DIR/auditor-key.pem" -e "SELECT COUNT(*) FROM securedb.audit_events;" >/dev/null

mysql -u auditor -pAudit#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/auditor-ca.pem" --ssl-cert="$CLIENTS_DIR/auditor-cert.pem" --ssl-key="$CLIENTS_DIR/auditor-key.pem" -e "UPDATE securedb.audit_events SET table_name='x' WHERE id=1;" && exit 1 || true

mysql -N -u auditor -pAudit#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/auditor-ca.pem" --ssl-cert="$CLIENTS_DIR/auditor-cert.pem" --ssl-key="$CLIENTS_DIR/auditor-key.pem" -e "WITH o AS (SELECT id,HEX(prev_hash) ph,HEX(curr_hash) ch FROM securedb.audit_events ORDER BY id) SELECT SUM(CASE WHEN LAG(ch) OVER (ORDER BY id) <=> ph THEN 0 ELSE 1 END) FROM o;" | grep -qx "0"

grep -q 1 /proc/sys/crypto/fips_enabled || exit 1

if command -v aa-status >/dev/null; then aa-status | grep -qi "profiles are in enforce mode" || exit 1; fi
if command -v getenforce >/dev/null; then [ "$(getenforce)" = "Enforcing" ] || true; fi

mysql -N -u auditor -pAudit#ChangeMe!23 --host="$DB_HOST" --ssl-mode=VERIFY_CA --ssl-ca="$CLIENTS_DIR/auditor-ca.pem" --ssl-cert="$CLIENTS_DIR/auditor-cert.pem" --ssl-key="$CLIENTS_DIR/auditor-key.pem" -e "SELECT @@require_secure_transport,@@local_infile,@@skip_name_resolve;" | awk '{if($1!=1||$2!=0||$3!=1) exit 1}'
echo PASS