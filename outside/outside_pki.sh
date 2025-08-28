#!/usr/bin/env bash

# (A) Outside: PKI generator

set -euo pipefail
OUT="${OUT:-./pki_artifacts}"
CN_SERVER="${CN_SERVER:-server.local}"
DAYS="${DAYS:-3650}"
mkdir -p "$OUT"/clients "$OUT"/server
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/ca-key.pem"
openssl req -x509 -new -key "$OUT/ca-key.pem" -sha384 -days "$DAYS" -subj "/CN=SecureDB-CA" -out "$OUT/ca-cert.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/server-key.pem"
openssl req -new -key "$OUT/server-key.pem" -subj "/CN=${CN_SERVER}" -out "$OUT/server.csr"
openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca-cert.pem" -CAkey "$OUT/ca-key.pem" -CAcreateserial -out "$OUT/server-cert.pem" -days "$DAYS" -sha384 -extfile <(printf "subjectAltName=DNS:%s,IP:127.0.0.1" "$CN_SERVER")
cp "$OUT/server-cert.pem" "$OUT/server/server-cert.pem"
cp "$OUT/server-key.pem" "$OUT/server/server-key.pem"
cp "$OUT/ca-cert.pem" "$OUT/server/ca-cert.pem"
for u in app_user auditor migration; do
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/clients/${u}-key.pem"
  openssl req -new -key "$OUT/clients/${u}-key.pem" -subj "/CN=${u}" -out "$OUT/clients/${u}.csr"
  openssl x509 -req -in "$OUT/clients/${u}.csr" -CA "$OUT/ca-cert.pem" -CAkey "$OUT/ca-key.pem" -CAcreateserial -out "$OUT/clients/${u}-cert.pem" -days "$DAYS" -sha384
  cp "$OUT/ca-cert.pem" "$OUT/clients/${u}-ca.pem"
done
tar -C "$OUT/server" -czf "$OUT/pki_server.tar.gz" .
printf "%s\n" "$OUT"