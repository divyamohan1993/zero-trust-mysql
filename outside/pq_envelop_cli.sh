#!/usr/bin/env python3

# (C) Outside: PQ+KMS envelope CLI

import os, sys, json, base64, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.cloud import kms
import oqs

def enc(kms_key, email, phone, aad=""):
    dek = secrets.token_bytes(32)
    a = AESGCM(dek)
    e_iv = secrets.token_bytes(12)
    p_iv = secrets.token_bytes(12)
    aad_b = aad.encode() if aad else b""
    email_ct = a.encrypt(e_iv, email.encode(), aad_b)
    phone_ct = a.encrypt(p_iv, phone.encode(), aad_b)
    c = kms.KeyManagementServiceClient()
    wrapped = c.encrypt(request={"name": kms_key, "plaintext": dek}).ciphertext
    with oqs.KeyEncapsulation("Kyber768") as kem:
        pk = kem.generate_keypair()
        ct_pq, ss = kem.encap_secret(pk)
        if ss != kem.decap_secret(ct_pq):
            raise SystemExit(1)
    return {
        "wrapped_key_b64": base64.b64encode(wrapped).decode(),
        "pq_wrapped_b64": base64.b64encode(ct_pq).decode(),
        "pq_alg": "Kyber768",
        "kms_key_name": kms_key,
        "email_ct_b64": base64.b64encode(email_ct).decode(),
        "email_iv_hex": e_iv.hex(),
        "email_aad_b64": base64.b64encode(aad_b).decode(),
        "phone_ct_b64": base64.b64encode(phone_ct).decode(),
        "phone_iv_hex": p_iv.hex(),
        "phone_aad_b64": base64.b64encode(aad_b).decode()
    }

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("usage: pq_envelope_cli.py <kms-key-resource> <tenant-uuid> <full-name> <role> [email] [phone] [aad]")
        sys.exit(2)
    kms_key, tenant, full_name, role = sys.argv[1:5]
    email = sys.argv[5] if len(sys.argv)>5 else "alice@example.com"
    phone = sys.argv[6] if len(sys.argv)>6 else "+12025550101"
    aad = sys.argv[7] if len(sys.argv)>7 else ""
    out = enc(kms_key, email, phone, aad)
    print(json.dumps({"tenant":tenant,"full_name":full_name,"role":role,**out}, separators=(',',':')))
