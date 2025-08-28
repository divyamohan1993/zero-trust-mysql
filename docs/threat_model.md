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