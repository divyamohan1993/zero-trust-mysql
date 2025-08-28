#!/usr/bin/env bash

# (B) Outside: GCP KMS + Logging + WORM

set -euo pipefail
PROJECT_ID="${PROJECT_ID:?}"
REGION="${REGION:-asia-south1}"
KRING="${KRING:-secdb-ring}"
KNAME="${KNAME:-pii-wrap-key}"
BUCKET="${BUCKET:?}"
SINK="${SINK:-audit-chain-head-sink}"
gcloud config set project "$PROJECT_ID"
gcloud kms keyrings create "$KRING" --location "$REGION" || true
gcloud kms keys create "$KNAME" --location "$REGION" --keyring "$KRING" --purpose=encryption --protection-level=hsm || true
gcloud storage buckets create "gs://${BUCKET#gs://}" --location="$REGION" --uniform-bucket-level-access --pap --no-public-access --default-storage-class=STANDARD || true
gcloud storage buckets retention set 30d "$BUCKET"
gcloud storage buckets retention lock "$BUCKET"
FILTER='resource.type="gce_instance" AND (logName:"syslog" OR logName:"system") AND textPayload:"AUDIT_CHAIN_HEAD"'
gcloud logging sinks create "$SINK" "$BUCKET" --log-filter="$FILTER" || true
SA_EMAIL=$(gcloud logging sinks describe "$SINK" --format="value(writerIdentity)")
gcloud storage buckets add-iam-policy-binding "$BUCKET" --member="$SA_EMAIL" --role="roles/storage.objectCreator"
printf "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s\n" "$PROJECT_ID" "$REGION" "$KRING" "$KNAME"
