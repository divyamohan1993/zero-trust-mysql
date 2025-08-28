#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-evidence/openscap}"
PROFILE="${PROFILE:-xccdf_org.ssgproject.content_profile_stig}"
mkdir -p "$OUT"
oscap xccdf eval --profile "$PROFILE" --results "$OUT/results.xml" --report "$OUT/report.html" /usr/share/xml/scap/ssg/content/*-ds.xml || true
echo "$OUT"