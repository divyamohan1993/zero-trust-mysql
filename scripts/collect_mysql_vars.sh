#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-evidence/mysql_vars.json}"
mkdir -p "$(dirname "$OUT")"
mysql -N -e "SHOW VARIABLES WHERE Variable_name IN ('require_secure_transport','local_infile','skip_name_resolve','sql_mode');" \
| awk -F'\t' 'BEGIN{print "{"}{printf "\"%s\":\"%s\",",$1,$2}END{print "\"_ts\":\""strftime("%Y-%m-%dT%H:%M:%SZ")"\"}"}' > "$OUT"
jq . "$OUT" >/dev/null
echo "$OUT"