#!/usr/bin/env bash
set -euo pipefail
DEST="${1:-/var/backups/securedb}"
mkdir -p "$DEST"
mysqldump --single-transaction --hex-blob securedb > "$DEST/securedb.sql"
mysql -e "SHOW BINARY LOGS" > "$DEST/binlogs.txt" || true
echo "$DEST"