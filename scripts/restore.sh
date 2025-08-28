#!/usr/bin/env bash
set -euo pipefail
SRC="${1:?}"
mysql < "$SRC/securedb.sql"