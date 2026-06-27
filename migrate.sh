#!/usr/bin/env bash
# Run Alembic migrations against the AILA database.
# Usage:  ./migrate.sh               -- upgrade to head
#         ./migrate.sh downgrade -1  -- pass any alembic sub-commands after migrate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[migrate] ERROR: .env not found at $ENV_FILE" >&2
  exit 1
fi

# Load .env -- strip Windows CR and skip blank/comment lines.
while IFS='=' read -r key val; do
  [[ -z "$key" || "$key" == \#* ]] && continue
  val="${val%$'\r'}"
  export "$key=$val"
done < <(sed 's/\r//' "$ENV_FILE")

if [[ -z "${AILA_DATABASE_URL:-}" ]]; then
  echo "[migrate] ERROR: AILA_DATABASE_URL not set in .env" >&2
  exit 1
fi

ALEMBIC_INI="$SCRIPT_DIR/src/aila/alembic.ini"
CMD="${1:-upgrade}"
ARG="${2:-head}"

echo "[migrate] $CMD $ARG  (db: ${AILA_DATABASE_URL%%@*}@...)"
alembic -c "$ALEMBIC_INI" "$CMD" "$ARG"
