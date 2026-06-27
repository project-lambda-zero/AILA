#!/usr/bin/env bash
#
# AILA dev teardown -- destroys local Postgres + Redis data with double confirmation.
#
# Usage:
#   make teardown               # interactive double-confirm prompt
#   make teardown CONFIRM=YES   # CI / automated path (one-shot, still asks once)
#   ./scripts/teardown.sh --force  # skip ALL prompts (dangerous; for scripts only)
#
# What gets wiped:
#   - docker compose stack at infra/utilities/docker-compose.yml (containers stopped)
#   - aila_postgres_data volume (entire database)
#   - aila_redis_data volume (queue state, sessions, cached data)
#
# What is NOT wiped:
#   - .env file
#   - source code or local edits
#   - .venv or node_modules
#   - any host-side directories (data/, reports/, logs/)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/infra/utilities/docker-compose.yml"
COMPOSE="docker compose -f $COMPOSE_FILE"

POSTGRES_VOLUME="aila_postgres_data"
REDIS_VOLUME="aila_redis_data"

red()    { printf "\033[0;31m%s\033[0m\n" "$*"; }
yellow() { printf "\033[0;33m%s\033[0m\n" "$*"; }
green()  { printf "\033[0;32m%s\033[0m\n" "$*"; }
cyan()   { printf "\033[0;36m%s\033[0m\n" "$*"; }

force=false
if [[ "${1:-}" == "--force" ]]; then
  force=true
fi

echo ""
red "================================================================"
red "  AILA -- DEV INFRASTRUCTURE TEARDOWN"
red "================================================================"
echo ""
yellow "This will PERMANENTLY DELETE:"
echo "  - Postgres database volume    : $POSTGRES_VOLUME"
echo "  - Redis data volume           : $REDIS_VOLUME"
echo "  - Running containers          : aila-postgres, aila-redis"
echo ""
yellow "After teardown, the next 'make dev-up' starts with a fresh database."
yellow "You'll need to run 'make db-init' again."
echo ""

# --- volume size summary so the user knows what they're about to lose ---
if command -v docker >/dev/null 2>&1; then
  echo "Current volume sizes:"
  for vol in "$POSTGRES_VOLUME" "$REDIS_VOLUME"; do
    if docker volume inspect "$vol" >/dev/null 2>&1; then
      mountpoint="$(docker volume inspect -f '{{.Mountpoint}}' "$vol")"
      size="$(sudo du -sh "$mountpoint" 2>/dev/null | cut -f1 || echo '?')"
      echo "  - $vol : $size"
    else
      echo "  - $vol : (volume does not exist)"
    fi
  done
  echo ""
fi

if [[ "$force" == "true" ]]; then
  yellow "--force passed; skipping all prompts."
else
  # First confirmation: typed acknowledgement
  cyan "Step 1 of 2: type 'destroy' (lowercase) to acknowledge the wipe."
  read -r -p "> " ack1
  if [[ "$ack1" != "destroy" ]]; then
    green "Aborted. Nothing was deleted."
    exit 1
  fi

  # Second confirmation: y/N prompt
  echo ""
  cyan "Step 2 of 2: are you ABSOLUTELY sure? Type 'YES' (uppercase) to proceed."
  read -r -p "> " ack2
  if [[ "$ack2" != "YES" ]]; then
    green "Aborted. Nothing was deleted."
    exit 1
  fi

  echo ""
  yellow "Both confirmations received. Proceeding in 3 seconds (Ctrl-C to abort)..."
  sleep 1; echo "  3..."
  sleep 1; echo "  2..."
  sleep 1; echo "  1..."
  echo ""
fi

# --- the actual teardown ---
yellow "Stopping compose stack and removing volumes..."
if [[ -f "$COMPOSE_FILE" ]]; then
  $COMPOSE down -v
else
  red "Compose file not found at $COMPOSE_FILE -- falling back to direct volume rm."
  docker rm -f aila-postgres aila-redis 2>/dev/null || true
  docker volume rm "$POSTGRES_VOLUME" "$REDIS_VOLUME" 2>/dev/null || true
fi

echo ""
green "Teardown complete."
echo ""
echo "Next steps:"
echo "  make dev-up      # start fresh containers"
echo "  make db-init     # recreate schema + stamp head"
echo "  make backend     # boot uvicorn (will create admin user from AILA_ADMIN_PASSWORD)"
