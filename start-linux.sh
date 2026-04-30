#!/usr/bin/env bash
# Start all AILA services (backend, workers, frontend) on Linux/macOS.
# For Windows Git Bash, use start.sh instead.
#
# Usage:
#   ./start-linux.sh          # start everything
#   ./start-linux.sh stop     # kill all AILA processes
#
# Logs are written to /tmp/aila_*.log.
# Environment is loaded from .env in the repo root.
# PID file at /tmp/aila.pids tracks spawned processes for clean shutdown.

set -e
cd "$(dirname "$0")"

COMMAND="${1:-start}"
LOG_DIR="/tmp"
PID_FILE="$LOG_DIR/aila.pids"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

load_env() {
  if [[ -f .env ]]; then
    set -a
    source .env
    set +a
    echo "[aila] .env loaded"
  else
    echo "[aila] WARNING: .env not found -- copy .env.example to .env first"
  fi
}

kill_aila_processes() {
  echo "[aila] Stopping AILA processes..."
  if [[ -f "$PID_FILE" ]]; then
    while IFS= read -r pid; do
      if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        echo "[aila]   killed PID $pid"
      fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
  else
    # Fallback: kill by pattern match.
    pkill -f "aila serve" 2>/dev/null || true
    pkill -f "aila worker" 2>/dev/null || true
    pkill -f "vite.*aila" 2>/dev/null || true
  fi
  sleep 1
  echo "[aila] Stopped."
}

record_pid() {
  echo "$1" >> "$PID_FILE"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

if [[ "$COMMAND" == "stop" ]]; then
  kill_aila_processes
  exit 0
fi

load_env
kill_aila_processes
rm -f "$PID_FILE"

# -- Backend (FastAPI via aila serve) --------------------------------------
echo "[aila] Starting backend..."
python -m aila serve --host 0.0.0.0 --port 8000 --reload \
  > "$LOG_DIR/aila_backend.log" 2>&1 &
BACKEND_PID=$!
record_pid "$BACKEND_PID"
echo "[aila]   backend PID=$BACKEND_PID (port 8000, reload enabled)"

sleep 3  # let backend initialize before workers connect

# -- Workers (ARQ over Redis) ----------------------------------------------
echo "[aila] Starting workers..."

python -m aila worker -q default \
  > "$LOG_DIR/aila_worker_default.log" 2>&1 &
record_pid "$!"
echo "[aila]   worker:default PID=$!"

python -m aila worker -q vulnerability \
  > "$LOG_DIR/aila_worker_vulnerability.log" 2>&1 &
record_pid "$!"
echo "[aila]   worker:vulnerability PID=$!"

python -m aila worker -q forensics \
  > "$LOG_DIR/aila_worker_forensics.log" 2>&1 &
record_pid "$!"
echo "[aila]   worker:forensics PID=$!"

# -- Frontend (Vite dev server on :3000) -----------------------------------
echo "[aila] Starting frontend..."
if [[ -d frontend ]]; then
  if [[ ! -d frontend/node_modules ]]; then
    echo "[aila]   node_modules missing -- running npm install..."
    (cd frontend && npm install > "$LOG_DIR/aila_frontend_install.log" 2>&1)
  fi
  (cd frontend && npm run dev > "$LOG_DIR/aila_frontend.log" 2>&1 &)
  record_pid "$!"
  echo "[aila]   frontend launched (port 3000)"
else
  echo "[aila]   WARNING: frontend/ not found -- skipping"
fi

# -- Health check ----------------------------------------------------------
sleep 5

echo ""
echo "[aila] Health check:"
curl -sf http://localhost:8000/health 2>/dev/null \
  | python3 -m json.tool 2>/dev/null \
  || echo "  backend not ready yet (check $LOG_DIR/aila_backend.log)"

curl -sfI http://localhost:3000 2>/dev/null \
  | head -n 1 \
  || echo "  frontend not ready yet (check $LOG_DIR/aila_frontend.log)"

echo ""
echo "[aila] All services started. Logs:"
echo "  backend:          $LOG_DIR/aila_backend.log"
echo "  worker:default:   $LOG_DIR/aila_worker_default.log"
echo "  worker:vuln:      $LOG_DIR/aila_worker_vulnerability.log"
echo "  worker:forensics: $LOG_DIR/aila_worker_forensics.log"
echo "  frontend:         $LOG_DIR/aila_frontend.log"
echo ""
echo "  Stop all: ./start-linux.sh stop"
echo "  PIDs:     cat $PID_FILE"
