#!/usr/bin/env bash
# Start all AILA services (backend, workers, frontend) on Windows.
# For Linux/macOS, use start-linux.sh instead.
#
# Usage:
#   bash start.sh          # start everything
#   bash start.sh stop     # kill all AILA processes
#
# Environment is loaded from .env in the repo root.

set -e
cd "$(dirname "$0")"

COMMAND="${1:-start}"

# Auto-detect PowerShell. Git Bash mangles PATH; try common locations.
PS=""
for candidate in \
  powershell.exe \
  powershell \
  /c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe \
  /c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe; do
  if command -v "$candidate" >/dev/null 2>&1 || [[ -x "$candidate" ]]; then
    PS="$candidate"
    break
  fi
done
if [[ -z "$PS" ]]; then
  echo "[aila] ERROR: PowerShell not found. Add to PATH or run services manually."
  exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

load_env() {
  if [[ -f .env ]]; then
    set -a
    source <(sed 's/\r//' .env)
    set +a
    echo "[aila] .env loaded"
  else
    echo "[aila] WARNING: .env not found -- copy .env.example to .env first"
  fi
}

kill_aila_processes() {
  echo "[aila] Stopping AILA processes..."
  "$PS" -NoProfile -Command \
    "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | \
     Where-Object { \$_.CommandLine -match 'aila' } | \
     ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }" \
    2>/dev/null || true

  "$PS" -NoProfile -Command \
    "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | \
     Where-Object { \$_.CommandLine -match 'vite|aila-frontend' } | \
     ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }" \
    2>/dev/null || true

  sleep 2
  echo "[aila] Stopped."
}

# Spawn a detached Python process via PowerShell Start-Process.
# Git Bash nohup+& does NOT persist children on Windows.
spawn() {
  local label="$1"; shift
  # Build comma-separated PowerShell argument list.
  local ps_args=""
  for arg in "$@"; do
    if [[ -n "$ps_args" ]]; then ps_args="$ps_args,"; fi
    ps_args="${ps_args}'${arg}'"
  done
  "$PS" -NoProfile -Command \
    "Start-Process python -ArgumentList $ps_args -WindowStyle Hidden"
  echo "[aila]   $label started"
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

# -- Backend ---------------------------------------------------------------
echo "[aila] Starting backend..."
spawn "backend (port 8000)" -m aila serve --host 0.0.0.0 --port 8000 --reload
sleep 4

# -- Workers ---------------------------------------------------------------
echo "[aila] Starting workers..."
spawn "worker:default"       -m aila worker -q default
spawn "worker:vulnerability" -m aila worker -q vulnerability
spawn "worker:forensics"     -m aila worker -q forensics

# -- Frontend --------------------------------------------------------------
echo "[aila] Starting frontend..."
if [[ -d frontend ]]; then
  if [[ ! -d frontend/node_modules ]]; then
    echo "[aila]   node_modules missing -- running npm install..."
    (cd frontend && npm install 2>&1 | tail -1)
  fi
  (cd frontend && nohup npm run dev > /dev/null 2>&1 &)
  echo "[aila]   frontend started (port 3000)"
else
  echo "[aila]   WARNING: frontend/ not found -- skipping"
fi

# -- Health check ----------------------------------------------------------
echo ""
echo "[aila] Waiting for services..."
sleep 8

echo "[aila] Health check:"
curl -sf http://localhost:8000/health 2>/dev/null \
  | python -m json.tool 2>/dev/null \
  || echo "  backend not ready yet"

echo ""
echo "[aila] Done. Stop all: bash start.sh stop"
