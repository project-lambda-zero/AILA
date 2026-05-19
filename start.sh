#!/usr/bin/env bash
# Start every AILA service on Windows (Git Bash) in one shot.
# For Linux/macOS, use start-linux.sh instead.
#
# Usage:
#   bash start.sh           # start everything
#   bash start.sh restart   # stop + start
#   bash start.sh stop      # kill every spawned process
#   bash start.sh status    # show running procs + endpoint health
#
# Services started:
#   audit-mcp            HTTP on  ${AUDIT_MCP_PORT:-18822}  (toggle: AILA_START_AUDIT_MCP=0)
#   AILA backend         uvicorn on ${BACKEND_PORT:-8000}
#   AILA workers         one per queue in $WORKERS
#   AILA frontend        Vite on ${FRONTEND_PORT:-3000}     (toggle: AILA_START_FRONTEND=0)
#
# Env overrides (read from .env or shell):
#   BACKEND_PORT          default 8000
#   FRONTEND_PORT         default 3000
#   AUDIT_MCP_PORT        default 18822
#   WORKERS               default "default vr vulnerability forensics sbd_nfr"
#   AUDIT_MCP_DIR         default ../audit-mcp (relative to repo root)
#   AILA_START_FRONTEND   1/0 (default 1)
#   AILA_START_AUDIT_MCP  1/0 (default 1)

set -e
cd "$(dirname "$0")"

COMMAND="${1:-start}"

# ── Defaults ────────────────────────────────────────────────────────────────
: "${BACKEND_PORT:=8000}"
: "${FRONTEND_PORT:=3000}"
: "${AUDIT_MCP_PORT:=18822}"
: "${WORKERS:=default vr vulnerability forensics sbd_nfr}"
: "${AUDIT_MCP_DIR:=../audit-mcp}"
: "${AILA_START_FRONTEND:=1}"
: "${AILA_START_AUDIT_MCP:=1}"

# ── PowerShell detection ────────────────────────────────────────────────────
PS=""
for candidate in \
  powershell.exe \
  powershell \
  /c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe \
  /c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe; do
  if command -v "$candidate" >/dev/null 2>&1; then
    PS="$candidate"
    break
  fi
done
if [[ -z "$PS" ]]; then
  echo "[aila] ERROR: powershell not found in PATH" >&2
  exit 1
fi

# ── Helpers ─────────────────────────────────────────────────────────────────

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

kill_matching() {
  local exe="$1"; shift
  local pattern=""
  for p in "$@"; do
    [[ -n "$pattern" ]] && pattern+="|"
    pattern+="$p"
  done
  [[ -z "$pattern" ]] && return 0
  "$PS" -NoProfile -Command \
    "Get-CimInstance Win32_Process -Filter \"Name='$exe'\" | \
     Where-Object { \$_.CommandLine -match '$pattern' } | \
     ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }" \
    2>/dev/null || true
}

kill_by_cmdline_substring() {
  # Kill every python.exe whose cmdline contains the given
  # substring. Broader than ``kill_matching`` because uvicorn's
  # --reload child workers, manually-spawned helpers, and stray
  # test runs all have slightly different cmdlines but share the
  # ``aila`` token. Catching all of them prevents the
  # multiple-listeners-on-8000 problem where stale module caches
  # served stale code.
  local needle="$1"
  "$PS" -NoProfile -Command \
    "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | \
     Where-Object { \$_.CommandLine -like '*${needle}*' } | \
     ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }" \
    2>/dev/null || true
}

kill_port_owner() {
  # Find whatever owns ``port`` and kill it. Last-resort cleanup
  # for ghost listeners — Windows sometimes shows stale PIDs in
  # netstat after a hard kill, and the next bind fails because
  # the OS still has the socket. ``Stop-Process`` on the owner
  # forces TCP cleanup so the next ``Start-Process`` can bind.
  local port="$1"
  "$PS" -NoProfile -Command \
    "Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | \
     ForEach-Object { Stop-Process -Id \$_.OwningProcess -Force -ErrorAction SilentlyContinue }" \
    2>/dev/null || true
}

kill_aila_processes() {
  echo "[aila] Stopping AILA processes..."
  # First pass: cmdline-substring kill catches everything with
  # ``aila`` in its command line — uvicorn parent + --reload child,
  # all 5 workers, audit_mcp, helper scripts, test runners.
  kill_by_cmdline_substring "aila"
  kill_by_cmdline_substring "audit_mcp"
  kill_by_cmdline_substring "ida_headless_mcp"
  # Second pass: kill any process still listening on the ports
  # we own. Catches the case where the cmdline match missed a
  # straggler (different exe name, hidden window, etc.).
  kill_port_owner "${BACKEND_PORT:-8000}"
  kill_port_owner "${AUDIT_MCP_PORT:-18822}"
  # Frontend: kill node processes running our vite shell.
  kill_matching "node.exe" "vite|aila/shell"
  sleep 2
  echo "[aila] Stopped."
}

# Spawn detached python via PowerShell Start-Process. Inherits the CALLER's
# cwd — caller must `cd` into the right repo before invoking spawn.
# This is the same minimal pattern that worked before — no -WorkingDirectory,
# no -RedirectStandardOutput. Logs go to a file via the bash redirect on the
# spawn call itself (see audit-mcp / backend / worker sections below).
spawn() {
  local label="$1"; shift
  local ps_args=""
  for arg in "$@"; do
    [[ -n "$ps_args" ]] && ps_args+=","
    ps_args+="'${arg}'"
  done
  "$PS" -NoProfile -Command \
    "Start-Process python -ArgumentList $ps_args -WindowStyle Hidden"
  echo "[aila]   $label started"
}

# pnpm dev needs cmd as shell host — Start-Process cmd /c "<cmd>" runs
# from caller's cwd just like spawn().
spawn_shell() {
  local label="$1"; shift
  local cmdline="$*"
  "$PS" -NoProfile -Command \
    "Start-Process cmd -ArgumentList '/c','$cmdline' -WindowStyle Hidden"
  echo "[aila]   $label started"
}

probe() {
  local label="$1"
  local url="$2"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url" 2>/dev/null || echo "000")
  if [[ "$code" =~ ^[123][0-9][0-9]$ || "$code" == "401" ]]; then
    echo "  ✓ $label  ($code)"
  else
    echo "  ✗ $label  ($code)"
  fi
}

show_status() {
  echo "[aila] Live processes:"
  "$PS" -NoProfile -Command \
    "Get-CimInstance Win32_Process -Filter \"Name='python.exe' OR Name='node.exe'\" | \
     Where-Object { \$_.CommandLine -match 'uvicorn aila|aila worker|audit_mcp|vite' } | \
     ForEach-Object { 'PID {0,6}  {1}' -f \$_.ProcessId, \$_.CommandLine.Substring(0, [Math]::Min(110, \$_.CommandLine.Length)) }" \
    2>/dev/null || true
  echo ""
  echo "[aila] Endpoint health:"
  probe "backend  http://127.0.0.1:${BACKEND_PORT}/health" "http://127.0.0.1:${BACKEND_PORT}/health"
  probe "backend  http://127.0.0.1:${BACKEND_PORT}/vr/projects (auth)" "http://127.0.0.1:${BACKEND_PORT}/vr/projects"
  probe "audit-mcp http://127.0.0.1:${AUDIT_MCP_PORT}/tools" "http://127.0.0.1:${AUDIT_MCP_PORT}/tools"
  probe "frontend http://127.0.0.1:${FRONTEND_PORT}/" "http://127.0.0.1:${FRONTEND_PORT}/"
}

# ── Commands ────────────────────────────────────────────────────────────────

case "$COMMAND" in
  stop)    kill_aila_processes; exit 0 ;;
  status)  show_status; exit 0 ;;
  restart) kill_aila_processes ;;
  start)   ;;
  *)       echo "[aila] Unknown command: $COMMAND (start|stop|restart|status)" >&2; exit 1 ;;
esac

REPO="$PWD"

load_env
kill_aila_processes

# ── audit-mcp (in its own repo) ─────────────────────────────────────────────
if [[ "$AILA_START_AUDIT_MCP" == "1" && -d "$AUDIT_MCP_DIR" ]]; then
  echo "[aila] Starting audit-mcp..."
  (
    cd "$AUDIT_MCP_DIR" && \
    spawn "audit-mcp (port ${AUDIT_MCP_PORT})" \
      -m audit_mcp --mode http --port "$AUDIT_MCP_PORT" --host 127.0.0.1
  )
elif [[ "$AILA_START_AUDIT_MCP" == "1" ]]; then
  echo "[aila]   WARNING: AUDIT_MCP_DIR not found: $AUDIT_MCP_DIR (skipping audit-mcp)"
else
  echo "[aila]   audit-mcp disabled (AILA_START_AUDIT_MCP=0)"
fi

# ── Backend ─────────────────────────────────────────────────────────────────
echo "[aila] Starting backend..."
cd "$REPO"
spawn "backend (port ${BACKEND_PORT})" \
  -m uvicorn aila.api.app:app --host 0.0.0.0 --port "$BACKEND_PORT" --reload
sleep 4

# ── Workers ─────────────────────────────────────────────────────────────────
echo "[aila] Starting workers: $WORKERS"
for q in $WORKERS; do
  spawn "worker:$q" -m aila worker -q "$q"
done

# ── Frontend ────────────────────────────────────────────────────────────────
if [[ "$AILA_START_FRONTEND" == "1" ]]; then
  if [[ -d frontend ]]; then
    if [[ ! -d frontend/node_modules ]]; then
      echo "[aila]   node_modules missing -- running pnpm install..."
      corepack pnpm install 2>&1 | tail -3
    fi
    echo "[aila] Starting frontend..."
    spawn_shell "frontend (port ${FRONTEND_PORT})" \
      "corepack pnpm --filter @aila/shell run dev"
  else
    echo "[aila]   WARNING: frontend/ not found -- skipping"
  fi
else
  echo "[aila]   frontend disabled (AILA_START_FRONTEND=0)"
fi

# ── Health check ────────────────────────────────────────────────────────────
echo ""
echo "[aila] Waiting for services..."
sleep 10
show_status
echo ""
echo "[aila] Restart: bash start.sh restart"
echo "[aila] Stop:    bash start.sh stop"
echo "[aila] Status:  bash start.sh status"
