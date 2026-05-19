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
# PID tracking:
#   Every spawned process writes its PID to .run/<label>.pid. ``stop`` walks
#   .run/*.pid and tree-kills each one via taskkill /T /F, then clears the
#   pidfile. Falls back to port-owner / cmdline sweep only if a tracked PID
#   is gone (orphaned by a hard reboot, manual kill, etc.).
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

RUN_DIR=".run"
mkdir -p "$RUN_DIR" 2>/dev/null || true
RUN_DIR_ABS="$PWD/$RUN_DIR"
# On Git Bash, convert /c/... to C:/... so PowerShell Start-Process accepts it.
if command -v cygpath >/dev/null 2>&1; then
  RUN_DIR_ABS=$(cygpath -m "$RUN_DIR_ABS" 2>/dev/null || echo "$RUN_DIR_ABS")
fi

# ── PowerShell + taskkill detection ─────────────────────────────────────────
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

TASKKILL=""
for candidate in \
  taskkill.exe \
  taskkill \
  /c/Windows/System32/taskkill.exe \
  /c/WINDOWS/System32/taskkill.exe; do
  if command -v "$candidate" >/dev/null 2>&1; then
    TASKKILL="$candidate"
    break
  fi
done
# taskkill is optional — we fall back to PowerShell Stop-Process when missing.

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

# Turn a free-form label like "backend (port 8000)" or "worker:vr" into a
# safe filename slug like "backend" or "worker-vr". Used for .run/<slug>.pid.
slugify() {
  local raw="$1"
  # Lowercase, replace any non-alnum run with '-', strip leading/trailing '-'.
  printf '%s' "$raw" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g'
}

# Tree-kill one PID + every descendant. Prefers ``taskkill /T /F`` (kills
# the whole process tree in one call), falls back to PowerShell that walks
# Win32_Process.ParentProcessId recursively.
tree_kill_pid() {
  local pidv="$1"
  [[ -z "$pidv" ]] && return 0
  if [[ -n "$TASKKILL" ]]; then
    "$TASKKILL" /T /F /PID "$pidv" >/dev/null 2>&1 || true
    return 0
  fi
  "$PS" -NoProfile -Command "
    function Kill-Tree(\$id) {
      Get-CimInstance Win32_Process -Filter \"ParentProcessId=\$id\" -ErrorAction SilentlyContinue |
        ForEach-Object { Kill-Tree \$_.ProcessId }
      Stop-Process -Id \$id -Force -ErrorAction SilentlyContinue
    }
    Kill-Tree $pidv
  " 2>/dev/null || true
}

# Write a tracked PID to .run/<slug>.pid. Append-only — multiple PIDs per
# label (rare) are space-separated on one line.
record_pid() {
  local label="$1"
  local pidv="$2"
  [[ -z "$pidv" || "$pidv" == "0" ]] && return 0
  mkdir -p "$RUN_DIR"
  local slug
  slug=$(slugify "$label")
  echo "$pidv" >> "$RUN_DIR/${slug}.pid"
}

# Walk every .run/*.pid, tree-kill each PID it contains, then delete the
# pidfile. Returns the count of PIDs killed.
kill_tracked_pids() {
  local killed=0
  if [[ ! -d "$RUN_DIR" ]]; then
    return 0
  fi
  local f
  for f in "$RUN_DIR"/*.pid; do
    [[ -e "$f" ]] || continue
    local label
    label=$(basename "$f" .pid)
    while IFS= read -r pidv; do
      [[ -z "$pidv" ]] && continue
      # Is the PID still alive? PowerShell Get-Process returns non-zero exit
      # when the process is gone. We tree-kill unconditionally — taskkill
      # silently no-ops on dead PIDs anyway.
      tree_kill_pid "$pidv"
      killed=$((killed + 1))
    done < "$f"
    rm -f "$f"
    echo "[aila]   killed tracked: $label"
  done
  return 0
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
  # FALLBACK ONLY — used when tracked pidfiles are missing (orphans from
  # a hard reboot, manual taskmgr kill, etc). Kill every python.exe whose
  # cmdline contains the given substring.
  local needle="$1"
  "$PS" -NoProfile -Command \
    "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | \
     Where-Object { \$_.CommandLine -like '*${needle}*' } | \
     ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }" \
    2>/dev/null || true
}

kill_port_owner() {
  # Last-resort cleanup for ghost listeners on a port.
  local port="$1"
  "$PS" -NoProfile -Command \
    "Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | \
     ForEach-Object { Stop-Process -Id \$_.OwningProcess -Force -ErrorAction SilentlyContinue }" \
    2>/dev/null || true
}

kill_aila_processes() {
  echo "[aila] Stopping AILA processes..."
  # PRIMARY: kill every PID we recorded at spawn time. taskkill /T /F kills
  # the whole tree, so uvicorn --reload's child worker dies with its parent.
  kill_tracked_pids
  # FALLBACK 1: sweep by cmdline substring in case a process orphaned its
  # pidfile (system reboot mid-run, manual kill in taskmgr, etc).
  kill_by_cmdline_substring "aila"
  kill_by_cmdline_substring "audit_mcp"
  kill_by_cmdline_substring "ida_headless_mcp"
  # FALLBACK 2: anything still holding our ports.
  kill_port_owner "${BACKEND_PORT:-8000}"
  kill_port_owner "${AUDIT_MCP_PORT:-18822}"
  # Frontend: vite spawns under node.exe.
  kill_matching "node.exe" "vite|aila/shell"
  echo "[aila] Stopped."
}

# Spawn detached python via PowerShell Start-Process -PassThru. Captures
# the spawned PID and records it under .run/<slug>.pid so ``stop`` can
# tree-kill it reliably without having to grep cmdlines. Inherits the
# CALLER's cwd — caller must ``cd`` into the right repo before invoking.
spawn() {
  local label="$1"; shift
  local ps_args=""
  for arg in "$@"; do
    [[ -n "$ps_args" ]] && ps_args+=","
    ps_args+="'${arg}'"
  done
  local slug log_path
  slug=$(slugify "$label")
  log_path="${RUN_DIR_ABS}/${slug}.log"
  local pidv
  pidv=$("$PS" -NoProfile -Command \
    "(Start-Process python -ArgumentList $ps_args -WindowStyle Hidden -PassThru).Id" \
    2>/dev/null | tr -d '\r\n ')
  record_pid "$label" "$pidv"
  echo "[aila]   $label started (PID $pidv)"
}

# pnpm dev needs cmd as shell host. Start-Process cmd /c "..." returns the
# cmd.exe PID; the actual node/pnpm runs as its child. taskkill /T /F on the
# cmd PID kills the whole tree.
spawn_shell() {
  local label="$1"; shift
  local cmdline="$*"
  local pidv
  pidv=$("$PS" -NoProfile -Command \
    "(Start-Process cmd -ArgumentList '/c','$cmdline' -WindowStyle Hidden -PassThru).Id" \
    2>/dev/null | tr -d '\r\n ')
  record_pid "$label" "$pidv"
  echo "[aila]   $label started (PID $pidv)"
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
  echo "[aila] Tracked PIDs (.run/*.pid):"
  if [[ -d "$RUN_DIR" ]]; then
    local any=0
    local f
    for f in "$RUN_DIR"/*.pid; do
      [[ -e "$f" ]] || continue
      any=1
      local label
      label=$(basename "$f" .pid)
      while IFS= read -r pidv; do
        [[ -z "$pidv" ]] && continue
        # Liveness check.
        if "$PS" -NoProfile -Command "Get-Process -Id $pidv -ErrorAction SilentlyContinue | Out-Null; exit \$LASTEXITCODE" 2>/dev/null; then
          echo "  ✓ $label  PID $pidv (alive)"
        else
          echo "  ✗ $label  PID $pidv (dead)"
        fi
      done < "$f"
    done
    [[ "$any" == "0" ]] && echo "  (none — start first)"
  else
    echo "  (no .run/ — start first)"
  fi
  echo ""
  echo "[aila] All matching processes (scan):"
  "$PS" -NoProfile -Command \
    "Get-CimInstance Win32_Process -Filter \"Name='python.exe' OR Name='node.exe' OR Name='cmd.exe'\" | \
     Where-Object { \$_.CommandLine -match 'uvicorn aila|aila worker|audit_mcp|vite|aila/shell' } | \
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
  stop)    load_env; kill_aila_processes; exit 0 ;;
  status)  load_env; show_status; exit 0 ;;
  restart) echo "[aila] Restart: stop + start" ;;
  start)   ;;
  *)       echo "Unknown command: $COMMAND. Use start | stop | status | restart"; exit 1 ;;
esac

REPO="$PWD"

load_env
kill_aila_processes
mkdir -p "$RUN_DIR"

# ── audit-mcp (in its own repo) ─────────────────────────────────────────────
if [[ "$AILA_START_AUDIT_MCP" == "1" && -d "$AUDIT_MCP_DIR" ]]; then
  echo "[aila] Starting audit-mcp..."
  (
    cd "$AUDIT_MCP_DIR" && \
    spawn "audit-mcp" \
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
spawn "backend" \
  -m uvicorn aila.api.app:app --host 0.0.0.0 --port "$BACKEND_PORT"
# NO --reload on Windows: it spawns child workers that get orphaned on
# kill, and orphans keep holding the TCP socket via the kernel — new
# requests hit STALE code while you assume the latest edit is live.
# Code changes require an explicit ``bash start.sh restart``.

# ── Workers ─────────────────────────────────────────────────────────────────
echo "[aila] Starting workers: $WORKERS"
for q in $WORKERS; do
  spawn "worker-$q" -m aila worker -q "$q"
done

# ── Frontend ────────────────────────────────────────────────────────────────
if [[ "$AILA_START_FRONTEND" == "1" ]]; then
  if [[ -d frontend ]]; then
    if [[ ! -d frontend/node_modules ]]; then
      echo "[aila]   node_modules missing -- running pnpm install..."
      corepack pnpm install 2>&1 | tail -3
    fi
    echo "[aila] Starting frontend..."
    spawn_shell "frontend" \
      "corepack pnpm --filter @aila/shell run dev"
  else
    echo "[aila]   WARNING: frontend/ not found -- skipping"
  fi
else
  echo "[aila]   frontend disabled (AILA_START_FRONTEND=0)"
fi

# ── Health check ────────────────────────────────────────────────────────────
echo ""
echo "[aila] Spawned. Health may take a few seconds — re-run 'bash start.sh status' if any service is red."
show_status
echo ""
echo "[aila] Restart: bash start.sh restart"
echo "[aila] Stop:    bash start.sh stop"
echo "[aila] Status:  bash start.sh status"
