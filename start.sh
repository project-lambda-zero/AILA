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
#   ida-headless         HTTP on  ${IDA_HEADLESS_PORT:-18821}  (toggle: AILA_START_IDA_HEADLESS=0)
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
#   IDA_HEADLESS_PORT     default 18821
#   WORKERS               default "default vr vulnerability forensics sbd_nfr"
#   AUDIT_MCP_DIR         default ../audit-mcp (relative to repo root)
#   IDA_HEADLESS_DIR      default ../ida-headless-mcp-exp (relative to repo root)
#   AILA_START_FRONTEND   1/0 (default 1)
#   AILA_START_AUDIT_MCP  1/0 (default 1)
#   AILA_START_IDA_HEADLESS  1/0 (default 1)

set -e
cd "$(dirname "$0")"

COMMAND="${1:-start}"

# ── Defaults ────────────────────────────────────────────────────────────────
: "${BACKEND_PORT:=8000}"
: "${FRONTEND_PORT:=3000}"
: "${AUDIT_MCP_PORT:=18822}"
: "${IDA_HEADLESS_PORT:=18821}"
: "${WORKERS:=default vr vulnerability forensics sbd_nfr}"
# Per-queue worker concurrency. The vr queue runs LLM-heavy investigations
# with multi-minute LLM retries; one worker per queue serializes them
# behind whichever investigation is mid-call. Default vr=5 so the queue
# drains in parallel. Override via WORKER_COUNT_<QUEUE> env vars (queue
# name uppercased, non-alnum -> underscore). E.g. WORKER_COUNT_VR=8.
: "${WORKER_COUNT_VR:=5}"
: "${WORKER_COUNT_DEFAULT:=1}"
: "${WORKER_COUNT_VULNERABILITY:=1}"
: "${WORKER_COUNT_FORENSICS:=1}"
: "${WORKER_COUNT_SBD_NFR:=1}"
: "${AUDIT_MCP_DIR:=../audit-mcp}"
: "${IDA_HEADLESS_DIR:=../ida-headless-mcp-exp}"
: "${AILA_START_FRONTEND:=1}"
: "${AILA_START_AUDIT_MCP:=1}"
: "${AUDIT_MCP_WORKERS:=1}"
: "${AILA_START_IDA_HEADLESS:=1}"

RUN_DIR=".run"
mkdir -p "$RUN_DIR" 2>/dev/null || true
RUN_DIR_ABS="$PWD/$RUN_DIR"
# On Git Bash, convert /c/... to C:/... so PowerShell + cmd accept it.
# On WSL bash, do the same via wslpath — /mnt/c/... is not a path
# Windows cmd.exe can open for stdout redirection, which silently kills
# every spawned worker the moment cmd tries to apply "> path 2>&1".
if command -v cygpath >/dev/null 2>&1; then
  RUN_DIR_ABS=$(cygpath -m "$RUN_DIR_ABS" 2>/dev/null || echo "$RUN_DIR_ABS")
elif command -v wslpath >/dev/null 2>&1; then
  RUN_DIR_ABS=$(wslpath -m "$RUN_DIR_ABS" 2>/dev/null || echo "$RUN_DIR_ABS")
fi
# Last-ditch fallback: some WSL distros lack wslpath. Convert
# /mnt/X/... to X:/... by hand. Idempotent — no-op when RUN_DIR_ABS
# is already a Windows path.
case "$RUN_DIR_ABS" in
  /mnt/?/*)
    _drive="${RUN_DIR_ABS:5:1}"
    _rest="${RUN_DIR_ABS:6}"
    RUN_DIR_ABS="${_drive^^}:${_rest}"
    unset _drive _rest
    ;;
esac

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
  # Use the ABSOLUTE run-dir path so subshells that `cd` elsewhere
  # (audit-mcp launches in its own repo dir) still write the pidfile
  # into AILA's .run/ rather than the subshell's cwd. Without this,
  # audit-mcp.pid silently landed in ../audit-mcp/.run/ and start.sh
  # status / restart-audit-mcp could not find it.
  mkdir -p "$RUN_DIR_ABS"
  local slug
  slug=$(slugify "$label")
  echo "$pidv" >> "$RUN_DIR_ABS/${slug}.pid"
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
  kill_port_owner "${IDA_HEADLESS_PORT:-18821}"
  # Frontend: vite spawns under node.exe.
  kill_matching "node.exe" "vite|aila/shell"
  echo "[aila] Stopped."
}

# Spawn detached python via PowerShell Start-Process -PassThru. Captures
# the spawned PID and records it under .run/<slug>.pid so ``stop`` can
# tree-kill it reliably without having to grep cmdlines. Inherits the
# CALLER's cwd — caller must ``cd`` into the right repo before invoking.
#
# stdout + stderr are merged into ${RUN_DIR_ABS}/<slug>.log via a `cmd /c`
# wrapper (Start-Process cannot redirect both streams to the SAME file —
# PowerShell rejects it as "duplicate path"). Previous session's log is
# rotated to .prev so each restart starts clean while one history step
# remains debuggable. The returned PID is cmd.exe; the python child is
# the sole descendant so ``taskkill /PID <cmd_pid> /T /F`` in
# kill_tracked_pids takes both down together — identical lifecycle to
# the prior direct-spawn path.
spawn() {
  local label="$1"; shift
  local cmd_args=""
  for arg in "$@"; do
    [[ -n "$cmd_args" ]] && cmd_args+=" "
    # Quote args containing whitespace; pass-through anything else.
    # None of the current callers pass args with embedded `"` so naive
    # quoting is sufficient. If a future caller needs to, switch to a
    # proper escape pass.
    if [[ "$arg" =~ [[:space:]] ]]; then
      cmd_args+="\"${arg}\""
    else
      cmd_args+="${arg}"
    fi
  done
  # Collect simple KEY=VAL lines from .env so spawned children see them.
  # PowerShell Start-Process strips the bash shell's exported env (D-251)
  # so .env settings would otherwise be invisible to detached children.
  # We translate each line into `set KEY=VAL && ` and prepend to the cmd
  # block so the cmd shell sets them before launching python. Skip blank
  # lines, comments, and any line whose key is not a bare identifier.
  local env_prefix=""
  if [[ -f .env ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
      local k="${line%%=*}"
      local v="${line#*=}"
      [[ "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
      # strip surrounding quotes from value if present
      [[ "$v" =~ ^\".*\"$ ]] && v="${v:1:-1}"
      [[ "$v" =~ ^\'.*\'$ ]] && v="${v:1:-1}"
      env_prefix+="set ${k}=${v}&& "
    done < .env
  fi
  local slug log_path
  slug=$(slugify "$label")
  log_path="${RUN_DIR_ABS}/${slug}.log"
  # Rotate one generation so a fresh restart doesn't lose the prior
  # session's tail (often where the crash that triggered the restart
  # lives). Keep only one .prev — unbounded rotation accumulates trash.
  [[ -f "$log_path" ]] && mv -f "$log_path" "${log_path}.prev" 2>/dev/null
  local pidv
  pidv=$("$PS" -NoProfile -Command \
    "(Start-Process cmd -ArgumentList '/c','${env_prefix}python ${cmd_args} > \"${log_path}\" 2>&1' -WindowStyle Hidden -PassThru).Id" \
    2>/dev/null | tr -d '\r\n ')
  record_pid "$label" "$pidv"
  echo "[aila]   $label started (PID $pidv, log $log_path)"
}

# pnpm dev needs cmd as shell host. Start-Process cmd /c "..." returns the
# cmd.exe PID; the actual node/pnpm runs as its child. taskkill /T /F on the
# cmd PID kills the whole tree. Same log-redirect pattern as spawn().
spawn_shell() {
  local label="$1"; shift
  local cmdline="$*"
  local slug log_path
  slug=$(slugify "$label")
  log_path="${RUN_DIR_ABS}/${slug}.log"
  [[ -f "$log_path" ]] && mv -f "$log_path" "${log_path}.prev" 2>/dev/null
  local pidv
  pidv=$("$PS" -NoProfile -Command \
    "(Start-Process cmd -ArgumentList '/c','${cmdline} > \"${log_path}\" 2>&1' -WindowStyle Hidden -PassThru).Id" \
    2>/dev/null | tr -d '\r\n ')
  record_pid "$label" "$pidv"
  echo "[aila]   $label started (PID $pidv, log $log_path)"
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
  probe "ida-headless http://127.0.0.1:${IDA_HEADLESS_PORT}/tools" "http://127.0.0.1:${IDA_HEADLESS_PORT}/tools"
  probe "frontend http://127.0.0.1:${FRONTEND_PORT}/" "http://127.0.0.1:${FRONTEND_PORT}/"
}

# ── Commands ────────────────────────────────────────────────────────────────

# Per-service restart helper: stop just one named service, re-run start.sh.
# Idempotent restart of a single tracked service. Two-phase kill:
#   1. Tree-kill the recorded pidfile (if present) — owns the happy path.
#   2. (optional) Sweep whoever currently holds $port — owns the case
#      where the pidfile got lost (manual cleanup, partial stop, crash
#      mid-spawn) but a previous process is still squatting the port.
#      Without this, restart silently no-ops then spawns a new process
#      that fails to bind and dies inside the cmd.exe wrapper —
#      Start-Process -PassThru only reports the wrapper's success.
restart_one() {
  local svc="$1"
  local port="${2:-}"
  local pidfile="$RUN_DIR/${svc}.pid"
  if [[ -f "$pidfile" ]]; then
    local pid; pid=$(cat "$pidfile" 2>/dev/null || echo "")
    if [[ -n "$pid" ]]; then
      echo "[aila] Killing ${svc} (PID $pid)..."
      "$PS" -NoProfile -Command "Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue; \
        Get-CimInstance Win32_Process -Filter \"ParentProcessId=$pid\" | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }" 2>/dev/null || true
      sleep 2
    fi
    rm -f "$pidfile"
  fi
  if [[ -n "$port" ]]; then
    # Sweep any process still listening on $port. Idempotent — no-op
    # when the pidfile kill already cleared it.
    kill_port_owner "$port"
    sleep 1
  fi
}

# Resolve a queue name to its configured worker count.
# Reads WORKER_COUNT_<QUEUE_UPPER> env var, defaulting to 1.
# Non-alnum chars in the queue name are translated to underscore so
# "sbd_nfr" -> WORKER_COUNT_SBD_NFR.
worker_count_for() {
  local q="$1"
  local varname
  varname="WORKER_COUNT_$(echo "$q" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9' '_')"
  varname="${varname%_}"
  echo "${!varname:-1}"
}

# Kill the legacy single-worker pidfile (worker-<q>.pid) AND every
# indexed pidfile (worker-<q>-N.pid for any N), then spawn fresh
# WORKER_COUNT workers under indexed names. Idempotent: safe to run
# on a host that's currently running legacy single-worker layout OR
# the new indexed layout OR a mix.
# Restart every worker in queue $1, idempotent regardless of pidfile
# state. Three-phase kill mirroring restart_one's two-phase pattern:
#   1. Tree-kill the legacy single-worker pidfile (worker-<q>.pid).
#   2. Tree-kill every indexed pidfile (worker-<q>-1.pid ... -20.pid).
#   3. Cmdline-sweep ANY surviving python.exe whose argv contains
#      `aila worker -q <q>`. Workers have no port so kill_port_owner
#      doesn't apply — kill_matching with a queue-anchored regex is
#      the equivalent fallback for "pidfile vanished, real process
#      still running stale code". Without this, restart_pool was
#      pidfile-only: a missing pidfile silently no-op'd the kill loop,
#      then spawn() layered fresh workers ON TOP of the orphans —
#      producing N×2 (or worse) workers, half on the new code half on
#      the old, racing each ARQ job. Same symptom as restart_one's
#      stale uvicorn bug (commit c562074); same shape of fix.
#
# The regex word-boundaries the queue name (`-q vr($| )`) so `-q vr`
# does NOT also match `-q vulnerability` / `-q vr_foo`. End-of-string
# or space is the only legal trailer in our cmdline shape.
restart_pool() {
  local q="$1"
  local n
  n=$(worker_count_for "$q")
  # Kill legacy single-worker pidfile (worker-<q>.pid)
  restart_one "worker-$q"
  # Kill every indexed pidfile (worker-<q>-*.pid). 20 is a safe upper
  # bound for any reasonable per-queue concurrency.
  local i
  for ((i=1; i<=20; i++)); do
    [[ -f "$RUN_DIR/worker-$q-$i.pid" ]] && restart_one "worker-$q-$i"
  done
  # Cmdline-sweep fallback (see header). Idempotent — no-op when the
  # pidfile kills already cleared the process; fatal to orphans when
  # they didn't.
  kill_matching "python.exe" "aila worker -q ${q}(\$| )"
  sleep 1
  # Spawn N fresh workers under indexed names.
  for ((i=1; i<=n; i++)); do
    spawn "worker-$q-$i" -m aila worker -q "$q"
  done
}

case "$COMMAND" in
  stop)    load_env; kill_aila_processes; exit 0 ;;
  status)  load_env; show_status; exit 0 ;;
  restart) echo "[aila] Restart: stop + start" ;;
  start)   ;;
  restart-backend)
    load_env; restart_one "backend" "$BACKEND_PORT"
    REPO="$PWD"; mkdir -p "$RUN_DIR"
    spawn "backend" -m uvicorn aila.api.app:app --host 0.0.0.0 --port "$BACKEND_PORT" --loop asyncio
    echo "[aila] Backend restarted; rest of stack untouched." ; exit 0 ;;
  restart-frontend)
    load_env; restart_one "frontend" "$FRONTEND_PORT"; mkdir -p "$RUN_DIR"
    spawn_shell "frontend" "corepack pnpm --filter @aila/shell run dev"
    echo "[aila] Frontend restarted; rest of stack untouched." ; exit 0 ;;
  restart-workers)
    load_env
    mkdir -p "$RUN_DIR"
    for q in $WORKERS; do restart_pool "$q"; done
    echo "[aila] All workers restarted; backend/frontend/audit-mcp/ida-headless untouched." ; exit 0 ;;
  restart-worker)
    if [[ -z "${2:-}" ]]; then echo "Usage: bash start.sh restart-worker <queue>"; exit 1; fi
    load_env; mkdir -p "$RUN_DIR"
    restart_pool "$2"
    echo "[aila] worker-$2 pool restarted (count=$(worker_count_for "$2")); rest of stack untouched." ; exit 0 ;;
  restart-audit-mcp)
    load_env; restart_one "audit-mcp" "$AUDIT_MCP_PORT"; mkdir -p "$RUN_DIR"
    ( cd "$AUDIT_MCP_DIR" && spawn "audit-mcp" -m audit_mcp --mode http --port "$AUDIT_MCP_PORT" --host 127.0.0.1 --workers "$AUDIT_MCP_WORKERS" )
    echo "[aila] audit-mcp restarted; rest of stack untouched. Firefox semble pickle reloads in ~9s." ; exit 0 ;;
  refresh-audit-mcp)
    load_env
    # Walk every audit-mcp index, git-fetch upstream, and re-index when
    # HEAD moved. Unchanged repos are a no-op via the SHA short-circuit.
    # Pass --force to rebuild regardless (use after a trailmark/semble
    # upgrade where the on-disk format changed).
    extra=()
    [[ "${2:-}" == "--force" ]] && extra=(--force)
    [[ -n "${AUDIT_MCP_REFRESH_ONLY:-}" ]] && extra+=(--only "$AUDIT_MCP_REFRESH_ONLY")
    python "$REPO/scripts/refresh_audit_mcp_indexes.py" \
      --url "http://127.0.0.1:${AUDIT_MCP_PORT:-18822}" \
      "${extra[@]}"
    exit $? ;;
  *) echo "Unknown: $COMMAND. start | stop | status | restart | restart-backend | restart-frontend | restart-workers | restart-worker <q> | restart-audit-mcp | refresh-audit-mcp [--force]"; exit 1 ;;
esac

REPO="$PWD"

load_env
kill_aila_processes
mkdir -p "$RUN_DIR"

# ── audit-mcp (in its own repo) ─────────────────────────────────────────────
if [[ "$AILA_START_AUDIT_MCP" == "1" && -d "$AUDIT_MCP_DIR" ]]; then
  echo "[aila] Starting audit-mcp (workers=${AUDIT_MCP_WORKERS})..."
  # NOTE: PowerShell Start-Process does NOT inherit bash env vars on
  # Windows. AUDIT_MCP_WORKERS MUST be passed as a CLI flag here, not
  # exported — the AUDIT_MCP_WORKERS= prefix in front of spawn won't
  # reach the spawned python process. The --workers flag wins over
  # the env-var path in audit_mcp's argparse.
  (
    cd "$AUDIT_MCP_DIR" && \
    spawn "audit-mcp" \
      -m audit_mcp --mode http \
      --port "$AUDIT_MCP_PORT" --host 127.0.0.1 \
      --workers "$AUDIT_MCP_WORKERS"
  )
elif [[ "$AILA_START_AUDIT_MCP" == "1" ]]; then
  echo "[aila]   WARNING: AUDIT_MCP_DIR not found: $AUDIT_MCP_DIR (skipping audit-mcp)"
else
  echo "[aila]   audit-mcp disabled (AILA_START_AUDIT_MCP=0)"
fi

# ── ida-headless-mcp (in its own repo) ──────────────────────────────────────
# Same launcher pattern as audit-mcp: detached background python via the
# spawn helper. Uses `ida_headless_mcp.server:main_http` (mirrors every
# MCP tool as a POST endpoint, no stdio plumbing — what the VR
# IDABridgeTool talks to). Without this MCP up, every `_rank_binary` /
# `_gather_binary_signals` / `assess_exploitability` call from the VR
# engine returns "Unreachable" and stalls binary-target investigations
# (source_repo targets like firefox are unaffected; CVE-derived
# native_binary targets aren't).
if [[ "$AILA_START_IDA_HEADLESS" == "1" && -d "$IDA_HEADLESS_DIR" ]]; then
  echo "[aila] Starting ida-headless-mcp..."
  # The pip-installed `ida-headless-http` console script (defined in
  # the package's pyproject.toml as ida_headless_mcp.server:main_http)
  # bypasses the `python -c '...'` quoting hell of spawn(). We call
  # PowerShell Start-Process on the .exe directly so the spawn helper
  # (which hardcodes `python` as the binary) doesn't apply.
  IDA_HEADLESS_EXE="${IDA_HEADLESS_EXE:-ida-headless-http}"
  IDA_HEADLESS_PID=$(IDA_HEADLESS_HTTP_PORT="$IDA_HEADLESS_PORT" \
    IDA_HEADLESS_HTTP_HOST="127.0.0.1" \
    "$PS" -NoProfile -Command \
      "(Start-Process '${IDA_HEADLESS_EXE}' -WindowStyle Hidden -PassThru).Id" \
    2>/dev/null | tr -d '\r\n ')
  if [[ -n "$IDA_HEADLESS_PID" ]]; then
    record_pid "ida-headless" "$IDA_HEADLESS_PID"
    echo "[aila]   ida-headless started (PID $IDA_HEADLESS_PID)"
  else
    echo "[aila]   WARNING: ida-headless launch failed — is ida-headless-http on PATH?"
  fi
elif [[ "$AILA_START_IDA_HEADLESS" == "1" ]]; then
  echo "[aila]   WARNING: IDA_HEADLESS_DIR not found: $IDA_HEADLESS_DIR (skipping ida-headless)"
else
  echo "[aila]   ida-headless disabled (AILA_START_IDA_HEADLESS=0)"
fi

# ── Backend ─────────────────────────────────────────────────────────────────
echo "[aila] Starting backend..."
cd "$REPO"
spawn "backend" \
  -m uvicorn aila.api.app:app --host 0.0.0.0 --port "$BACKEND_PORT" \
  --loop asyncio
# --loop asyncio forces the selector event loop on Windows. The default
# ProactorEventLoop binds sockets to IOCP; if the python process dies
# mid-listen (Ctrl-C, taskkill, watchfiles reload child crash), the
# kernel keeps the socket bound to a phantom PID and 'netstat' shows
# it owned by a non-existent process. The next backend launch then
# fails with WSAEADDRINUSE on a port nothing is actually serving.
# Selector loop releases sockets cleanly on exit.
# NO --reload on Windows: it spawns child workers that get orphaned on
# kill, and orphans keep holding the TCP socket via the kernel — new
# requests hit STALE code while you assume the latest edit is live.
# Code changes require an explicit ``bash start.sh restart``.

# ── Workers ─────────────────────────────────────────────────────────────────
echo "[aila] Starting workers: $WORKERS (per-queue counts: $(for q in $WORKERS; do printf '%s=%s ' "$q" "$(worker_count_for "$q")"; done))"
for q in $WORKERS; do
  n=$(worker_count_for "$q")
  for ((i=1; i<=n; i++)); do
    spawn "worker-$q-$i" -m aila worker -q "$q"
  done
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
