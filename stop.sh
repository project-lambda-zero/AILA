#!/usr/bin/env bash
# Stop all AILA servers, workers, and the frontend dev server.
# Usage: bash stop.sh
#
# python.exe gets the blunt-force treatment (only AILA uses it on the dev
# box). node.exe is shared with editors and MCP tooling — we target only
# the Vite process launched by start.sh, matched via its command line.

echo "[stop] Killing Python processes..."
taskkill //F //IM python.exe 2>/dev/null && echo "[stop] Python stopped." || echo "[stop] No Python processes found."

echo "[stop] Killing Vite (frontend) processes..."
killed=0
if powershell -NoProfile -Command \
    "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | \
     Where-Object { \$_.CommandLine -match 'vite|aila-frontend' } | \
     ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue; Write-Output \$_.ProcessId }" \
    2>/dev/null | grep -q .; then
  killed=1
else
  # WMIC fallback (older Windows).
  pids=$(wmic process where "name='node.exe'" get processid,commandline 2>/dev/null \
         | grep -iE 'vite|aila-frontend' \
         | awk '{print $NF}' | tr -d '\r')
  for pid in $pids; do
    taskkill //F //PID "$pid" 2>/dev/null && killed=1 || true
  done
fi
[[ $killed -eq 1 ]] && echo "[stop] Vite stopped." || echo "[stop] No Vite processes found."
