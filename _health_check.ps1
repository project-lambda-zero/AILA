$ErrorActionPreference = 'Continue'

Write-Host "`n== PostgreSQL services =="
Get-Service | Where-Object { $_.Name -like '*postgres*' -or $_.DisplayName -like '*PostgreSQL*' } |
  Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize

Write-Host "`n== Redis services =="
Get-Service | Where-Object { $_.Name -like '*redis*' -or $_.DisplayName -like '*Redis*' } |
  Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize

Write-Host "`n== Postgres listening on :5432 =="
try {
  $tcp = Get-NetTCPConnection -LocalPort 5432 -State Listen -ErrorAction Stop
  $tcp | Select-Object LocalAddress, LocalPort, State, OwningProcess | Format-Table -AutoSize
  foreach ($c in $tcp) {
    $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    if ($p) { "PID=$($p.Id) Name=$($p.ProcessName)  WS=$([int]($p.WS/1MB)) MB  Started=$($p.StartTime)" }
  }
} catch {
  "Nothing listening on 5432 or insufficient perms: $($_.Exception.Message)"
}

Write-Host "`n== Redis listening on :6379 =="
try {
  $tcp = Get-NetTCPConnection -LocalPort 6379 -State Listen -ErrorAction Stop
  $tcp | Select-Object LocalAddress, LocalPort, State, OwningProcess | Format-Table -AutoSize
  foreach ($c in $tcp) {
    $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    if ($p) { "PID=$($p.Id) Name=$($p.ProcessName)  WS=$([int]($p.WS/1MB)) MB  Started=$($p.StartTime)" }
  }
} catch {
  "Nothing listening on 6379: $($_.Exception.Message)"
}

Write-Host "`n== API listening on :8000 =="
try {
  $tcp = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction Stop
  $tcp | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
  foreach ($c in $tcp) {
    $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    if ($p) { "PID=$($p.Id) Name=$($p.ProcessName)  WS=$([int]($p.WS/1MB)) MB  Started=$($p.StartTime)" }
  }
} catch {
  "Nothing listening on 8000: $($_.Exception.Message)"
}

Write-Host "`n== Current python.exe processes =="
Get-Process python -ErrorAction SilentlyContinue |
  Select-Object Id, ProcessName, @{N='WS_MB';E={[int]($_.WS/1MB)}}, StartTime |
  Format-Table -AutoSize

Write-Host "`n== Current postgres.exe processes =="
Get-Process postgres -ErrorAction SilentlyContinue |
  Select-Object Id, ProcessName, @{N='WS_MB';E={[int]($_.WS/1MB)}}, StartTime |
  Format-Table -AutoSize
