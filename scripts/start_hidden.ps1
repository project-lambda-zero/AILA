# Hidden-window WMI process launcher for AILA services (Windows).
#
# start.sh spawns every service through Win32_Process.Create for the
# Job-Object breakaway (a Start-Process child dies with the launching
# terminal's job). Without an explicit startup info, the spawned cmd.exe
# gets a VISIBLE console window -- a row of blank CLI screens that die
# the moment an operator closes them (window-CLOSE aborts the child:
# "forrtl: error (200): program aborting due to window-CLOSE event").
#
# This helper passes Win32_ProcessStartup with ShowWindow=0 (SW_HIDE) so
# the service runs with no console window at all. Log redirection still
# goes through the cmd /c wrapper in start.sh so the caller sees output
# in .run/<slug>.log exactly as before.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/start_hidden.ps1 \
#     -CommandLine 'cmd /c ...' -CurrentDirectory 'C:\path'
# Output: ReturnValue=<0|nonzero> then ProcessId=<pid> on success.
param(
  [Parameter(Mandatory = $true)]
  [string]$CommandLine,
  [Parameter(Mandatory = $true)]
  [string]$CurrentDirectory
)
$ErrorActionPreference = 'Stop'
$startup = ([wmiclass]'\\.\root\cimv2:Win32_ProcessStartup').CreateInstance()
$startup.ShowWindow = 0
$r = ([wmiclass]'\\.\root\cimv2:Win32_Process').Create(
  $CommandLine,
  $CurrentDirectory,
  $startup
)
Write-Output ("ReturnValue=" + $r.ReturnValue)
Write-Output ("ProcessId=" + $r.ProcessId)
if ($r.ReturnValue -ne 0) {
  exit 1
}
