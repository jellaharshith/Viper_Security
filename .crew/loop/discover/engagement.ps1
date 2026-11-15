# engagement discovery: enumerate projects/*-h1 scopes. PASSIVE write-ups only; active steps need approval.
param([int]$Max = 5)
. (Join-Path $PSScriptRoot '_common.ps1')
$root = Get-RepoRoot
$tasks = @()
$projects = Get-ChildItem -Path (Join-Path $root 'projects') -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'h1$' } | Select-Object -First $Max
foreach ($p in $projects) {
  $tasks += New-LoopTask -Mode 'engagement' -Title "Advance passive write-up for $($p.Name)" `
    -Maker 'agy' -Checker 'codex' -RequiresApproval $false `
    -Condition "artifact renders, cites resolve to real audit hashes, and NO active action was taken" `
    -Source "projects/$($p.Name)"
}
$tasks | ConvertTo-Json -Depth 4
