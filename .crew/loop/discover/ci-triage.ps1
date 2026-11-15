# ci-triage discovery: failed CI runs on main (via gh), falling back to a fast local ruff check.
param([int]$Max = 5)
. (Join-Path $PSScriptRoot '_common.ps1')
$root = Get-RepoRoot
$tasks = @()
$ghOk = [bool](Get-Command gh -ErrorAction SilentlyContinue)
if ($ghOk) {
  try {
    $runs = & gh run list --branch main --status failure --limit $Max --json displayTitle,databaseId,workflowName 2>$null | ConvertFrom-Json
    foreach ($r in $runs) {
      $tasks += New-LoopTask -Mode 'ci-triage' -Title "Fix CI failure: $($r.workflowName) - $($r.displayTitle)" `
        -Maker 'claude' -Checker 'codex' `
        -Condition "the specific previously-red gate/test is now GREEN and no other test regressed" `
        -Source "gh-run:$($r.databaseId)"
    }
  } catch {}
}
if ($tasks.Count -eq 0) {
  # Offline fallback: a fast local ruff check surfaces lint regressions as triage tasks.
  $py = Join-Path $root '.venv\Scripts\python.exe'
  if (Test-Path $py) {
    Push-Location $root
    try { $ruff = & $py -m ruff check . 2>&1 } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) {
      $tasks += New-LoopTask -Mode 'ci-triage' -Title 'Fix ruff lint failures (local gate red)' `
        -Maker 'claude' -Checker 'codex' `
        -Condition "ruff check . is clean and no test regressed" -Source 'local:ruff'
    }
  }
}
$tasks | ConvertTo-Json -Depth 4
