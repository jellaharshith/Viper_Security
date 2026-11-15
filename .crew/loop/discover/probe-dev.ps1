# probe-dev discovery: emit tasks from the v1.2 backlog headings (### 3.x) in docs/v1-scope.md.
param([int]$Max = 5)
. (Join-Path $PSScriptRoot '_common.ps1')
$root  = Get-RepoRoot
$scope = Join-Path $root 'docs\v1-scope.md'
$tasks = @()
if (Test-Path $scope) {
  $inBacklog = $false
  foreach ($line in Get-Content $scope) {
    if ($line -match '^##\s+3\.')      { $inBacklog = $true;  continue }  # "## 3. The v1.2 Backlog"
    if ($inBacklog -and $line -match '^##\s+[^3]') { break }              # next top section ends it
    if ($inBacklog -and $line -match '^###\s+3\.\d+\s+(.+?)\s*$') {
      $item = $Matches[1].Trim()
      $tasks += New-LoopTask -Mode 'probe-dev' -Title $item -Maker 'agy' -Checker 'codex' `
        -Condition "tests for this probe/tool pass AND it is registered in its parser/tool map AND it demonstrably fires" `
        -Source 'docs/v1-scope.md#v1.2-backlog'
    }
    if ($tasks.Count -ge $Max) { break }
  }
}
$tasks | ConvertTo-Json -Depth 4
