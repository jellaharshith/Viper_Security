# test-quality discovery: emit tasks from explicitly skipped tests (a light, offline signal).
param([int]$Max = 5)
. (Join-Path $PSScriptRoot '_common.ps1')
$root = Get-RepoRoot
$tasks = @()
$globs = @((Join-Path $root 'tests\*.py'), (Join-Path $root 'vmapi\tests\*.py'))
$hits = Select-String -Path $globs -Pattern 'pytest\.mark\.skip|pytest\.skip\(' -ErrorAction SilentlyContinue |
        Select-Object -First $Max
foreach ($h in $hits) {
  $rel = $h.Path.Replace($root + '\','').Replace('\','/')
  $loc = "${rel}:$($h.LineNumber)"
  $tasks += New-LoopTask -Mode 'test-quality' -Title "Un-skip or justify: $loc" `
    -Maker 'agy' -Checker 'codex' -Owns @($rel) `
    -Condition "the test runs (not skipped) and passes deterministically across two runs, no production-code change" `
    -Source $loc
}
$tasks | ConvertTo-Json -Depth 4
