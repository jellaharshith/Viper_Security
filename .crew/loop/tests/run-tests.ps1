<#
.SYNOPSIS
  Portable assertion suite for the herdr crew loop (no Pester required).
  Dot-sources each component and checks its pure logic. Exit 0 = all pass.

.EXAMPLE
  .\.crew\loop\tests\run-tests.ps1
#>
$LoopDir = Split-Path -Parent $PSScriptRoot
$script:Pass = 0; $script:Fail = 0

function Assert-True { param([bool]$Cond, [string]$Name)
  if ($Cond) { $script:Pass++; Write-Host "  PASS $Name" -ForegroundColor Green }
  else       { $script:Fail++; Write-Host "  FAIL $Name" -ForegroundColor Red }
}
function Assert-Eq { param($Expected, $Actual, [string]$Name)
  Assert-True ($Expected -eq $Actual) "$Name (expected '$Expected', got '$Actual')"
}

# --- dot-source components (run-guards skip their main blocks) ---
. (Join-Path $LoopDir 'crew-dispatch.ps1')
. (Join-Path $LoopDir 'crew-judge.ps1')
. (Join-Path $LoopDir 'crew-pr.ps1')
. (Join-Path $LoopDir 'crew-worktree.ps1')
. (Join-Path $LoopDir 'discover\_common.ps1')
. (Join-Path $LoopDir 'crew-loop.ps1')
$ErrorActionPreference = 'Continue'   # crew-loop sets Stop; tests want to continue + report

Write-Host "`n[dispatch]"
Assert-Eq 'herdr' (Resolve-CrewBackend 'auto') 'backend auto-resolves to herdr on this machine'
Assert-Eq 'noop'  (Resolve-CrewBackend 'noop') 'explicit backend passes through'
$msg = New-KickMessage -Lane 'codex-ci' -BriefPath '.crew\loop\briefs\x.md'
Assert-True ($msg -match 'codex-ci' -and $msg -match '/x.md' -and $msg -match 'STOP') 'kick message names lane, brief (fwd-slashed), STOP'

Write-Host "`n[discover/_common]"
$a = New-LoopTask -Mode 'probe-dev' -Title 'Same Title'
$b = New-LoopTask -Mode 'probe-dev' -Title 'Same Title'
$c = New-LoopTask -Mode 'probe-dev' -Title 'Different'
Assert-Eq $a.id $b.id 'task id is deterministic for same mode+title'
Assert-True ($a.id -ne $c.id) 'task id differs for different title'
Assert-True ($a.id -match '^T[0-9A-F]{8}$') 'task id shape is T + 8 hex'

Write-Host "`n[judge]"
$fake = Join-Path $PSScriptRoot '_fakeboard.md'
'codex: T1 APPROVED' | Out-File -Encoding utf8 $fake
Assert-Eq 'APPROVED' (Get-CheckerVerdict -CheckerLane 'codex' -TaskId 'T1' -Board $fake) 'checker APPROVED parsed'
'codex: T2 REJECTED: nope' | Out-File -Encoding utf8 $fake
Assert-Eq 'REJECTED' (Get-CheckerVerdict -CheckerLane 'codex' -TaskId 'T2' -Board $fake) 'checker REJECTED parsed'
Assert-Eq 'PENDING' (Get-CheckerVerdict -CheckerLane 'codex' -TaskId 'T9' -Board $fake) 'absent verdict is PENDING'
# Safety invariant: for a still-unimplemented mode, gates skipped + checker APPROVED still PARKs.
'codex: T1 APPROVED' | Out-File -Encoding utf8 $fake
$j = Invoke-CrewJudge -Mode 'probe-dev' -Lane 'claude' -TaskId 'T1' -WorktreePath 'none' -Board $fake -SkipGates
Assert-Eq 'PARK' $j.Verdict 'unimplemented mode (probe-dev) PARKs by safe default'
Assert-True ($j.Gates -and $j.Checker -eq 'APPROVED' -and -not $j.Condition) 'park is due to the condition, not gates/checker'
Assert-True ($j.Reasons -join ' ' -match 'TODO human') 'unimplemented-mode detail still flags TODO human'
Remove-Item $fake -ErrorAction SilentlyContinue

Write-Host "`n[pr: no-attribution enforcement]"
Assert-True (Test-HasAttribution "fix: thing`n`nCo-Authored-By: Someone <x@y>") 'detects Co-Authored-By footer'
Assert-True (Test-HasAttribution "chore`n`nGenerated with Claude Code") 'detects Generated with footer'
Assert-True (-not (Test-HasAttribution "fix: a clean message`n`nwith a normal body")) 'clean message passes'

Write-Host "`n[judge: ci-triage condition]"
# Pure cases
Assert-True (-not (Test-CiTriageCondition -WorktreePath 'does-not-exist').Ok) 'missing worktree -> not done'
# Real worktree: no commit beyond base -> not done; a scoped commit -> done.
$tid = 'CONDTEST01'; $lane = 'probe'
try {
  $wt = New-CrewWorktree -Lane $lane -TaskId $tid
  $r0 = Test-CiTriageCondition -WorktreePath $wt.Path -Base 'main'
  Assert-True (-not $r0.Ok) 'fresh worktree, no commit -> not done'
  # make one scoped commit in the worktree
  Set-Content -Encoding utf8 -Path (Join-Path $wt.Path '_cond_probe.txt') -Value 'loop condition test'
  & git -C $wt.Path add _cond_probe.txt 2>&1 | Out-Null
  & git -C $wt.Path -c user.email=t@t -c user.name=t commit -m 'test: scoped change' 2>&1 | Out-Null
  $r1 = Test-CiTriageCondition -WorktreePath $wt.Path -Base 'main'
  Assert-True $r1.Ok 'worktree with one scoped commit -> done'
  Assert-True ($r1.Detail -match '1 file') 'detail reports the scoped file count'
} finally {
  Remove-CrewWorktree -Lane $lane -TaskId $tid -DeleteBranch
}

Write-Host "`n[loop: queue merge]"
$q = [pscustomobject]@{ updated=''; tasks=@($a) }
$q = Merge-Tasks -Queue $q -New @($a, $c)   # $a already present -> dedup; $c is new
Assert-Eq 2 (@($q.tasks).Count) 'merge dedups existing id and adds the new one'

Write-Host "`n==== $script:Pass passed, $script:Fail failed ====" -ForegroundColor $(if ($script:Fail) {'Red'} else {'Green'})
if ($script:Fail) { exit 1 } else { exit 0 }
