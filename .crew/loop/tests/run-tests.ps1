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
# Pin condition tests to the actual branch point (New-CrewWorktree branches from repo HEAD), so they
# are location-independent -- running from a worktree whose 'main' has diverged won't skew the diff.
$RepoRoot = Split-Path -Parent (Split-Path -Parent $LoopDir)
$TESTBASE = (& git -C $RepoRoot rev-parse HEAD 2>$null | Select-Object -First 1)

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
# Safety invariant: gates skipped + checker APPROVED is NOT enough -- the condition still gates.
$j = Invoke-CrewJudge -Mode 'engagement' -Lane 'claude' -TaskId 'T1' -WorktreePath 'none' -Board $fake -SkipGates
Assert-Eq 'PARK' $j.Verdict 'engagement with no worktree/artifact PARKs despite gates+checker'
Assert-True ($j.Gates -and $j.Checker -eq 'APPROVED' -and -not $j.Condition) 'park is due to the condition, not gates/checker'
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
  $r0 = Test-CiTriageCondition -WorktreePath $wt.Path -Base $TESTBASE
  Assert-True (-not $r0.Ok) 'fresh worktree, no commit -> not done'
  # make one scoped commit in the worktree
  Set-Content -Encoding utf8 -Path (Join-Path $wt.Path '_cond_probe.txt') -Value 'loop condition test'
  & git -C $wt.Path add _cond_probe.txt 2>&1 | Out-Null
  & git -C $wt.Path -c user.email=t@t -c user.name=t commit -m 'test: scoped change' 2>&1 | Out-Null
  $r1 = Test-CiTriageCondition -WorktreePath $wt.Path -Base $TESTBASE
  Assert-True $r1.Ok 'worktree with one scoped commit -> done'
  Assert-True ($r1.Detail -match '1 file') 'detail reports the scoped file count'
} finally {
  Remove-CrewWorktree -Lane $lane -TaskId $tid -DeleteBranch
}

Write-Host "`n[judge: probe-dev condition]"
$pdid = 'PDCOND01'; $pdlane = 'pd'
try {
  $wt = New-CrewWorktree -Lane $pdlane -TaskId $pdid
  New-Item -ItemType Directory -Force (Join-Path $wt.Path 'vmapi/probes') | Out-Null
  Set-Content -Encoding utf8 (Join-Path $wt.Path 'vmapi/probes/_cond_probe.py') "# probe`n"
  & git -C $wt.Path add vmapi/probes/_cond_probe.py 2>&1 | Out-Null
  & git -C $wt.Path -c user.email=t@t -c user.name=t commit -m 'feat: probe only' 2>&1 | Out-Null
  $r0 = Test-ProbeDevCondition -WorktreePath $wt.Path -Base $TESTBASE
  Assert-True (-not $r0.Ok) 'probe without registration -> not done (silent-failure class)'
  Assert-True ($r0.Detail -match 'registration') 'detail names the missing registration point'
  # add registration touch + a test -> now done
  Add-Content -Encoding utf8 (Join-Path $wt.Path 'src/viper/agents/evidence.py') "# loop cond test touch`n"
  Set-Content -Encoding utf8 (Join-Path $wt.Path 'tests/test_cond_probe.py') "def test_probe():`n    assert True`n"
  & git -C $wt.Path add src/viper/agents/evidence.py tests/test_cond_probe.py 2>&1 | Out-Null
  & git -C $wt.Path -c user.email=t@t -c user.name=t commit -m 'feat: register + test' 2>&1 | Out-Null
  $r1 = Test-ProbeDevCondition -WorktreePath $wt.Path -Base $TESTBASE
  Assert-True $r1.Ok 'probe + registration + test -> done'
} finally { Remove-CrewWorktree -Lane $pdlane -TaskId $pdid -DeleteBranch }

Write-Host "`n[judge: test-quality condition]"
$tqid = 'TQCOND01'; $tqlane = 'tq'
try {
  $wt = New-CrewWorktree -Lane $tqlane -TaskId $tqid
  # production-code change -> not done
  Add-Content -Encoding utf8 (Join-Path $wt.Path 'src/viper/policy/engine.py') "# loop cond test touch`n"
  & git -C $wt.Path add src/viper/policy/engine.py 2>&1 | Out-Null
  & git -C $wt.Path -c user.email=t@t -c user.name=t commit -m 'chore: touch prod' 2>&1 | Out-Null
  $r0 = Test-TestQualityCondition -WorktreePath $wt.Path -Source '' -Base $TESTBASE
  Assert-True (-not $r0.Ok) 'production-code change -> not done'
  Assert-True ($r0.Detail -match 'production code') 'detail flags the production file'
} finally { Remove-CrewWorktree -Lane $tqlane -TaskId $tqid -DeleteBranch }
# tests-only + deterministic target passes twice -> done (needs the venv; else assert fallback)
$tqid2 = 'TQCOND02'
try {
  $wt = New-CrewWorktree -Lane $tqlane -TaskId $tqid2
  Set-Content -Encoding utf8 (Join-Path $wt.Path 'tests/test_cond_quality.py') "def test_ok():`n    assert True`n"
  & git -C $wt.Path add tests/test_cond_quality.py 2>&1 | Out-Null
  & git -C $wt.Path -c user.email=t@t -c user.name=t commit -m 'test: add passing test' 2>&1 | Out-Null
  if (Test-Path (Join-Path $LoopDir '..\..\.venv\Scripts\python.exe')) {
    $r1 = Test-TestQualityCondition -WorktreePath $wt.Path -Source 'tests/test_cond_quality.py:1' -Base $TESTBASE
    Assert-True $r1.Ok 'tests-only + target passes twice -> done (deterministic)'
    Assert-True ($r1.Detail -match 'twice') 'detail reports the twice-run determinism check'
  } else {
    $r1 = Test-TestQualityCondition -WorktreePath $wt.Path -Source '' -Base $TESTBASE
    Assert-True $r1.Ok 'tests-only change -> done (fallback; no venv for twice-run)'
  }
} finally { Remove-CrewWorktree -Lane $tqlane -TaskId $tqid2 -DeleteBranch }

Write-Host "`n[judge: engagement condition]"
# E1: active-execution code in the diff -> PARK (defense in depth over the pre-dispatch gate)
$e = 'EN1'
try {
  $wt = New-CrewWorktree -Lane en -TaskId $e
  New-Item -ItemType Directory -Force (Join-Path $wt.Path 'src/viper/execution') | Out-Null
  Set-Content -Encoding utf8 (Join-Path $wt.Path 'src/viper/execution/_cond_x.py') "# x`n"
  & git -C $wt.Path add src/viper/execution/_cond_x.py 2>&1 | Out-Null
  & git -C $wt.Path -c user.email=t@t -c user.name=t commit -m 'active' 2>&1 | Out-Null
  $r = Test-EngagementCondition -WorktreePath $wt.Path -Base $TESTBASE
  Assert-True (-not $r.Ok) 'active-execution code -> PARK (requires approval)'
  Assert-True ($r.Detail -match 'active-execution') 'detail flags active code'
} finally { Remove-CrewWorktree -Lane en -TaskId $e -DeleteBranch }
# E2: passive artifact (projects/ write-up), non-empty, no citations -> done
$e = 'EN2'
try {
  $wt = New-CrewWorktree -Lane en -TaskId $e
  New-Item -ItemType Directory -Force (Join-Path $wt.Path 'projects/_cond-h1') | Out-Null
  Set-Content -Encoding utf8 (Join-Path $wt.Path 'projects/_cond-h1/writeup.md') "# Passive write-up`nFindings summary.`n"
  & git -C $wt.Path add projects/_cond-h1/writeup.md 2>&1 | Out-Null
  & git -C $wt.Path -c user.email=t@t -c user.name=t commit -m 'writeup' 2>&1 | Out-Null
  $r = Test-EngagementCondition -WorktreePath $wt.Path -Base $TESTBASE
  Assert-True $r.Ok 'passive artifact, no citations -> done'
} finally { Remove-CrewWorktree -Lane en -TaskId $e -DeleteBranch }
# E3: artifact cites an audit hash that resolves to another committed file -> done
$H = 'a1b2c3d4' * 8
$e = 'EN3'
try {
  $wt = New-CrewWorktree -Lane en -TaskId $e
  New-Item -ItemType Directory -Force (Join-Path $wt.Path 'projects/_cond2-h1') | Out-Null
  Set-Content -Encoding utf8 (Join-Path $wt.Path 'projects/_cond2-h1/writeup.md') "Cites audit $H in evidence.`n"
  Set-Content -Encoding utf8 (Join-Path $wt.Path 'projects/_cond2-h1/evidence.txt') "$H`n"
  & git -C $wt.Path add projects/_cond2-h1/writeup.md projects/_cond2-h1/evidence.txt 2>&1 | Out-Null
  & git -C $wt.Path -c user.email=t@t -c user.name=t commit -m 'cited' 2>&1 | Out-Null
  $r = Test-EngagementCondition -WorktreePath $wt.Path -Base $TESTBASE
  Assert-True $r.Ok 'artifact citing a resolvable audit hash -> done'
} finally { Remove-CrewWorktree -Lane en -TaskId $e -DeleteBranch }
# E4: artifact cites an audit hash that resolves nowhere -> PARK
$e = 'EN4'
try {
  $wt = New-CrewWorktree -Lane en -TaskId $e
  New-Item -ItemType Directory -Force (Join-Path $wt.Path 'projects/_cond3-h1') | Out-Null
  Set-Content -Encoding utf8 (Join-Path $wt.Path 'projects/_cond3-h1/writeup.md') "Cites audit $H but nothing backs it.`n"
  & git -C $wt.Path add projects/_cond3-h1/writeup.md 2>&1 | Out-Null
  & git -C $wt.Path -c user.email=t@t -c user.name=t commit -m 'bad cite' 2>&1 | Out-Null
  $r = Test-EngagementCondition -WorktreePath $wt.Path -Base $TESTBASE
  Assert-True (-not $r.Ok) 'artifact citing an unresolvable audit hash -> PARK'
  Assert-True ($r.Detail -match 'does not resolve') 'detail flags the dangling citation'
} finally { Remove-CrewWorktree -Lane en -TaskId $e -DeleteBranch }

Write-Host "`n[loop: queue merge]"
$q = [pscustomobject]@{ updated=''; tasks=@($a) }
$q = Merge-Tasks -Queue $q -New @($a, $c)   # $a already present -> dedup; $c is new
Assert-Eq 2 (@($q.tasks).Count) 'merge dedups existing id and adds the new one'

Write-Host "`n==== $script:Pass passed, $script:Fail failed ====" -ForegroundColor $(if ($script:Fail) {'Red'} else {'Green'})
if ($script:Fail) { exit 1 } else { exit 0 }
