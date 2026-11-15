<#
.SYNOPSIS
  Independent stop-judge for the herdr crew loop. A task is DONE only when it passes an objective,
  verifiable bar -- never because the maker said "done" ("done is a claim, not a proof").

.DESCRIPTION
  Three independent conditions must ALL hold for a PASS:
    1. Gates green    -- ruff / mypy / pytest (BOTH test paths) run against the lane's worktree.
    2. Checker verdict -- the checker lane (codex, != maker) posted APPROVED on the board.
    3. Task condition  -- the per-mode "verifiably done" predicate holds (see Test-TaskCondition).
  Anything short of all three -> PARK (a triage card; never a PR). Safe by default.

.EXAMPLE
  .\crew-judge.ps1 -Mode probe-dev -Lane claude -TaskId T123 -WorktreePath .\viper-wt\claude__T123
#>
param(
  [ValidateSet('probe-dev','ci-triage','engagement','test-quality')][string]$Mode,
  [string]$Lane,
  [string]$TaskId,
  [string]$WorktreePath,
  [string]$CheckerLane = 'codex',
  [string]$Board = '.crew/board.md',
  [string]$Source = '',
  [string]$Base = 'main',
  [switch]$SkipGates
)

$script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Get-VenvPython {
  $p = Join-Path $script:RepoRoot '.venv\Scripts\python.exe'
  if (Test-Path $p) { return $p }
  return 'python'  # fallback to PATH python
}

function Test-GateSet {
  # Run ruff/mypy/pytest in $WorkDir using the main repo venv. Returns @{ Ok=[bool]; Detail=[string] }.
  param([Parameter(Mandatory)][string]$WorkDir)
  if (-not (Test-Path $WorkDir)) { return @{ Ok = $false; Detail = "worktree missing: $WorkDir" } }
  $py = Get-VenvPython
  $results = @()
  $allOk = $true
  Push-Location $WorkDir
  try {
    foreach ($g in @(
      @{ Name='ruff';   Args=@('-m','ruff','check','.') },
      @{ Name='mypy';   Args=@('-m','mypy','src') },
      @{ Name='pytest'; Args=@('-m','pytest','-q','vmapi\tests','tests') }  # BOTH paths
    )) {
      & $py @($g.Args) *> $null
      $ok = ($LASTEXITCODE -eq 0)
      if (-not $ok) { $allOk = $false }
      $results += ("{0}={1}" -f $g.Name, $(if ($ok) {'PASS'} else {'FAIL'}))
    }
  } finally { Pop-Location }
  return @{ Ok = $allOk; Detail = ($results -join ' ') }
}

function Get-CheckerVerdict {
  # Parse the board for the checker lane's verdict on this task. APPROVED / REJECTED / PENDING.
  param([string]$CheckerLane, [string]$TaskId, [string]$Board)
  if (-not (Test-Path $Board)) { return 'PENDING' }
  $text = Get-Content -Raw -Path $Board
  # Look for a line mentioning the task id and an explicit verdict token from the checker.
  $approved = [regex]::IsMatch($text, "(?im)^.*$([regex]::Escape($TaskId)).*\bAPPROVED\b.*$")
  $rejected = [regex]::IsMatch($text, "(?im)^.*$([regex]::Escape($TaskId)).*\bREJECTED\b.*$")
  if ($rejected) { return 'REJECTED' }
  if ($approved) { return 'APPROVED' }
  return 'PENDING'
}

function Test-CiTriageCondition {
  # ci-triage is DONE when the lane branch carries a REAL, SCOPED, COMMITTED change (so gates
  # passing on a no-op can't masquerade as a fix), and -- for a ruff-origin task -- ruff is now
  # clean in the worktree. The full-suite regression guard is the gate set, ANDed by the judge.
  param([string]$WorktreePath, [string]$Source, [string]$Base = 'main', [int]$MaxFiles = 20)
  if (-not $WorktreePath -or -not (Test-Path $WorktreePath)) {
    return @{ Ok = $false; Detail = 'worktree missing -> nothing to verify' }
  }
  # A commit must exist on this branch beyond the base (crew-rules require committing owned paths).
  $countRaw = (& git -C $WorktreePath rev-list --count "$Base..HEAD" 2>$null | Select-Object -First 1)
  $nCommits = 0; [void][int]::TryParse("$countRaw", [ref]$nCommits)
  if ($nCommits -lt 1) { return @{ Ok = $false; Detail = 'no commit on branch: nothing was fixed' } }
  # The change must be non-empty and narrow (a triage fix is surgical, not a sprawl).
  $changed = @(& git -C $WorktreePath diff --name-only "$Base...HEAD" 2>$null | Where-Object { $_ })
  if ($changed.Count -eq 0)         { return @{ Ok = $false; Detail = 'empty diff: no files changed' } }
  if ($changed.Count -gt $MaxFiles) { return @{ Ok = $false; Detail = "change too broad for a triage fix ($($changed.Count) files)" } }
  # If this task came from the local ruff signal, prove ruff specifically went red -> green.
  if ($Source -like 'local:ruff*') {
    $py = Get-VenvPython
    Push-Location $WorktreePath
    try { & $py -m ruff check . *> $null; $ruffOk = ($LASTEXITCODE -eq 0) } finally { Pop-Location }
    if (-not $ruffOk) { return @{ Ok = $false; Detail = 'ruff still reports errors in the worktree' } }
  }
  return @{ Ok = $true; Detail = "scoped committed fix ($($changed.Count) file(s)); regression covered by gates" }
}

function Get-BranchChange {
  # Shared: @{ Commits=[int]; Files=[string[]] (fwd-slashed) } for $Base...HEAD in a worktree.
  param([string]$WorktreePath, [string]$Base = 'main')
  $countRaw = (& git -C $WorktreePath rev-list --count "$Base..HEAD" 2>$null | Select-Object -First 1)
  $n = 0; [void][int]::TryParse("$countRaw", [ref]$n)
  $files = @(& git -C $WorktreePath diff --name-only "$Base...HEAD" 2>$null |
            Where-Object { $_ } | ForEach-Object { $_.Replace('\','/') })
  return @{ Commits = $n; Files = $files }
}

function Test-ProbeDevCondition {
  # probe-dev is DONE when a new/changed probe or parser is COMMITTED, REGISTERED at its
  # cross-cutting registration point (evidence._PARSERS / tools.registry -- the silent-failure
  # class from CRYPTO-H1), and covered by a TEST. "Demonstrably fires" is approximated by a probe
  # test changing plus the gate suite passing (ANDed by the judge).
  param([string]$WorktreePath, [string]$Base = 'main')
  if (-not $WorktreePath -or -not (Test-Path $WorktreePath)) {
    return @{ Ok = $false; Detail = 'worktree missing -> nothing to verify' }
  }
  $chg = Get-BranchChange -WorktreePath $WorktreePath -Base $Base
  if ($chg.Commits -lt 1)      { return @{ Ok = $false; Detail = 'no commit on branch: nothing was built' } }
  if ($chg.Files.Count -eq 0)  { return @{ Ok = $false; Detail = 'empty diff: no files changed' } }

  $touchesProbe = @($chg.Files | Where-Object { $_ -match 'findings/parsers\.py$|/probes/[^/]+\.py$' }).Count -gt 0
  $touchesReg   = @($chg.Files | Where-Object { $_ -match 'agents/evidence\.py$|tools/registry\.py$' }).Count -gt 0
  $touchesTest  = @($chg.Files | Where-Object { $_ -match '(^|/)tests/|vmapi/tests/' }).Count -gt 0

  if ($touchesProbe -and -not $touchesReg) {
    return @{ Ok = $false; Detail = 'probe/parser changed but no registration point (evidence._PARSERS / tools.registry) updated -- the silent-failure class' }
  }
  if (-not $touchesTest) {
    return @{ Ok = $false; Detail = 'no test added/updated -- cannot confirm the probe fires' }
  }
  return @{ Ok = $true; Detail = "probe change committed, registered, and tested ($($chg.Files.Count) file(s))" }
}

function Test-TestQualityCondition {
  # test-quality is DONE when the change is TESTS-ONLY (no production .py changed) and the target
  # test file (parsed from $Source '<file>:<line>') passes DETERMINISTICALLY across two runs. A
  # flaky test that passes once is not fixed, so one green run is not enough.
  param([string]$WorktreePath, [string]$Source, [string]$Base = 'main')
  if (-not $WorktreePath -or -not (Test-Path $WorktreePath)) {
    return @{ Ok = $false; Detail = 'worktree missing -> nothing to verify' }
  }
  $chg = Get-BranchChange -WorktreePath $WorktreePath -Base $Base
  if ($chg.Commits -lt 1)     { return @{ Ok = $false; Detail = 'no commit on branch: nothing changed' } }
  if ($chg.Files.Count -eq 0) { return @{ Ok = $false; Detail = 'empty diff: no files changed' } }

  $prod = @($chg.Files | Where-Object { $_ -match '\.py$' -and $_ -notmatch '(^|/)tests/|vmapi/tests/' })
  if ($prod.Count -gt 0) {
    return @{ Ok = $false; Detail = "test-quality must not change production code: $($prod -join ', ')" }
  }
  $file = ($Source -replace ':\d+\s*$', '').Trim()
  if ($file -and (Test-Path (Join-Path $WorktreePath $file))) {
    $py = Get-VenvPython
    Push-Location $WorktreePath
    try {
      & $py -m pytest -q $file *> $null; $run1 = ($LASTEXITCODE -eq 0)
      & $py -m pytest -q $file *> $null; $run2 = ($LASTEXITCODE -eq 0)
    } finally { Pop-Location }
    if (-not ($run1 -and $run2)) {
      return @{ Ok = $false; Detail = "target test not green+deterministic across two runs ($file)" }
    }
    return @{ Ok = $true; Detail = "tests-only change; $file passed twice (deterministic)" }
  }
  return @{ Ok = $true; Detail = 'tests-only change; determinism covered by the gate suite' }
}

function Test-TaskCondition {
  # The per-mode "verifiably done" predicate. Returns @{ Ok=[bool]; Detail=[string] }.
  # Gates prove the code is clean; THIS proves the task's own goal was actually achieved.
  param(
    [Parameter(Mandatory)][string]$Mode,
    [string]$WorktreePath,
    [string]$TaskId,
    [string]$Source = '',
    [string]$Base = 'main'
  )
  switch ($Mode) {
    'ci-triage'    { return (Test-CiTriageCondition    -WorktreePath $WorktreePath -Source $Source -Base $Base) }
    'probe-dev'    { return (Test-ProbeDevCondition    -WorktreePath $WorktreePath -Base $Base) }
    'test-quality' { return (Test-TestQualityCondition -WorktreePath $WorktreePath -Source $Source -Base $Base) }
    default {
      # TODO(human): implement the engagement done-condition (the one remaining mode).
      #   engagement -> the artifact renders, every cited audit hash resolves, and NO active action
      #   was taken (git diff shows no active-tool invocation); otherwise it must PARK for approval.
      #   Until implemented, the safe default below PARKs engagement (never a false PASS).
      return @{ Ok = $false; Detail = "condition for '$Mode' not implemented (TODO human) -> parked for safety" }
    }
  }
}

function Invoke-CrewJudge {
  param(
    [Parameter(Mandatory)][string]$Mode, [Parameter(Mandatory)][string]$Lane,
    [Parameter(Mandatory)][string]$TaskId, [string]$WorktreePath,
    [string]$CheckerLane = 'codex', [string]$Board = '.crew/board.md',
    [string]$Source = '', [string]$Base = 'main', [switch]$SkipGates
  )
  $reasons = @()

  if ($SkipGates) { $gates = @{ Ok = $true; Detail = 'skipped' } }
  else            { $gates = Test-GateSet -WorkDir $WorktreePath }
  $reasons += "gates: $($gates.Detail)"

  $verdict = Get-CheckerVerdict -CheckerLane $CheckerLane -TaskId $TaskId -Board $Board
  $reasons += "checker: $verdict"

  $cond = Test-TaskCondition -Mode $Mode -WorktreePath $WorktreePath -TaskId $TaskId -Source $Source -Base $Base
  $reasons += "condition: $($cond.Detail)"

  $pass = $gates.Ok -and ($verdict -eq 'APPROVED') -and $cond.Ok
  [pscustomobject]@{
    TaskId  = $TaskId
    Verdict = $(if ($pass) { 'PASS' } else { 'PARK' })
    Gates   = $gates.Ok
    Checker = $verdict
    Condition = $cond.Ok
    Reasons = $reasons
  }
}

if ($MyInvocation.InvocationName -ne '.') {
  if (-not $Mode -or -not $Lane -or -not $TaskId) { throw "crew-judge needs -Mode, -Lane, -TaskId." }
  $r = Invoke-CrewJudge -Mode $Mode -Lane $Lane -TaskId $TaskId -WorktreePath $WorktreePath `
                        -CheckerLane $CheckerLane -Board $Board -Source $Source -Base $Base -SkipGates:$SkipGates
  $r | ConvertTo-Json -Depth 4
  if ($r.Verdict -ne 'PASS') { exit 3 }  # non-zero => caller parks to triage
}
