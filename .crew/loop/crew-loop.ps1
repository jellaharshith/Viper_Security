<#
.SYNOPSIS
  The herdr crew loop runner. One cycle: discover -> queue -> worktree -> brief -> dispatch (maker)
  -> dispatch (checker) -> judge -> PR (pass) or triage (park) -> state. Osmani's loop, automated.

.DESCRIPTION
  Full-auto to PR for code work. Engagement tasks needing an ACTIVE security action are routed
  straight to triage for human approval (never auto-fired) -- honoring viper.policy.

  Orchestrates the helper scripts as child processes (clean isolation; they emit JSON + exit codes).

  -DryRun: no git/dispatch/PR side effects. Uses the noop dispatch backend, skips gates, and takes
  the judge's safe PARK default -- proves the plumbing (briefs, queue, triage) without touching live
  agents or the remote.

.EXAMPLE
  .\crew-loop.ps1 -Mode test-quality -Once -DryRun
  .\crew-loop.ps1 -Mode ci-triage -Loop -IntervalMinutes 30
#>
param(
  [ValidateSet('probe-dev','ci-triage','engagement','test-quality')][string]$Mode = 'ci-triage',
  [int]$MaxLanes = 2,
  [int]$Max = 5,
  [switch]$Once,
  [switch]$Loop,
  [int]$IntervalMinutes = 30,
  [switch]$DryRun,
  [string]$Backend = 'auto',
  [int]$DispatchTimeoutMs = 600000
)

$ErrorActionPreference = 'Stop'
$LoopDir   = $PSScriptRoot
$RepoRoot  = Split-Path -Parent (Split-Path -Parent $LoopDir)
$QueuePath = Join-Path $LoopDir 'queue.json'
$StatePath = Join-Path $LoopDir 'state.md'
$BriefDir  = Join-Path $LoopDir 'briefs'
$TriageDir = Join-Path $LoopDir 'triage'
$Board     = Join-Path $RepoRoot '.crew\board.md'

function Read-LoopTasks {
  param([string]$Mode, [int]$Max)
  $raw = & (Join-Path $LoopDir "discover\$Mode.ps1") -Max $Max
  if (-not $raw) { return @() }
  return @(($raw -join "`n") | ConvertFrom-Json)
}

function Get-Queue {
  if (Test-Path $QueuePath) {
    try { return (Get-Content -Raw $QueuePath | ConvertFrom-Json) } catch {}
  }
  return [pscustomobject]@{ updated = ''; tasks = @() }
}

function Save-Queue {
  param($Queue)
  $Queue.updated = [DateTime]::UtcNow.ToString('o')
  $Queue | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 $QueuePath
}

function Merge-Tasks {
  # Add newly-discovered tasks to the queue, deduping by id (keeps existing status).
  param($Queue, [object[]]$New)
  $byId = [ordered]@{}
  foreach ($t in @($Queue.tasks)) { if ($t.id) { $byId[$t.id] = $t } }
  foreach ($t in @($New)) { if ($t.id -and -not $byId.Contains($t.id)) { $byId[$t.id] = $t } }
  $Queue.tasks = @($byId.Values)
  return $Queue
}

function New-Brief {
  param($Task, [string]$Role, [string]$WorktreePath, [string]$Branch)
  $isChecker = ($Role -eq 'checker')
  $agent = if ($isChecker) { $Task.checker } else { $Task.maker }
  $file  = Join-Path $BriefDir ("{0}-{1}.md" -f $agent, $Task.id)
  $owns  = if ($Task.owns -and @($Task.owns).Count) { ($Task.owns -join ', ') } else { 'choose the narrowest set and name them in your READY' }
  if ($isChecker) {
    $body = @"
You are $agent, the INDEPENDENT checker for task $($Task.id) (you did NOT write this change).
Repo: $RepoRoot  Worktree: $WorktreePath ($Branch)  Mode: $($Task.mode)
Read .crew/loop/skills/crew-rules.md and .crew/loop/skills/$($Task.mode).md.

VERIFY independently -- do not just read the diff:
1. Re-run the gates inside the worktree: ruff check . ; mypy src ; pytest -q vmapi\tests tests
2. Confirm the done-condition actually holds: $($Task.condition)
3. probe-dev: confirm every registration point is updated (src/viper/agents/evidence.py _PARSERS,
   src/viper/tools/registry.py) -- this is the class that silently broke before.
4. engagement: confirm NO active security action was taken.

Post 'APPROVED $($Task.id)' or 'REJECTED $($Task.id): <reason>' under '## $agent' in .crew/board.md, then STOP.
"@
  } else {
    $body = @"
You are $agent in the Viper herdr crew (loop mode, $($Task.mode)).
Repo: $RepoRoot  Worktree: $WorktreePath ($Branch)
Read .crew/loop/skills/crew-rules.md and .crew/loop/skills/$($Task.mode).md. Follow the RULES exactly.

TASK $($Task.id): $($Task.title)
Source: $($Task.source)
Owns: $owns
Verifiable done-condition (the checker and stop-judge enforce this): $($Task.condition)

Steps:
1. Work ONLY inside your worktree: $WorktreePath
2. TDD: write the failing test first, watch it go RED, then implement to GREEN.
3. Gates green: ruff check . ; mypy src ; pytest -q vmapi\tests tests
4. Commit ONLY your own paths. NO attribution trailers.
5. Post 'READY $($Task.id)' (or 'BLOCKED $($Task.id): <reason>') under '## $agent' in .crew/board.md, then STOP.
"@
  }
  Set-Content -Encoding utf8 -Path $file -Value $body
  return $file
}

function New-TriageCard {
  param($Task, [string]$Reason, [string[]]$Detail = @())
  $file = Join-Path $TriageDir ("{0}-{1}.md" -f $Task.mode, $Task.id)
  $lines = @(
    "# Triage: $($Task.id) ($($Task.mode))",
    "", "- **Title:** $($Task.title)",
    "- **Reason parked:** $Reason",
    "- **Requires approval:** $($Task.requires_approval)",
    "- **Condition:** $($Task.condition)",
    "- **Source:** $($Task.source)",
    "- **When:** $([DateTime]::UtcNow.ToString('o'))",
    ""
  )
  if ($Detail) { $lines += '## Detail'; $lines += ($Detail | ForEach-Object { "- $_" }) }
  $lines += @("", "A human reviews this, approves/redirects, then the loop can pick it up again.")
  Set-Content -Encoding utf8 -Path $file -Value ($lines -join "`n")
  return $file
}

function Add-StateLog {
  param([string]$Line)
  "- $([DateTime]::UtcNow.ToString('o')) $Line" | Add-Content -Encoding utf8 -Path $StatePath
}

function Set-TaskStatus { param($Task, [string]$Status) $Task.status = $Status }

function Invoke-LoopCycle {
  Write-Host "=== cycle: mode=$Mode dryrun=$DryRun maxlanes=$MaxLanes ===" -ForegroundColor Cyan
  $queue = Get-Queue
  $discovered = Read-LoopTasks -Mode $Mode -Max $Max
  $queue = Merge-Tasks -Queue $queue -New $discovered
  Save-Queue $queue
  Write-Host "discovered $(@($discovered).Count); queue size $(@($queue.tasks).Count)"

  $ready = @($queue.tasks | Where-Object { $_.status -eq 'ready' -and $_.mode -eq $Mode } | Select-Object -First $MaxLanes)
  if (-not $ready -or $ready.Count -eq 0) {
    Add-StateLog "quiet cycle ($Mode): nothing ready"
    Write-Host "nothing ready -- quiet cycle."
    return
  }

  foreach ($task in $ready) {
    # Safety gate: engagement tasks needing an active action never auto-dispatch.
    if ($task.mode -eq 'engagement' -and $task.requires_approval) {
      $card = New-TriageCard -Task $task -Reason 'active action requires human approval'
      Set-TaskStatus $task 'parked'; Save-Queue $queue
      Add-StateLog "PARK $($task.id): approval-required -> $card"
      Write-Host "  PARK $($task.id): approval-required" -ForegroundColor Yellow
      continue
    }

    $maker = $task.maker; $id = $task.id
    Write-Host "  task $id ($maker): $($task.title)"

    # Worktree
    $wtPath = Join-Path $RepoRoot ("viper-wt\{0}__{1}" -f $maker, $id)
    $branch = "loop/$maker/$id"
    if (-not $DryRun) {
      & (Join-Path $LoopDir 'crew-worktree.ps1') -Action create -Lane $maker -TaskId $id | Out-Null
    }

    # Briefs
    $makerBrief   = New-Brief -Task $task -Role 'maker'   -WorktreePath $wtPath -Branch $branch
    $checkerBrief = New-Brief -Task $task -Role 'checker' -WorktreePath $wtPath -Branch $branch
    Set-TaskStatus $task 'dispatched'; Save-Queue $queue

    $dispatchBackend = if ($DryRun) { 'noop' } else { $Backend }
    $doWait = -not $DryRun

    # Dispatch maker (wait for settle), then the independent checker.
    & (Join-Path $LoopDir 'crew-dispatch.ps1') -Role $maker -Lane $maker -BriefPath $makerBrief `
        -Backend $dispatchBackend -Wait:$doWait -TimeoutMs $DispatchTimeoutMs | Out-Null
    Set-TaskStatus $task 'checking'; Save-Queue $queue
    & (Join-Path $LoopDir 'crew-dispatch.ps1') -Role $task.checker -Lane $task.checker -BriefPath $checkerBrief `
        -Backend $dispatchBackend -Wait:$doWait -TimeoutMs $DispatchTimeoutMs | Out-Null

    # Judge  (hashtable splat passes NAMED params; an array splat would go positional)
    $judgeArgs = @{ Mode = $Mode; Lane = $maker; TaskId = $id; WorktreePath = $wtPath; Board = $Board; Source = "$($task.source)" }
    if ($DryRun) { $judgeArgs.SkipGates = $true }
    $judgeRaw = & (Join-Path $LoopDir 'crew-judge.ps1') @judgeArgs
    $judge = ($judgeRaw -join "`n") | ConvertFrom-Json

    if ($judge.Verdict -eq 'PASS') {
      $prArgs = @{ Lane = $maker; TaskId = $id; Title = "$($task.mode): $($task.title)"; BodyPath = $makerBrief }
      if ($DryRun) { $prArgs.DryRun = $true }
      & (Join-Path $LoopDir 'crew-pr.ps1') @prArgs | Out-Null
      Set-TaskStatus $task 'done'; Save-Queue $queue
      Add-StateLog "PASS $id -> PR ($($task.title))"
      Write-Host "  PASS $id -> PR" -ForegroundColor Green
    } else {
      $card = New-TriageCard -Task $task -Reason 'stop-judge did not PASS' -Detail $judge.Reasons
      Set-TaskStatus $task 'parked'; Save-Queue $queue
      Add-StateLog "PARK ${id}: $($judge.Reasons -join '; ') -> $card"
      Write-Host "  PARK $id ($($judge.Reasons -join '; '))" -ForegroundColor Yellow
    }

    # Cleanup worktree on park (branch kept for a real PR on pass).
    if (-not $DryRun -and $task.status -eq 'parked') {
      & (Join-Path $LoopDir 'crew-worktree.ps1') -Action remove -Lane $maker -TaskId $id -DeleteBranch | Out-Null
    }
  }
}

# --- run ---
if ($MyInvocation.InvocationName -ne '.') {
  do {
    Invoke-LoopCycle
    if ($Loop -and -not $Once) {
      Write-Host "sleeping $IntervalMinutes min..." -ForegroundColor DarkGray
      Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
  } while ($Loop -and -not $Once)
  exit 0  # a completed cycle is success; per-task PARK/PASS is recorded in state + triage, not the exit code
}
