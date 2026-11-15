<#
.SYNOPSIS
  Dispatch adapter for the herdr crew loop. Resolves a live agent, sends a kick that points at a
  brief file, and (optionally) waits for the agent to settle.

.DESCRIPTION
  herdr is the real backend (detected on this machine). `herdr agent prompt <target> <msg>
  --wait` submits the kick AND waits for a settled state in one call. Targets are herdr pane IDs
  (e.g. w4:p3, as in .crew/panes.txt) or live agent names (e.g. codex-crypto). Live agents are
  discovered via `herdr agent list` -- panes.txt is only a hint, it goes stale between sessions.

  IMPORTANT (safety): a settled idle/done state does NOT prove the work is complete (per the herdr
  skill). The loop confirms the agent's explicit READY line on the board in addition to this.

  Backends (auto priority): herdr -> wezterm -> tmux -> manual. `noop` is for dry-runs/tests.

.EXAMPLE
  .\crew-dispatch.ps1 -Probe
.EXAMPLE
  .\crew-dispatch.ps1 -ListAgents
.EXAMPLE
  .\crew-dispatch.ps1 -Target w4:p3 -Lane codex-ci -BriefPath .crew/loop/briefs/codex-ci-T12.md -Wait
#>
param(
  [string]$Target,
  [string]$Role,
  [string]$Lane,
  [string]$BriefPath,
  [string]$Message,
  [ValidateSet('auto','herdr','wezterm','tmux','manual','noop')]
  [string]$Backend = 'auto',
  [int]$TimeoutMs = 600000,
  [switch]$Wait,
  [switch]$Probe,
  [switch]$ListAgents
)

$script:NoopLog = Join-Path $PSScriptRoot 'dispatch-noop.log'

function Test-Cmd { param([string]$Name) [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

function Resolve-CrewBackend {
  param([string]$Requested = 'auto')
  if ($Requested -ne 'auto') { return $Requested }
  if (Test-Cmd 'herdr')   { return 'herdr' }
  if (Test-Cmd 'wezterm') { return 'wezterm' }
  if (Test-Cmd 'tmux')    { return 'tmux' }
  return 'manual'
}

function Get-CrewAgents {
  # Ground truth: live agents from the herdr socket API. Returns @() on any failure.
  if (-not (Test-Cmd 'herdr')) { return @() }
  try {
    $raw = & herdr agent list 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return @() }
    $json = $raw | ConvertFrom-Json
    return @($json.result.agents)
  } catch { return @() }
}

function Resolve-CrewTarget {
  # Pick a live agent by role/lane prefix (e.g. 'codex' matches 'codex-crypto'). $null if none live.
  param([string]$Role, [object[]]$Agents = $null)
  if ($null -eq $Agents) { $Agents = Get-CrewAgents }
  if (-not $Agents -or $Agents.Count -eq 0) { return $null }
  $match = $Agents | Where-Object { $_.agent -like "$Role*" } | Select-Object -First 1
  if ($match) { return $match.pane_id }
  return $null
}

function New-KickMessage {
  param([string]$Lane, [string]$BriefPath)
  $rel = $BriefPath.Replace('\','/')
  return ("You are {0} in the Viper herdr crew (loop mode). Read {1} top to bottom and follow it, " +
          "plus .crew/loop/skills/crew-rules.md. When done, post a READY line (or 'BLOCKED: <reason>') " +
          "under your board heading in .crew/board.md, then STOP.") -f $Lane, $rel
}

function Send-ViaHerdr {
  param([string]$Target, [string]$Message, [switch]$Wait, [int]$TimeoutMs)
  $a = @('agent','prompt',$Target,$Message)
  if ($Wait) { $a += @('--wait','--timeout',"$TimeoutMs") }
  & herdr @a
  return ($LASTEXITCODE -eq 0)
}

function ConvertTo-WeztermPaneId {
  param([string]$Address)
  if ($Address -match 'p(\d+)\s*$') { return [int]$Matches[1] }
  if ($Address -match '^\d+$')      { return [int]$Address }
  return $null
}

function Send-ViaWezterm {
  param([string]$Target, [string]$Message)
  $id = ConvertTo-WeztermPaneId $Target
  if ($null -eq $id) { Write-Warning "Cannot map '$Target' to a WezTerm pane id."; return $false }
  $Message | & wezterm cli send-text --pane-id $id --no-paste
  & wezterm cli send-text --pane-id $id --no-paste "`n" | Out-Null
  return ($LASTEXITCODE -eq 0)
}

function Send-ViaTmux {
  param([string]$Target, [string]$Message)
  & tmux send-keys -t $Target $Message Enter
  return ($LASTEXITCODE -eq 0)
}

function Send-ViaManual {
  param([string]$Target, [string]$BriefPath)
  Write-Host "[manual] Brief ready: $BriefPath" -ForegroundColor Yellow
  Write-Host "[manual] Kick target '$Target' by hand, then let the loop resume." -ForegroundColor Yellow
  return $true
}

function Send-ViaNoop {
  param([string]$Target, [string]$BriefPath)
  "$([DateTime]::UtcNow.ToString('o'))`t$Target`t$BriefPath" | Add-Content -Path $script:NoopLog
  return $true
}

function Send-CrewBrief {
  param(
    [string]$Target,
    [string]$Role,
    [string]$Lane,
    [Parameter(Mandatory)][string]$BriefPath,
    [string]$Message,
    [string]$Backend = 'auto',
    [switch]$Wait,
    [int]$TimeoutMs = 600000
  )
  if (-not (Test-Path $BriefPath)) { throw "Brief not found: $BriefPath" }
  $resolved = Resolve-CrewBackend $Backend

  # Resolve a live target from role when no explicit pane/name was given.
  if (-not $Target -and $Role -and $resolved -eq 'herdr') {
    $Target = Resolve-CrewTarget -Role $Role
    if (-not $Target) {
      Write-Warning "No live herdr agent matches role '$Role' -- caller should park this task."
      return $false
    }
  }
  if (-not $Target) { $Target = $Role }  # last-resort: pass role through to fallback backends
  if (-not $Lane) { $Lane = $Role }
  if (-not $Message) { $Message = New-KickMessage -Lane $Lane -BriefPath $BriefPath }

  Write-Host "[dispatch] backend=$resolved target=$Target lane=$Lane brief=$BriefPath wait=$Wait"
  switch ($resolved) {
    'herdr'   { return Send-ViaHerdr   -Target $Target -Message $Message -Wait:$Wait -TimeoutMs $TimeoutMs }
    'wezterm' { return Send-ViaWezterm -Target $Target -Message $Message }
    'tmux'    { return Send-ViaTmux    -Target $Target -Message $Message }
    'manual'  { return Send-ViaManual  -Target $Target -BriefPath $BriefPath }
    'noop'    { return Send-ViaNoop    -Target $Target -BriefPath $BriefPath }
  }
}

# --- run-as-script guard (skipped when dot-sourced by tests) ---
if ($MyInvocation.InvocationName -ne '.') {
  if ($Probe) { Write-Host "Detected dispatch backend: $(Resolve-CrewBackend $Backend)"; return }
  if ($ListAgents) {
    $agents = Get-CrewAgents
    if (-not $agents -or $agents.Count -eq 0) { Write-Host "No live herdr agents."; return }
    $agents | ForEach-Object { Write-Host ("{0}`t{1}`t{2}" -f $_.pane_id, $_.agent, $_.agent_status) }
    return
  }
  if (-not $BriefPath) { throw "Provide -BriefPath (with -Target or -Role), or -Probe / -ListAgents." }
  $ok = Send-CrewBrief -Target $Target -Role $Role -Lane $Lane -BriefPath $BriefPath -Message $Message `
                       -Backend $Backend -Wait:$Wait -TimeoutMs $TimeoutMs
  if (-not $ok) { exit 1 }
}
