# Shared helpers for loop discovery scripts. Dot-sourced by each discover/<mode>.ps1.

function New-LoopTask {
  param(
    [Parameter(Mandatory)][string]$Mode,
    [Parameter(Mandatory)][string]$Title,
    [string]$Maker = 'claude',
    [string]$Checker = 'codex',
    [string[]]$Owns = @(),
    [string]$Condition = '',
    [bool]$RequiresApproval = $false,
    [string]$Source = ''
  )
  # Deterministic short id from mode+title so re-discovery dedups instead of duplicating.
  $hash = [System.BitConverter]::ToString(
    [System.Security.Cryptography.MD5]::Create().ComputeHash(
      [System.Text.Encoding]::UTF8.GetBytes("$Mode|$Title"))).Replace('-','').Substring(0,8)
  [pscustomobject]@{
    id               = "T$hash"
    mode             = $Mode
    title            = $Title
    maker            = $Maker
    checker          = $Checker
    owns             = $Owns
    condition        = $Condition
    requires_approval = $RequiresApproval
    status           = 'ready'
    source           = $Source
  }
}

function Get-RepoRoot {
  # Walk up from where this helper lives until a .git dir is found. Depth-independent.
  param([string]$Start = $PSScriptRoot)
  $d = Get-Item -LiteralPath $Start
  while ($d -and -not (Test-Path (Join-Path $d.FullName '.git'))) { $d = $d.Parent }
  if (-not $d) { throw "repo root (.git) not found from $Start" }
  return $d.FullName
}
