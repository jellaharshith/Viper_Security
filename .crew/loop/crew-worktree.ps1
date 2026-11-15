<#
.SYNOPSIS
  Git worktree helper for the herdr crew loop. Each lane/task gets an isolated checkout on its own
  branch, so full-auto parallel lanes cannot collide on files (Osmani's worktree primitive).

.DESCRIPTION
  Coordinator-side, deterministic, plain-git. The worktree dir (viper-wt/<lane>__<task>) is
  gitignored. The branch loop/<lane>/<task> is what crew-pr.ps1 later pushes + opens a PR from.
  We do NOT merge locally -- the PR is the merge surface (full-auto-to-PR).

.EXAMPLE
  .\crew-worktree.ps1 -Action create -Lane claude -TaskId T123
  .\crew-worktree.ps1 -Action remove -Lane claude -TaskId T123 -DeleteBranch
  .\crew-worktree.ps1 -Action list
#>
param(
  [ValidateSet('create','remove','list')][string]$Action = 'list',
  [string]$Lane,
  [string]$TaskId,
  [string]$Base = 'HEAD',
  [switch]$DeleteBranch
)

$script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)  # .../Viper

function Get-WorktreeSlug { param([string]$Lane,[string]$TaskId) return "$Lane`__$TaskId" }
function Get-WorktreePath { param([string]$Lane,[string]$TaskId)
  return (Join-Path $script:RepoRoot (Join-Path 'viper-wt' (Get-WorktreeSlug $Lane $TaskId))) }
function Get-LoopBranch   { param([string]$Lane,[string]$TaskId) return "loop/$Lane/$TaskId" }

function New-CrewWorktree {
  param([Parameter(Mandatory)][string]$Lane, [Parameter(Mandatory)][string]$TaskId, [string]$Base = 'HEAD')
  $path   = Get-WorktreePath $Lane $TaskId
  $branch = Get-LoopBranch   $Lane $TaskId
  if (Test-Path $path) { throw "Worktree already exists: $path (remove it first)." }
  Push-Location $script:RepoRoot
  try {
    & git worktree add -b $branch $path $Base 2>&1 | Write-Verbose
    if ($LASTEXITCODE -ne 0) { throw "git worktree add failed for $branch." }
  } finally { Pop-Location }
  [pscustomobject]@{ Lane = $Lane; TaskId = $TaskId; Path = $path; Branch = $branch }
}

function Remove-CrewWorktree {
  param([Parameter(Mandatory)][string]$Lane, [Parameter(Mandatory)][string]$TaskId, [switch]$DeleteBranch)
  $path   = Get-WorktreePath $Lane $TaskId
  $branch = Get-LoopBranch   $Lane $TaskId
  Push-Location $script:RepoRoot
  try {
    if (Test-Path $path) { & git worktree remove $path --force 2>&1 | Write-Verbose }
    & git worktree prune 2>&1 | Write-Verbose
    if ($DeleteBranch) {
      & git branch -D $branch 2>&1 | Write-Verbose  # best-effort; unmerged is expected pre-PR
    }
  } finally { Pop-Location }
}

function Get-CrewWorktrees {
  Push-Location $script:RepoRoot
  try { $out = & git worktree list 2>$null } finally { Pop-Location }
  return $out
}

if ($MyInvocation.InvocationName -ne '.') {
  switch ($Action) {
    'create' {
      if (-not $Lane -or -not $TaskId) { throw "create needs -Lane and -TaskId." }
      $wt = New-CrewWorktree -Lane $Lane -TaskId $TaskId -Base $Base
      Write-Host "created: $($wt.Path) on $($wt.Branch)"
      $wt | ConvertTo-Json -Compress
    }
    'remove' {
      if (-not $Lane -or -not $TaskId) { throw "remove needs -Lane and -TaskId." }
      Remove-CrewWorktree -Lane $Lane -TaskId $TaskId -DeleteBranch:$DeleteBranch
      Write-Host "removed worktree for $Lane/$TaskId"
    }
    'list' { Get-CrewWorktrees }
  }
}
