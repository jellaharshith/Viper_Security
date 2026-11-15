<#
.SYNOPSIS
  Full-auto PR opener for the herdr crew loop. Pushes a lane branch and opens a PR via `gh`.
  Runs ONLY after crew-judge returns PASS. Enforces the no-attribution rule mechanically.

.DESCRIPTION
  Osmani's loop ends code work at a PR -- the PR is the review surface, not a human pre-merge gate.
  Before opening anything, Assert-NoAttribution scans the branch's commits for Co-Authored-By /
  "Generated with" footers and REFUSES if any are present (matches includeCoAuthoredBy:false and
  the CRYPTO-H1 rule). -DryRun prints the plan without pushing or calling gh.

.EXAMPLE
  .\crew-pr.ps1 -Lane claude -TaskId T123 -Title "fix: ..." -BodyPath .crew/loop/briefs/claude-T123.md -DryRun
#>
param(
  [string]$Lane,
  [string]$TaskId,
  [string]$Title,
  [string]$BodyPath,
  [string]$Base = 'main',
  [switch]$DryRun
)

$script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Get-LoopBranch { param([string]$Lane,[string]$TaskId) return "loop/$Lane/$TaskId" }

function Test-HasAttribution {
  # Pure + unit-testable: true if $Text carries any attribution footer we forbid.
  param([string]$Text)
  if (-not $Text) { return $false }
  return [bool]($Text -match '(?im)^\s*Co-Authored-By:' -or $Text -match '(?i)Generated with')
}

function Assert-NoAttribution {
  # FAIL (return $false) if any commit on $Branch (not on $Base) carries an attribution footer.
  param([string]$Branch, [string]$Base = 'main')
  Push-Location $script:RepoRoot
  try {
    $range = "$Base..$Branch"
    $log = (& git log $range --format='%B' 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0) { $log = '' }
  } finally { Pop-Location }
  if (Test-HasAttribution $log) {
    Write-Warning "Attribution footer found on $Branch -- refusing to open PR."
    return $false
  }
  return $true
}

function New-CrewPr {
  param(
    [Parameter(Mandatory)][string]$Lane, [Parameter(Mandatory)][string]$TaskId,
    [Parameter(Mandatory)][string]$Title, [string]$BodyPath, [string]$Base = 'main', [switch]$DryRun
  )
  $branch = Get-LoopBranch $Lane $TaskId
  if (-not (Assert-NoAttribution -Branch $branch -Base $Base)) {
    return [pscustomobject]@{ Ok = $false; Reason = 'attribution-footer-present'; Branch = $branch }
  }
  $body = if ($BodyPath -and (Test-Path $BodyPath)) { Get-Content -Raw $BodyPath } else { "Automated loop PR for $TaskId." }

  if ($DryRun) {
    Write-Host "[dry-run] git push -u origin $branch"
    Write-Host "[dry-run] gh pr create --base $Base --head $branch --title `"$Title`""
    return [pscustomobject]@{ Ok = $true; DryRun = $true; Branch = $branch; Base = $Base; Title = $Title }
  }

  Push-Location $script:RepoRoot
  try {
    & git push -u origin $branch 2>&1 | Write-Verbose
    if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ Ok = $false; Reason = 'push-failed'; Branch = $branch } }
    $url = & gh pr create --base $Base --head $branch --title $Title --body $body 2>&1
    if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ Ok = $false; Reason = 'gh-pr-failed'; Detail = "$url" } }
  } finally { Pop-Location }
  return [pscustomobject]@{ Ok = $true; Branch = $branch; Url = "$url" }
}

if ($MyInvocation.InvocationName -ne '.') {
  if (-not $Lane -or -not $TaskId -or -not $Title) { throw "crew-pr needs -Lane, -TaskId, -Title." }
  $r = New-CrewPr -Lane $Lane -TaskId $TaskId -Title $Title -BodyPath $BodyPath -Base $Base -DryRun:$DryRun
  $r | ConvertTo-Json -Compress
  if (-not $r.Ok) { exit 4 }
}
