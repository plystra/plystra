$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$workspace = Split-Path -Parent $root
$outRoot = Join-Path $root "capabilities"

$capabilities = @(
  @{ Name = "system-audit"; Cmd = "cmd/system-audit"; Binary = "system-audit" },
  @{ Name = "system-identity"; Cmd = "cmd/system-identity"; Binary = "system-identity" },
  @{ Name = "system-resource-registry"; Cmd = "cmd/system-resource-registry"; Binary = "system-resource-registry" },
  @{ Name = "system-authz"; Cmd = "cmd/system-authz"; Binary = "system-authz" },
  @{ Name = "system-admin"; Cmd = "cmd/system-admin"; Binary = "system-admin" }
)

foreach ($cap in $capabilities) {
  $repo = Join-Path $workspace $cap.Name
  $dest = Join-Path $outRoot $cap.Name
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Copy-Item -Force (Join-Path $repo "capability.yaml") (Join-Path $dest "capability.yaml")
  if (Test-Path (Join-Path $dest "migrations")) {
    Remove-Item -Recurse -Force (Join-Path $dest "migrations")
  }
  Copy-Item -Recurse -Force (Join-Path $repo "migrations") (Join-Path $dest "migrations")
  $binary = $cap.Binary
  if ($IsWindows -or $env:OS -eq "Windows_NT") {
    $binary = $binary + ".exe"
  }
  Push-Location $repo
  try {
    go build -o (Join-Path $dest $binary) ("./" + $cap.Cmd)
  } finally {
    Pop-Location
  }
}

$lock = Join-Path $outRoot "plystra.lock"
if (Test-Path $lock) {
  Remove-Item -Force $lock
}

Write-Host "Built trusted system capabilities into $outRoot"
