#Requires -Version 5.1
[CmdletBinding()]
param(
  [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installDir = "$env:LOCALAPPDATA\Programs\expose"
$binary     = 'expose'

function Show-Usage {
  Write-Host @"
Uninstall expose.

Removes expose from $installDir and removes that directory from your user PATH.

Examples:
  irm https://raw.githubusercontent.com/koltyakov/expose/main/scripts/uninstall.ps1 | iex
"@
}

function Normalize-PathEntry {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) {
    return ''
  }
  try {
    return [System.IO.Path]::GetFullPath($Path.Trim()).TrimEnd([char[]]@('\', '/'))
  } catch {
    return $Path.Trim().TrimEnd([char[]]@('\', '/'))
  }
}

if ($Help) {
  Show-Usage
  exit 0
}

$exePath = Join-Path $installDir "$binary.exe"

if (Test-Path $exePath) {
  Remove-Item -LiteralPath $exePath -Force
  Write-Host "Removed $exePath"
} else {
  Write-Host "$binary is not installed at $exePath"
}

if (Test-Path $installDir) {
  $remaining = Get-ChildItem -LiteralPath $installDir -Force -ErrorAction SilentlyContinue
  if (-not $remaining) {
    Remove-Item -LiteralPath $installDir -Force
    Write-Host "Removed $installDir"
  }
}

$userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
if ($userPath) {
  $installDirKey = Normalize-PathEntry $installDir
  $parts = $userPath -split ';' | Where-Object {
    $entry = ([string]$_).Trim()
    $entry -and ((Normalize-PathEntry $entry) -ine $installDirKey)
  }
  $newPath = $parts -join ';'
  if ($newPath -ne $userPath) {
    [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')
    Write-Host "Removed $installDir from your user PATH."
    Write-Host 'Restart your terminal for the PATH change to take effect.'
  }
}
