#Requires -Version 5.1
[CmdletBinding()]
param(
  [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo       = 'koltyakov/expose'
$installDir = "$env:LOCALAPPDATA\Programs\expose"
$binary     = 'expose'

function Show-Usage {
  Write-Host @"
Install expose from GitHub Releases.

Installs the latest release to $installDir.

Examples:
  irm https://raw.githubusercontent.com/koltyakov/expose/main/scripts/install.ps1 | iex
"@
}

if ($Help) {
  Show-Usage
  exit 0
}

function Get-AssetArch {
  switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { return 'x86_64' }
    'ARM64' { return 'arm64' }
    default {
      Write-Error "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE"
      exit 1
    }
  }
}

function Invoke-Download {
  param([string]$Url, [string]$Out)
  try {
    Invoke-WebRequest -Uri $Url -OutFile $Out -UseBasicParsing
  } catch {
    Write-Error "Failed to download ${Url}: $_"
    exit 1
  }
}

$arch   = Get-AssetArch
$asset  = "${binary}_Windows_${arch}.zip"
$url    = "https://github.com/$repo/releases/latest/download/$asset"
$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
  $archive = "$tmpDir\$asset"
  Write-Host "Downloading $asset from $repo..."
  Invoke-Download -Url $url -Out $archive

  Expand-Archive -LiteralPath $archive -DestinationPath $tmpDir -Force
  $exeSrc = "$tmpDir\$binary.exe"
  if (-not (Test-Path $exeSrc)) {
    Write-Error "$binary.exe not found in $asset"
    exit 1
  }

  if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir | Out-Null
  }
  Copy-Item -Path $exeSrc -Destination "$installDir\$binary.exe" -Force

  Write-Host "Installed $binary to $installDir\$binary.exe"

  $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
  if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable('PATH', "$userPath;$installDir", 'User')
    Write-Host "Added $installDir to your user PATH."
    Write-Host 'Restart your terminal for the PATH change to take effect.'
  }
} finally {
  Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
