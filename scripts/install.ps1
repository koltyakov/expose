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

function Test-Checksum {
  param([string]$Archive, [string]$AssetName, [string]$ChecksumsFile)
  $entry = Get-Content $ChecksumsFile |
    Where-Object { $_ -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $AssetName } |
    Select-Object -First 1
  if (-not $entry) {
    Write-Error "No checksum entry for $AssetName in checksums.txt"
    exit 1
  }
  $null = $entry -match '^\s*([0-9a-fA-F]{64})\s'
  $expected = $Matches[1].ToLowerInvariant()
  $actual = (Get-FileHash -Path $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) {
    Write-Error "Checksum mismatch for ${AssetName}: expected $expected, got $actual"
    exit 1
  }
  Write-Host "Checksum verified for $AssetName"
}

$arch    = Get-AssetArch
$asset   = "${binary}_Windows_${arch}.zip"
$baseUrl = "https://github.com/$repo/releases/latest/download"
$tmpDir  = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
  $archive   = "$tmpDir\$asset"
  $checksums = "$tmpDir\checksums.txt"
  Write-Host "Downloading $asset from $repo..."
  Invoke-Download -Url "$baseUrl/$asset" -Out $archive
  Invoke-Download -Url "$baseUrl/checksums.txt" -Out $checksums
  Test-Checksum -Archive $archive -AssetName $asset -ChecksumsFile $checksums

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
