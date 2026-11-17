#Requires -Version 5.1
[CmdletBinding()]
param(
  [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo       = 'koltyakov/expose'
$installDir = Join-Path (Join-Path $env:LOCALAPPDATA 'Programs') 'expose'
$binary     = 'expose'
# Filled by release-sign -mode prepare. Runtime environment keys are not trusted.
$pinnedKeysJSON = 'EXPOSE_PINNED_RELEASE_KEYS'

function Show-Usage {
  Write-Host @"
Install expose from GitHub Releases.

Installs the latest release to $installDir.

Examples:
  irm https://github.com/koltyakov/expose/releases/latest/download/install.ps1 | iex
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

function Test-Signature {
  param([string]$ChecksumsFile, $Envelope, [string]$Directory)
  if ((Get-Item -LiteralPath $ChecksumsFile).Length -gt 1048576) {
    throw 'Checksum manifest exceeds size limit'
  }
  $properties = @($pinnedKeys.PSObject.Properties | Where-Object { $_.Name -ceq $Envelope.keyId })
  if ($properties.Count -ne 1 -or $properties[0].Value -cnotmatch '^[A-Za-z0-9+/]{43}=$') {
    throw 'Unknown or invalid pinned release signing key'
  }
  $property = $properties[0]
  $publicKey = [Convert]::FromBase64String($property.Value)
  if ($publicKey.Length -ne 32) { throw 'Invalid Ed25519 public key' }
  $keyPath = Join-Path $Directory 'key.pem'
  [IO.File]::WriteAllText($keyPath, "-----BEGIN PUBLIC KEY-----`nMCowBQYDK2VwAyEA$($property.Value)`n-----END PUBLIC KEY-----`n", [Text.Encoding]::ASCII)
  $sigPath = Join-Path $Directory 'signature.bin'
  $sigBytes = [Convert]::FromBase64String($Envelope.signature)
  if ($sigBytes.Length -ne 64) { throw 'Invalid Ed25519 signature' }
  [IO.File]::WriteAllBytes($sigPath, $sigBytes)
  $messagePath = Join-Path $Directory 'signed'
  $header = [Text.Encoding]::UTF8.GetBytes("expose-release-v1`n$repo`n$($Envelope.tag)`n$($Envelope.keyId)`n")
  [IO.File]::WriteAllBytes($messagePath, [byte[]]($header + [IO.File]::ReadAllBytes($ChecksumsFile)))
  & $openssl.Source pkeyutl -verify -pubin -inkey $keyPath -rawin -in $messagePath -sigfile $sigPath
  if ($LASTEXITCODE -ne 0) {
    throw 'Signature verification failed for checksums.txt'
  }
  Write-Host 'Signature verified for checksums.txt'
}

$openssl = Get-Command openssl -ErrorAction Stop
$opensslVersion = & $openssl.Source version
if ($LASTEXITCODE -ne 0 -or $opensslVersion -notmatch '^OpenSSL [34]\.') {
  throw 'OpenSSL 3 or newer is required for Ed25519 verification'
}
$pinnedKeys = $pinnedKeysJSON | ConvertFrom-Json
if (-not $pinnedKeys -or @($pinnedKeys.PSObject.Properties).Count -eq 0) {
  throw 'Use the prepared installer attached to a release'
}

$arch    = Get-AssetArch
$asset   = "${binary}_Windows_${arch}.zip"
$baseUrl = "https://github.com/$repo/releases/latest/download"
$tmpDir  = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
  $archive   = Join-Path $tmpDir $asset
  $checksums = Join-Path $tmpDir 'checksums.txt'
  $signature = Join-Path $tmpDir 'checksums.txt.sig'
  Write-Host "Downloading $asset from $repo..."
  Invoke-Download -Url "$baseUrl/checksums.txt.sig" -Out $signature
  if ((Get-Item -LiteralPath $signature).Length -gt 4096) { throw 'Signature exceeds size limit' }
  $envelope = [IO.File]::ReadAllText($signature) | ConvertFrom-Json
  $fields = @($envelope.PSObject.Properties.Name | Sort-Object)
  if (($fields -join ',') -cne 'keyId,repository,signature,tag,version' -or
      $envelope.version -ne 1 -or $envelope.repository -cne $repo -or
      $envelope.tag -cnotmatch '^v[0-9][a-zA-Z0-9.+_-]{0,127}$' -or
      $envelope.keyId -cnotmatch '^[a-zA-Z0-9._-]{1,80}$' -or
      $envelope.signature -cnotmatch '^[A-Za-z0-9+/]{86}==$') {
    throw 'Invalid release signature envelope'
  }
  $baseUrl = "https://github.com/$repo/releases/download/$($envelope.tag)"
  Invoke-Download -Url "$baseUrl/checksums.txt" -Out $checksums
  Test-Signature -ChecksumsFile $checksums -Envelope $envelope -Directory $tmpDir
  Invoke-Download -Url "$baseUrl/$asset" -Out $archive
  Test-Checksum -Archive $archive -AssetName $asset -ChecksumsFile $checksums

  Expand-Archive -LiteralPath $archive -DestinationPath $tmpDir -Force
  $exeSrc = Join-Path $tmpDir "$binary.exe"
  if (-not (Test-Path $exeSrc)) {
    Write-Error "$binary.exe not found in $asset"
    exit 1
  }

  if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir | Out-Null
  }
  $exeDest = Join-Path $installDir "$binary.exe"
  Copy-Item -Path $exeSrc -Destination $exeDest -Force

  Write-Host "Installed $binary to $exeDest"

  $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
  if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable('PATH', "$userPath;$installDir", 'User')
    Write-Host "Added $installDir to your user PATH."
    Write-Host 'Restart your terminal for the PATH change to take effect.'
  }
} finally {
  Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
