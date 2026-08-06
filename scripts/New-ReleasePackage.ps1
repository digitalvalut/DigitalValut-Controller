#Requires -Version 5.1
<#
.SYNOPSIS
    Crea il pacchetto ZIP di una release e il relativo file di checksum SHA-256.
.DESCRIPTION
    Impacchetta i file tracciati da git (rispetta .gitignore: nessun report reale,
    nessun file di test locale) in uno ZIP riproducibile, poi calcola l'hash
    SHA-256 dello ZIP e lo scrive in SHA256SUMS.txt, cosi' chi scarica la release
    puo' verificare l'integrita' del file prima di eseguirlo.
.PARAMETER Version
    Numero di versione da usare nel nome del pacchetto (es. "4.1.0").
.EXAMPLE
    .\scripts\New-ReleasePackage.ps1 -Version 4.1.0
#>
param(
    [Parameter(Mandatory)][string]$Version
)

$ErrorActionPreference = "Stop"
$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$outDir = Join-Path $repoRoot "dist"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

$zipName = "DigitalValut-Controller-v$Version.zip"
$zipPath = Join-Path $outDir $zipName

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

Push-Location $repoRoot
try {
    $files = git ls-files
    if (-not $files) { throw "Nessun file tracciato da git trovato: esegui questo script dentro il repository." }

    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dv-release-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    try {
        foreach ($f in $files) {
            $dest = Join-Path $tempDir $f
            $destDir = Split-Path -Parent $dest
            if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
            Copy-Item -Path $f -Destination $dest -Force
        }
        Compress-Archive -Path (Join-Path $tempDir "*") -DestinationPath $zipPath -CompressionLevel Optimal
    } finally {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} finally {
    Pop-Location
}

$hash = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLower()
$sumsPath = Join-Path $outDir "SHA256SUMS.txt"
"$hash  $zipName" | Set-Content -Path $sumsPath -Encoding UTF8 -NoNewline
Add-Content -Path $sumsPath -Value "" -Encoding UTF8

Write-Host "Pacchetto creato: $zipPath"
Write-Host "SHA-256: $hash"
Write-Host "Checksum salvato in: $sumsPath"
