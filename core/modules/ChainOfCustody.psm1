# DigitalValut Controller v4.0 - ChainOfCustody Module
# Integrita' forense: hash reale del contenuto + registro a catena (append-only)
# per rendere i report utilizzabili come prova documentale (manomissione-evidente).

function Get-DVContentHash {
    <#
    .SYNOPSIS
        Calcola SHA-256 di una stringa di contenuto (UTF-8).
    #>
    param([Parameter(Mandatory)][string]$Content)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash($bytes)
        return ([BitConverter]::ToString($hashBytes) -replace '-', '').ToLower()
    } finally {
        $sha.Dispose()
    }
}

function Get-DVFileHashSHA256 {
    <#
    .SYNOPSIS
        Calcola SHA-256 di un file su disco (hash del contenuto reale scritto).
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try {
        return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower()
    } catch {
        return $null
    }
}

function Get-DVLedgerPath {
    param([Parameter(Mandatory)][string]$ReportDir)
    return Join-Path $ReportDir "chain_of_custody.jsonl"
}

function Get-DVLastLedgerEntryHash {
    param([Parameter(Mandatory)][string]$LedgerPath)
    if (-not (Test-Path $LedgerPath)) { return "GENESIS" }
    $lastLine = Get-Content -Path $LedgerPath -Tail 1 -ErrorAction SilentlyContinue
    if (-not $lastLine) { return "GENESIS" }
    try {
        $entry = $lastLine | ConvertFrom-Json
        if ($entry.EntryHash) { return $entry.EntryHash }
    } catch { }
    return "GENESIS"
}

function Add-DVCustodyRecord {
    <#
    .SYNOPSIS
        Aggiunge un record al registro di catena di custodia (append-only, JSON Lines).
        Ogni record include l'hash del record precedente: qualunque modifica o cancellazione
        di un record passato rompe la catena e diventa rilevabile con Test-DVChainIntegrity.
    #>
    param(
        [Parameter(Mandatory)][string]$LedgerPath,
        [Parameter(Mandatory)][string]$ReportFileName,
        [Parameter(Mandatory)][string]$ReportFileHash,
        [string]$JsonFileHash = $null,
        [Parameter(Mandatory)][hashtable]$SystemInfo,
        [int]$ThreatScore = 0,
        [string]$ThreatLevel = ""
    )

    $previousHash = Get-DVLastLedgerEntryHash -LedgerPath $LedgerPath

    $record = [ordered]@{
        Timestamp       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
        TimestampUtc    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff'Z'")
        ComputerName    = $SystemInfo.ComputerName
        UserName        = $SystemInfo.UserName
        Domain          = $SystemInfo.Domain
        ReportFileName  = $ReportFileName
        ReportFileHash  = $ReportFileHash
        JsonFileHash    = $JsonFileHash
        ThreatScore     = $ThreatScore
        ThreatLevel     = $ThreatLevel
        PreviousHash    = $previousHash
    }

    $recordJson = $record | ConvertTo-Json -Compress -Depth 5
    $entryHash = Get-DVContentHash -Content ($previousHash + $recordJson)
    $record["EntryHash"] = $entryHash

    $finalLine = $record | ConvertTo-Json -Compress -Depth 5
    Add-Content -Path $LedgerPath -Value $finalLine -Encoding UTF8

    return [PSCustomObject]$record
}

function Test-DVChainIntegrity {
    <#
    .SYNOPSIS
        Verifica che il registro di catena di custodia non sia stato alterato:
        ricalcola ogni EntryHash dalla catena e lo confronta con quello salvato.
    .OUTPUTS
        PSCustomObject con Valid (bool), TotalEntries, e dettaglio del primo problema trovato.
    #>
    param([Parameter(Mandatory)][string]$LedgerPath)

    if (-not (Test-Path $LedgerPath)) {
        return [PSCustomObject]@{ Valid = $true; TotalEntries = 0; Message = "Nessun registro presente." }
    }

    $lines = Get-Content -Path $LedgerPath -ErrorAction SilentlyContinue
    $expectedPrevious = "GENESIS"
    $index = 0

    foreach ($line in $lines) {
        $index++
        try {
            $entry = $line | ConvertFrom-Json
        } catch {
            return [PSCustomObject]@{ Valid = $false; TotalEntries = $index; Message = "Riga $index non e' JSON valido: registro corrotto o manomesso." }
        }

        if ($entry.PreviousHash -ne $expectedPrevious) {
            return [PSCustomObject]@{ Valid = $false; TotalEntries = $index; Message = "Riga ${index}: PreviousHash non corrisponde alla catena attesa. Possibile rimozione/riordino di record." }
        }

        $savedEntryHash = $entry.EntryHash
        $recomputeSource = [ordered]@{}
        foreach ($prop in $entry.PSObject.Properties) {
            if ($prop.Name -ne 'EntryHash') { $recomputeSource[$prop.Name] = $prop.Value }
        }
        $recomputeJson = $recomputeSource | ConvertTo-Json -Compress -Depth 5
        $recomputedHash = Get-DVContentHash -Content ($entry.PreviousHash + $recomputeJson)

        if ($recomputedHash -ne $savedEntryHash) {
            return [PSCustomObject]@{ Valid = $false; TotalEntries = $index; Message = "Riga ${index}: EntryHash non corrisponde al contenuto. Il record e' stato modificato dopo la scrittura." }
        }

        $expectedPrevious = $savedEntryHash
    }

    return [PSCustomObject]@{ Valid = $true; TotalEntries = $index; Message = "Catena integra: $index record verificati, nessuna manomissione rilevata." }
}

Export-ModuleMember -Function Get-DVContentHash, Get-DVFileHashSHA256, Get-DVLedgerPath, Get-DVLastLedgerEntryHash, Add-DVCustodyRecord, Test-DVChainIntegrity
