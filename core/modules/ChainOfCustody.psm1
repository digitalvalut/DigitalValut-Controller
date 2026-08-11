# DigitalValut Controller v5.0 - ChainOfCustody Module
# Copyright (C) 2024-2026 DigitalValut - www.digitalvalut.it
# Sviluppatore: Dott. Giuseppe Falsone e il team DigitalValut
#
# Questo file e' parte di DigitalValut Controller.
# Software libero: puoi ridistribuirlo e/o modificarlo secondo i termini della
# GNU General Public License v3.0 o (a tua scelta) qualsiasi versione successiva,
# come pubblicata dalla Free Software Foundation.
# Distribuito SENZA ALCUNA GARANZIA; senza neppure la garanzia implicita di
# COMMERCIABILITA' o IDONEITA' PER UNO SCOPO PARTICOLARE. Vedi la GNU GPL v3.
# Copia della licenza nel file LICENSE. Avvertenze e limiti: DISCLAIMER.md

# Integrita' dei report: hash SHA-256 reale del contenuto + registro a catena
# (append-only) per rendere EVIDENTE un'eventuale manomissione (tamper-evident).
#
# LIMITI NOTI (dichiarati esplicitamente, vedi DISCLAIMER.md):
# - Il registro risiede sulla stessa macchina ed e' scrivibile dallo stesso utente
#   che genera i report; l'algoritmo e' pubblico (software open source). Un soggetto
#   tecnicamente competente puo' quindi rigenerare l'intera catena da zero.
# - Non esiste marcatura temporale certificata da terza parte (RFC 3161) ne'
#   notarizzazione esterna: i timestamp provengono dall'orologio di sistema locale.
# - Il meccanismo rileva alterazioni accidentali o manomissioni non esperte.
#   NON costituisce acquisizione forense ai sensi della L. 48/2008 e non e'
#   di per se' opponibile in giudizio: per finalita' probatorie e' necessaria
#   una perizia eseguita da un tecnico forense qualificato.

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

function Get-DVLastLedgerEntry {
    <#
    .SYNOPSIS
        Restituisce l'ultimo record del registro (oggetto completo), o $null se il
        registro non esiste o e' vuoto. Usato per confrontare la scansione corrente
        con l'ultima registrata (vedi Compare-DVScanFindings).
    #>
    param([Parameter(Mandatory)][string]$LedgerPath)
    if (-not (Test-Path $LedgerPath)) { return $null }
    $lastLine = Get-Content -Path $LedgerPath -Tail 1 -ErrorAction SilentlyContinue
    if (-not $lastLine) { return $null }
    try {
        return ($lastLine | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Compare-DVScanFindings {
    <#
    .SYNOPSIS
        Confronta i findings della scansione corrente con quelli dell'ultima
        scansione registrata nella catena di custodia, leggendo il file JSON
        della scansione precedente (stessa cartella dei report).
    .DESCRIPTION
        Funzione puramente locale: non richiede alcuna connessione di rete.
        Se non esiste una scansione precedente valida, restituisce $null: in
        quel caso il report non mostrera' alcuna sezione di confronto.
    #>
    param(
        [Parameter(Mandatory)][string]$LedgerPath,
        [Parameter(Mandatory)][string]$ReportDir,
        [Parameter(Mandatory)][int]$CurrentScore,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$CurrentFindings
    )

    $previous = Get-DVLastLedgerEntry -LedgerPath $LedgerPath
    if (-not $previous) { return $null }

    $prevJsonName = $previous.ReportFileName -replace '\.html$', '.json'
    $prevJsonPath = Join-Path $ReportDir $prevJsonName
    if (-not (Test-Path $prevJsonPath)) { return $null }

    try {
        $prevData = Get-Content -Path $prevJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $prevFindings = @($prevData.ThreatScore.Findings)
    } catch {
        return $null
    }

    $currentSet = @($CurrentFindings)
    $newFindings      = @($currentSet | Where-Object { $prevFindings -notcontains $_ })
    $resolvedFindings = @($prevFindings | Where-Object { $currentSet -notcontains $_ })

    return @{
        PreviousTimestamp = $previous.Timestamp
        PreviousScore     = [int]$previous.ThreatScore
        PreviousLevel     = $previous.ThreatLevel
        CurrentScore      = $CurrentScore
        ScoreDelta        = ($CurrentScore - [int]$previous.ThreatScore)
        NewFindings       = $newFindings
        ResolvedFindings  = $resolvedFindings
        Unchanged         = ($newFindings.Count -eq 0 -and $resolvedFindings.Count -eq 0)
    }
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

Export-ModuleMember -Function Get-DVContentHash, Get-DVFileHashSHA256, Get-DVLedgerPath, Get-DVLastLedgerEntryHash, Get-DVLastLedgerEntry, Compare-DVScanFindings, Add-DVCustodyRecord, Test-DVChainIntegrity
