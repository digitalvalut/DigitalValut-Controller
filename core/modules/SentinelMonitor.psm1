# DigitalValut Controller v5.0 - SentinelMonitor Module
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
#
# MODALITA' SENTINELLA - MONITORAGGIO CONTINUO
#
# Perche' esiste: una scansione singola e' una fotografia. Se il collegamento
# remoto avviene alle 3 di notte, o il microfono si attiva mentre l'utente non
# e' alla postazione, una fotografia non lo vedra' mai. La Sentinella osserva nel
# tempo e registra gli eventi MENTRE ACCADONO.
#
# La differenza sul piano documentale e' sostanziale: si passa da "sul PC e'
# installato un software di controllo remoto" (circostanza che ammette molte
# spiegazioni) a "il 14 marzo, dalle 03:12 alle 03:59, la postazione ha avuto
# una sessione di controllo remoto attiva dall'indirizzo 10.x.x.x" (un fatto
# circostanziato, con inizio, fine e durata).
#
# COME REGISTRA
# - Registro append-only in JSON Lines, un evento per riga.
# - Ogni riga include l'hash della riga precedente (catena): rimuovere o
#   modificare un evento passato rompe la catena e diventa rilevabile.
# - Deduplicazione a sessioni: una connessione continuativa NON genera una riga
#   ogni ciclo, ma due soli eventi (APERTURA e CHIUSURA) con la durata. Questo
#   rende il registro leggibile e utilizzabile, invece di migliaia di righe.
#
# LIMITI DICHIARATI (vedi DISCLAIMER.md)
# - Campiona a intervalli: una sessione piu' breve dell'intervallo di
#   campionamento puo' non essere osservata. L'intervallo e' registrato nel log.
# - Se il PC e' spento o la Sentinella non e' in esecuzione, non osserva nulla:
#   i "buchi" temporali sono espliciti nel registro (eventi AVVIO e ARRESTO).
# - Registra cio' che il sistema operativo espone; senza privilegi
#   amministrativi alcuni processi non sono ispezionabili.
# - Non e' un intercettatore di traffico: non vede il CONTENUTO delle sessioni,
#   solo la loro esistenza, origine e durata.

$Global:DVSentinelStopFileName = "STOP_SENTINELLA.txt"

function Get-DVSentinelLogPath {
    param([Parameter(Mandatory)][string]$ReportDir)
    return (Join-Path $ReportDir "sentinella_eventi.jsonl")
}

function Get-DVSentinelStopPath {
    param([Parameter(Mandatory)][string]$ReportDir)
    return (Join-Path $ReportDir $Global:DVSentinelStopFileName)
}

function Add-DVSentinelEvent {
    <#
    .SYNOPSIS
        Aggiunge un evento al registro della Sentinella, concatenandolo
        crittograficamente all'evento precedente.
    .DESCRIPTION
        Ogni record contiene l'hash del record precedente. Una manomissione
        successiva (cancellare una sessione scomoda, cambiarne l'orario) rompe
        la catena e viene rilevata da Test-DVSentinelChain.
    #>
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$EventType,
        [Parameter(Mandatory)][hashtable]$Data
    )

    $previousHash = "GENESIS"
    if (Test-Path $LogPath) {
        $lastLine = Get-Content -Path $LogPath -Tail 1 -ErrorAction SilentlyContinue
        if ($lastLine) {
            try {
                $prev = $lastLine | ConvertFrom-Json
                if ($prev.EntryHash) { $previousHash = $prev.EntryHash }
            } catch { }
        }
    }

    $record = [ordered]@{
        Timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff'Z'")
        EventType    = $EventType
        Data         = $Data
        PreviousHash = $previousHash
    }

    $recordJson = $record | ConvertTo-Json -Compress -Depth 6
    $entryHash = Get-DVContentHash -Content ($previousHash + $recordJson)
    $record["EntryHash"] = $entryHash

    Add-Content -Path $LogPath -Value ($record | ConvertTo-Json -Compress -Depth 6) -Encoding UTF8
    return [PSCustomObject]$record
}

function Test-DVSentinelChain {
    <#
    .SYNOPSIS
        Verifica che il registro degli eventi non sia stato alterato dopo la
        scrittura, ricalcolando l'intera catena di hash.
    #>
    param([Parameter(Mandatory)][string]$LogPath)

    if (-not (Test-Path $LogPath)) {
        return [PSCustomObject]@{ Valid = $true; TotalEvents = 0; Message = "Nessun registro Sentinella presente." }
    }

    $lines = @(Get-Content -Path $LogPath -ErrorAction SilentlyContinue)
    $expectedPrevious = "GENESIS"
    $index = 0

    foreach ($line in $lines) {
        $index++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $entry = $line | ConvertFrom-Json }
        catch { return [PSCustomObject]@{ Valid=$false; TotalEvents=$index; Message="Riga $index non e' JSON valido: registro corrotto o manomesso." } }

        if ($entry.PreviousHash -ne $expectedPrevious) {
            return [PSCustomObject]@{ Valid=$false; TotalEvents=$index; Message="Riga ${index}: la catena non corrisponde. Possibile rimozione o riordino di eventi." }
        }

        $recomputeSource = [ordered]@{}
        foreach ($prop in $entry.PSObject.Properties) {
            if ($prop.Name -ne 'EntryHash') { $recomputeSource[$prop.Name] = $prop.Value }
        }
        $recomputed = Get-DVContentHash -Content ($entry.PreviousHash + ($recomputeSource | ConvertTo-Json -Compress -Depth 6))
        if ($recomputed -ne $entry.EntryHash) {
            return [PSCustomObject]@{ Valid=$false; TotalEvents=$index; Message="Riga ${index}: il contenuto e' stato modificato dopo la scrittura." }
        }
        $expectedPrevious = $entry.EntryHash
    }

    return [PSCustomObject]@{ Valid=$true; TotalEvents=$index; Message="Registro integro: $index eventi verificati, nessuna manomissione rilevata." }
}

function Get-DVCurrentRemoteSessions {
    <#
    .SYNOPSIS
        Fotografa le sessioni di controllo remoto attive in questo istante,
        restituendo una tabella indicizzata da una chiave di sessione stabile.
    .DESCRIPTION
        La chiave (IP remoto + porta locale + processo) resta identica finche' la
        sessione e' la stessa: e' cio' che permette di distinguere "sessione
        ancora in corso" da "nuova sessione", evitando di riscrivere lo stesso
        evento a ogni ciclo di campionamento.
    #>
    param(
        [hashtable]$PortsDb = @{},
        [hashtable]$ProcessDb = @{}
    )

    $sessions = @{}
    try {
        $connections = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)
        foreach ($conn in $connections) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($process) { $process.ProcessName } else { "sconosciuto" }

            $isRemoteControl = $false
            $matchedName = $procName
            foreach ($key in $ProcessDb.Keys) {
                if ($ProcessDb[$key].Alert -eq $true -and $procName -like "*$key*") {
                    $isRemoteControl = $true
                    $matchedName = $ProcessDb[$key].Name
                    break
                }
            }
            $portMatch = $PortsDb.ContainsKey([int]$conn.LocalPort)

            if (-not ($isRemoteControl -or $portMatch)) { continue }

            $key = "$($conn.RemoteAddress)|$($conn.LocalPort)|$procName"
            if (-not $sessions.ContainsKey($key)) {
                $sessions[$key] = @{
                    IPRemoto    = $conn.RemoteAddress
                    PortaLocale = $conn.LocalPort
                    PortaRemota = $conn.RemotePort
                    Processo    = $procName
                    Software    = $matchedName
                    PID         = $conn.OwningProcess
                    Servizio    = if ($portMatch) { $PortsDb[[int]$conn.LocalPort].Name } else { "" }
                }
            }
        }
    } catch { }
    return $sessions
}

function Get-DVCurrentMediaUse {
    <#
    .SYNOPSIS
        Rileva se microfono o webcam risultano in uso in questo istante,
        restituendo una tabella con chiave stabile per processo e periferica.
    #>
    $inUse = @{}
    try {
        if (Get-Command Get-DVSurveillanceCapabilities -ErrorAction SilentlyContinue) {
            $sv = Get-DVSurveillanceCapabilities
            foreach ($p in @($sv.Microphone.ActiveProcesses)) {
                $inUse["MIC|$($p.ProcessName)"] = @{ Periferica = "Microfono"; Processo = $p.ProcessName; PID = $p.PID; Sospetto = [bool]$p.Suspicious }
            }
            foreach ($p in @($sv.Webcam.ActiveProcesses)) {
                $inUse["CAM|$($p.ProcessName)"] = @{ Periferica = "Webcam"; Processo = $p.ProcessName; PID = $p.PID; Sospetto = [bool]$p.Suspicious }
            }
        }
    } catch { }
    return $inUse
}

function Start-DVSentinel {
    <#
    .SYNOPSIS
        Avvia il monitoraggio continuo. Registra apertura e chiusura di ogni
        sessione di controllo remoto e di ogni uso di microfono/webcam.
    .PARAMETER ReportDir
        Cartella dove scrivere il registro eventi.
    .PARAMETER IntervalSeconds
        Intervallo di campionamento. Piu' basso = maggiore probabilita' di
        cogliere sessioni brevi, ma maggiore uso di CPU.
    .PARAMETER MaxMinutes
        Durata massima in minuti; 0 = fino all'arresto manuale. E' un valore
        decimale (non intero) per poter impostare anche durate inferiori al
        minuto, indispensabile per i test automatici.
    .PARAMETER IncludeMedia
        Se attivo, sorveglia anche microfono e webcam (piu' lento per ciclo).
    .NOTES
        Per fermarla: creare il file STOP_SENTINELLA.txt nella cartella dei
        report, oppure chiudere la finestra. L'arresto viene registrato.
    #>
    param(
        [Parameter(Mandatory)][string]$ReportDir,
        [int]$IntervalSeconds = 30,
        [double]$MaxMinutes = 0,
        [switch]$IncludeMedia,
        [hashtable]$PortsDb = @{},
        [hashtable]$ProcessDb = @{}
    )

    $logPath = Get-DVSentinelLogPath -ReportDir $ReportDir
    $stopPath = Get-DVSentinelStopPath -ReportDir $ReportDir
    if (Test-Path $stopPath) { Remove-Item $stopPath -Force -ErrorAction SilentlyContinue }

    $startedAt = Get-Date
    Add-DVSentinelEvent -LogPath $logPath -EventType "AVVIO_SENTINELLA" -Data @{
        ComputerName    = $env:COMPUTERNAME
        UserName        = $env:USERNAME
        IntervalSeconds = $IntervalSeconds
        IncludeMedia    = [bool]$IncludeMedia
        Versione        = if ($Global:DVConfig) { $Global:DVConfig.Version } else { "n/d" }
    } | Out-Null

    Write-Host ""
    Write-Host "  SENTINELLA ATTIVA - registra gli eventi mentre accadono." -ForegroundColor Green
    Write-Host "  Registro: $logPath"
    Write-Host "  Controllo ogni $IntervalSeconds secondi. Lascia questa finestra aperta." -ForegroundColor DarkGray
    Write-Host "  Per fermare: chiudi la finestra oppure premi CTRL+C." -ForegroundColor DarkGray
    Write-Host ""

    $activeSessions = @{}
    $activeMedia = @{}
    $cycles = 0
    $eventsLogged = 0
    $stopReason = "arresto manuale"

    try {
        while ($true) {
            $cycles++

            if (Test-Path $stopPath) { $stopReason = "richiesta di arresto (file STOP)"; break }
            if ($MaxMinutes -gt 0 -and ((Get-Date) - $startedAt).TotalMinutes -ge $MaxMinutes) {
                $stopReason = "durata massima raggiunta"; break
            }

            # --- Sessioni di controllo remoto ---
            $current = Get-DVCurrentRemoteSessions -PortsDb $PortsDb -ProcessDb $ProcessDb

            foreach ($key in $current.Keys) {
                if (-not $activeSessions.ContainsKey($key)) {
                    $info = $current[$key]
                    $activeSessions[$key] = @{ Start = Get-Date; Info = $info }
                    Add-DVSentinelEvent -LogPath $logPath -EventType "SESSIONE_REMOTA_APERTA" -Data @{
                        IPRemoto    = $info.IPRemoto
                        PortaLocale = $info.PortaLocale
                        PortaRemota = $info.PortaRemota
                        Processo    = $info.Processo
                        Software    = $info.Software
                        PID         = $info.PID
                        Servizio    = $info.Servizio
                    } | Out-Null
                    $eventsLogged++
                    Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] SESSIONE REMOTA APERTA: $($info.IPRemoto) -> $($info.Software) (porta $($info.PortaLocale))" -ForegroundColor Red
                }
            }

            foreach ($key in @($activeSessions.Keys)) {
                if (-not $current.ContainsKey($key)) {
                    $s = $activeSessions[$key]
                    $durata = [math]::Round(((Get-Date) - $s.Start).TotalSeconds)
                    Add-DVSentinelEvent -LogPath $logPath -EventType "SESSIONE_REMOTA_CHIUSA" -Data @{
                        IPRemoto       = $s.Info.IPRemoto
                        PortaLocale    = $s.Info.PortaLocale
                        Processo       = $s.Info.Processo
                        Software       = $s.Info.Software
                        InizioSessione = $s.Start.ToString("yyyy-MM-dd HH:mm:ss")
                        DurataSecondi  = $durata
                    } | Out-Null
                    $eventsLogged++
                    Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] Sessione chiusa: $($s.Info.IPRemoto) - durata $durata s" -ForegroundColor Yellow
                    $activeSessions.Remove($key)
                }
            }

            # --- Microfono e webcam (opzionale) ---
            if ($IncludeMedia) {
                $media = Get-DVCurrentMediaUse
                foreach ($key in $media.Keys) {
                    if (-not $activeMedia.ContainsKey($key)) {
                        $m = $media[$key]
                        $activeMedia[$key] = @{ Start = Get-Date; Info = $m }
                        Add-DVSentinelEvent -LogPath $logPath -EventType "PERIFERICA_ATTIVATA" -Data $m | Out-Null
                        $eventsLogged++
                        $col = if ($m.Sospetto) { "Red" } else { "DarkGray" }
                        Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] $($m.Periferica) attivo: $($m.Processo)" -ForegroundColor $col
                    }
                }
                foreach ($key in @($activeMedia.Keys)) {
                    if (-not $media.ContainsKey($key)) {
                        $m = $activeMedia[$key]
                        $durata = [math]::Round(((Get-Date) - $m.Start).TotalSeconds)
                        Add-DVSentinelEvent -LogPath $logPath -EventType "PERIFERICA_DISATTIVATA" -Data @{
                            Periferica    = $m.Info.Periferica
                            Processo      = $m.Info.Processo
                            InizioUso     = $m.Start.ToString("yyyy-MM-dd HH:mm:ss")
                            DurataSecondi = $durata
                        } | Out-Null
                        $eventsLogged++
                        $activeMedia.Remove($key)
                    }
                }
            }

            # Attesa "a scatti" di un secondo invece di un unico Start-Sleep lungo:
            # cosi' una richiesta di arresto viene raccolta entro un secondo,
            # anziche' costringere ad attendere l'intero intervallo.
            for ($w = 0; $w -lt $IntervalSeconds; $w++) {
                if (Test-Path $stopPath) { break }
                if ($MaxMinutes -gt 0 -and ((Get-Date) - $startedAt).TotalMinutes -ge $MaxMinutes) { break }
                Start-Sleep -Seconds 1
            }
        }
    } catch {
        $stopReason = "interruzione: $($_.Exception.Message)"
    } finally {
        # Chiude ordinatamente le sessioni ancora aperte, per non lasciare
        # nel registro eventi di apertura senza la corrispondente chiusura.
        foreach ($key in @($activeSessions.Keys)) {
            $s = $activeSessions[$key]
            $durata = [math]::Round(((Get-Date) - $s.Start).TotalSeconds)
            Add-DVSentinelEvent -LogPath $logPath -EventType "SESSIONE_REMOTA_CHIUSA" -Data @{
                IPRemoto       = $s.Info.IPRemoto
                PortaLocale    = $s.Info.PortaLocale
                Processo       = $s.Info.Processo
                Software       = $s.Info.Software
                InizioSessione = $s.Start.ToString("yyyy-MM-dd HH:mm:ss")
                DurataSecondi  = $durata
                Nota           = "sessione ancora aperta all'arresto della Sentinella"
            } | Out-Null
        }

        $durataTot = [math]::Round(((Get-Date) - $startedAt).TotalMinutes, 1)
        Add-DVSentinelEvent -LogPath $logPath -EventType "ARRESTO_SENTINELLA" -Data @{
            DurataMinuti   = $durataTot
            CicliEseguiti  = $cycles
            EventiRegistrati = $eventsLogged
            Motivo         = $stopReason
        } | Out-Null

        if (Test-Path $stopPath) { Remove-Item $stopPath -Force -ErrorAction SilentlyContinue }

        Write-Host ""
        Write-Host "  Sentinella arrestata ($stopReason)." -ForegroundColor Cyan
        Write-Host "  Durata: $durataTot minuti | Eventi registrati: $eventsLogged"
        Write-Host "  Registro: $logPath"
        Write-Host ""
    }

    return @{ DurataMinuti = $durataTot; Eventi = $eventsLogged; LogPath = $logPath }
}

function Get-DVSentinelSummary {
    <#
    .SYNOPSIS
        Riassume il registro della Sentinella: periodi di sorveglianza, sessioni
        remote osservate con durata, uso di microfono e webcam.
    .DESCRIPTION
        E' la funzione che trasforma il registro grezzo in qualcosa di leggibile
        da una persona non tecnica e allegabile a una richiesta al DPO.
    #>
    param([Parameter(Mandatory)][string]$LogPath)

    $summary = @{
        Presente          = $false
        TotaleEventi      = 0
        PeriodiSorveglianza = @()
        SessioniRemote    = @()
        UsiPeriferiche    = @()
        MinutiSorvegliati = 0
        ChainValid        = $true
        ChainMessage      = ""
    }

    if (-not (Test-Path $LogPath)) { return $summary }
    $summary.Presente = $true

    $chain = Test-DVSentinelChain -LogPath $LogPath
    $summary.ChainValid = $chain.Valid
    $summary.ChainMessage = $chain.Message

    $lines = @(Get-Content -Path $LogPath -ErrorAction SilentlyContinue)
    $currentStart = $null

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $e = $line | ConvertFrom-Json } catch { continue }
        $summary.TotaleEventi++

        switch ($e.EventType) {
            "AVVIO_SENTINELLA" { $currentStart = $e.Timestamp }
            "ARRESTO_SENTINELLA" {
                $summary.PeriodiSorveglianza += [PSCustomObject]@{
                    Inizio = $currentStart
                    Fine   = $e.Timestamp
                    Minuti = $e.Data.DurataMinuti
                }
                $summary.MinutiSorvegliati += [double]$e.Data.DurataMinuti
                $currentStart = $null
            }
            "SESSIONE_REMOTA_CHIUSA" {
                $summary.SessioniRemote += [PSCustomObject]@{
                    Inizio        = $e.Data.InizioSessione
                    Fine          = $e.Timestamp
                    DurataSecondi = $e.Data.DurataSecondi
                    IPRemoto      = $e.Data.IPRemoto
                    Software      = $e.Data.Software
                    PortaLocale   = $e.Data.PortaLocale
                    Nota          = $e.Data.Nota
                }
            }
            "PERIFERICA_DISATTIVATA" {
                $summary.UsiPeriferiche += [PSCustomObject]@{
                    Periferica    = $e.Data.Periferica
                    Processo      = $e.Data.Processo
                    Inizio        = $e.Data.InizioUso
                    Fine          = $e.Timestamp
                    DurataSecondi = $e.Data.DurataSecondi
                }
            }
        }
    }

    # Periodo di sorveglianza ancora in corso (Sentinella attiva in questo momento)
    if ($currentStart) {
        $summary.PeriodiSorveglianza += [PSCustomObject]@{ Inizio = $currentStart; Fine = "(in corso)"; Minuti = $null }
    }

    return $summary
}

Export-ModuleMember -Function Get-DVSentinelLogPath, Get-DVSentinelStopPath, Add-DVSentinelEvent, `
    Test-DVSentinelChain, Get-DVCurrentRemoteSessions, Get-DVCurrentMediaUse, `
    Start-DVSentinel, Get-DVSentinelSummary
