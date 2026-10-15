# DigitalValut Controller - UltraVncLogAnalyzer Module
# Copyright 2024-2026 Digital Valut APS - www.digitalvalut.it
# Sviluppatore: Dott. Giuseppe Falsone e il team DigitalValut
#
# Questo file e' parte di DigitalValut Controller.
# Licenza Apache, Versione 2.0 (la "Licenza"): puoi usare questo file solo nel
# rispetto della Licenza, di cui trovi copia nel file LICENSE e su
# http://www.apache.org/licenses/LICENSE-2.0
# Salvo diversa disposizione di legge o accordo scritto, il software e' distribuito
# "COSI' COM'E'", SENZA GARANZIE O CONDIZIONI DI ALCUN TIPO, esplicite o implicite.
# Avvertenze e limiti: DISCLAIMER.md
# SPDX-License-Identifier: Apache-2.0
#
# Legge, in SOLA LETTURA, il registro locale di UltraVNC per ricostruire le connessioni
# avvenute in passato. E' l'unico dato che mostra l'USO effettivo dello strumento (la
# presenza di un software installato mostra soltanto che l'accesso e' POSSIBILE).
#
# Fonti dei formati riconosciuti (verificate, non dedotte):
#   - Sorgente di UltraVNC, winvnc/vncsockconnect.cpp: la riga
#       "accepted connection from <indirizzo>"   (livello LL_CLIENTS)
#     viene scritta quando il server accetta una connessione.
#   - Registro mslogon.log, descritto dall'autore di UltraVNC (forum ufficiale):
#       "Connection received from <indirizzo>"
#       "Invalid attempt from client <indirizzo>"
#       "Client <indirizzo> disconnected"
#     lo stesso autore indica che gli stessi eventi compaiono anche nel Visualizzatore
#     eventi di Windows.
#
# Non e' stato possibile verificare: il formato esatto dell'ora scritta in testa alle
# righe, e il nome del provider nel Visualizzatore eventi. Per questo l'ora viene
# riportata COME SCRITTA nel file e interpretata solo quando non e' ambigua, e la
# ricerca nel Visualizzatore eventi usa un criterio largo (provider contenente "vnc").
#
# Tutela dei terzi: dalle righe si estraggono SOLO ora, tipo di evento e indirizzo di
# origine. La riga non viene mai conservata: potrebbe contenere nomi utente.

function Test-DVLoopbackAddress {
    <#
    .SYNOPSIS
        Indica se un indirizzo e' di loopback (connessione dal PC stesso).
    #>
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $a = $Address.Trim().ToLower()
    if ($a -match '^127\.') { return $true }
    if ($a -eq '::1' -or $a -eq 'localhost') { return $true }
    return $false
}

function ConvertTo-DVLogAddress {
    <#
    .SYNOPSIS
        Normalizza l'indirizzo letto da una riga di log.
    .DESCRIPTION
        Toglie punteggiatura finale, parentesi e porta (IPv4:porta), e riduce un
        indirizzo IPv4 incapsulato in IPv6 (::ffff:a.b.c.d) all'IPv4. Se il valore non
        e' un indirizzo IP (potrebbe essere un nome host) lo riporta ripulito dai
        caratteri non ammessi: non si inventa un indirizzo.
    #>
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return '' }
    $a = $Raw.Trim().Trim('[', ']', '(', ')', ',', ';', '.', '"', "'")
    if ($a -match '^(?i)::ffff:(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$') { return $Matches[1] }
    if ($a -match '^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$') { return $Matches[1] }
    $a = ($a -replace '[^A-Za-z0-9\.\-_:]', '')
    if ($a.Length -gt 100) { $a = $a.Substring(0, 100) }
    return $a
}

function ConvertFrom-DVLogTimestamp {
    <#
    .SYNOPSIS
        Estrae l'ora scritta in testa a una riga e la interpreta solo se non ambigua.
    .DESCRIPTION
        Il formato dipende dalle impostazioni regionali del PC: 05/06/2026 puo' essere il
        5 giugno o il 6 maggio. Interpretare a caso produrrebbe una data falsa in un
        documento destinato a terzi. Il testo originale e' sempre restituito; la data
        interpretata solo quando il formato la determina con certezza (anno per primo,
        oppure un campo maggiore di 12 che indica quale e' il giorno).
    .OUTPUTS
        Hashtable: Text (come scritto, o ''), Time ([datetime] o $null), Ambiguous.
    #>
    param([string]$Line)
    $r = @{ Text = ''; Time = $null; Ambiguous = $false }
    if ([string]::IsNullOrEmpty($Line)) { return $r }
    $m = [regex]::Match($Line, '^\s*\[?(?<d1>\d{1,4})[/\-.](?<d2>\d{1,2})[/\-.](?<d3>\d{1,4})[ T,]+(?<h>\d{1,2}):(?<mi>\d{2})(?::(?<s>\d{2}))?')
    if (-not $m.Success) { return $r }
    $r.Text = $m.Value.Trim().TrimStart('[')
    $d1 = [int]$m.Groups['d1'].Value; $d2 = [int]$m.Groups['d2'].Value; $d3 = [int]$m.Groups['d3'].Value
    $h = [int]$m.Groups['h'].Value; $mi = [int]$m.Groups['mi'].Value
    $s = if ($m.Groups['s'].Success) { [int]$m.Groups['s'].Value } else { 0 }
    $year = 0; $month = 0; $day = 0
    if ($m.Groups['d1'].Value.Length -eq 4) {
        $year = $d1; $month = $d2; $day = $d3                      # anno per primo: yyyy-MM-dd
    } elseif ($m.Groups['d3'].Value.Length -eq 4) {
        $year = $d3
        if ($d1 -gt 12 -and $d2 -le 12) { $day = $d1; $month = $d2 }       # dd/MM/yyyy
        elseif ($d2 -gt 12 -and $d1 -le 12) { $month = $d1; $day = $d2 }   # MM/dd/yyyy
        else { $r.Ambiguous = $true; return $r }
    } else {
        $r.Ambiguous = $true; return $r
    }
    try { $r.Time = New-Object DateTime($year, $month, $day, $h, $mi, $s) } catch { $r.Time = $null; $r.Ambiguous = $true }
    return $r
}

function ConvertFrom-DVVncLogLine {
    <#
    .SYNOPSIS
        Riconosce una riga di connessione nel registro di UltraVNC.
    .OUTPUTS
        $null se la riga non e' un evento di connessione noto; altrimenti un oggetto con
        Kind, Address, IsLocal, TimeText, Time, TimeAmbiguous. La riga NON viene conservata.
    #>
    param([string]$Line)
    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }
    $patterns = @(
        @{ Kind = 'Connessione accettata';               Rx = '(?i)accepted connection from\s+(?<ip>\S+)' }
        @{ Kind = 'Connessione ricevuta';                Rx = '(?i)connection received from\s+(?<ip>\S+)' }
        @{ Kind = 'Tentativo di accesso non valido';     Rx = '(?i)invalid attempt from client\s+(?<ip>\S+)' }
        @{ Kind = 'Disconnessione';                      Rx = '(?i)\bclient\s+(?<ip>\S+)\s+disconnected' }
    )
    foreach ($p in $patterns) {
        $m = [regex]::Match($Line, $p.Rx)
        if (-not $m.Success) { continue }
        $addr = ConvertTo-DVLogAddress -Raw $m.Groups['ip'].Value
        if (-not $addr) { return $null }
        $ts = ConvertFrom-DVLogTimestamp -Line $Line
        return [PSCustomObject]@{
            Kind          = $p.Kind
            Address       = $addr
            IsLocal       = (Test-DVLoopbackAddress -Address $addr)
            TimeText      = [string]$ts.Text
            Time          = $ts.Time
            TimeAmbiguous = [bool]$ts.Ambiguous
        }
    }
    return $null
}

function Read-DVLogFileTail {
    <#
    .SYNOPSIS
        Legge un file di log in sola lettura, senza bloccarlo, limitando i byte letti.
    .DESCRIPTION
        Il file e' aperto con condivisione in lettura/scrittura: il servizio che lo sta
        scrivendo non viene disturbato. Se il file supera il limite si legge la sola
        coda (le righe piu' recenti) e lo si dichiara. L'impronta SHA-256 e' calcolata
        sui byte effettivamente letti, cosi' un terzo puo' verificare di avere letto lo
        stesso contenuto. Il file non viene mai modificato.
    #>
    param([string]$Path, [int64]$MaxBytes = 8388608)

    $res = @{
        Readable = $false; Error = ''; SizeBytes = [int64]0; LastWrite = $null
        BytesRead = [int64]0; Truncated = $false; Sha256 = ''; Lines = @()
    }
    $fs = $null
    try {
        $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        $len = $fs.Length
        $res.SizeBytes = $len
        try { $res.LastWrite = (Get-Item -LiteralPath $Path -ErrorAction Stop).LastWriteTime } catch { $res.LastWrite = $null }
        $toRead = $len
        if ($len -gt $MaxBytes) {
            [void]$fs.Seek(-$MaxBytes, [System.IO.SeekOrigin]::End)
            $toRead = $MaxBytes
            $res.Truncated = $true
        }
        $buf = New-Object byte[] ([int]$toRead)
        $got = 0
        while ($got -lt $toRead) {
            $n = $fs.Read($buf, $got, [int]($toRead - $got))
            if ($n -le 0) { break }
            $got += $n
        }
        $res.BytesRead = [int64]$got
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha.ComputeHash($buf, 0, $got)
            $res.Sha256 = (($hashBytes | ForEach-Object { $_.ToString('x2') }) -join '')
        } finally { $sha.Dispose() }
        # ISO-8859-1: ogni byte e' un carattere valido, nessun errore di decodifica; gli
        # indirizzi e le parole chiave sono ASCII.
        $text = [System.Text.Encoding]::GetEncoding(28591).GetString($buf, 0, $got)
        $lines = @($text -split "\r?\n")
        if ($res.Truncated -and $lines.Count -gt 0) { $lines = @($lines | Select-Object -Skip 1) }  # prima riga probabilmente spezzata
        $res.Lines = $lines
        $res.Readable = $true
    } catch {
        $res.Error = [string]$_.Exception.Message
    } finally {
        if ($fs) { $fs.Dispose() }
    }
    return $res
}

function Get-DVUltraVncLogCandidatePaths {
    <#
    .SYNOPSIS
        Percorsi in cui cercare i registri di UltraVNC.
    #>
    param([object]$UltraVncConfig = $null, [string[]]$ExtraPaths = @())
    $paths = New-Object System.Collections.Generic.List[string]
    $add = { param($p) if ($p -and -not ($paths | Where-Object { $_ -ieq [string]$p })) { [void]$paths.Add([string]$p) } }

    if ($UltraVncConfig) {
        if ($UltraVncConfig.LogFile) { & $add ([string]$UltraVncConfig.LogFile) }
        if ($UltraVncConfig.ConfigPath) {
            $dir = Split-Path -Parent ([string]$UltraVncConfig.ConfigPath)
            if ($dir) {
                & $add (Join-Path $dir 'winvnc.log')
                & $add (Join-Path $dir 'mslogon.log')
            }
        }
    }
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $base) { continue }
        foreach ($sub in 'uvnc bvba\UltraVNC', 'UltraVNC', 'uvnc bvba\UltraVnc') {
            & $add (Join-Path $base (Join-Path $sub 'winvnc.log'))
            & $add (Join-Path $base (Join-Path $sub 'mslogon.log'))
        }
    }
    foreach ($e in $ExtraPaths) { & $add $e }
    return @($paths)
}

function Get-DVUltraVncEventLogEvents {
    <#
    .SYNOPSIS
        Cerca nel registro Applicazione di Windows gli eventi scritti da UltraVNC.
    .DESCRIPTION
        Il registro Applicazione, a differenza del registro di Sicurezza, e' di norma
        leggibile da un utente standard. Il criterio di ricerca e' largo (provider il cui
        nome contiene "vnc") perche' il nome esatto del provider non e' stato verificato.
        L'ora degli eventi e' quella registrata da Windows, quindi non ambigua.
    #>
    param([int]$DaysBack = 30, [int]$MaxEvents = 5000)

    $out = @{ Readable = $false; Error = ''; ProviderEvents = 0; Events = @() }
    $since = (Get-Date).AddDays(-$DaysBack)
    $raw = @()
    try {
        $raw = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction Stop)
        $out.Readable = $true
    } catch {
        $msg = [string]$_.Exception.Message
        if ($msg -match 'No events were found|Nessun evento') { $out.Readable = $true } else { $out.Error = $msg; return $out }
    }
    $mine = @($raw | Where-Object { [string]$_.ProviderName -match '(?i)vnc' })
    $out.ProviderEvents = $mine.Count
    $events = @()
    foreach ($ev in $mine) {
        $msg = ''
        try { $msg = [string]$ev.Message } catch { $msg = '' }
        foreach ($line in ($msg -split "\r?\n")) {
            $parsed = ConvertFrom-DVVncLogLine -Line $line
            if (-not $parsed) { continue }
            $events += [PSCustomObject]@{
                Source        = "Registro eventi di Windows (Applicazione), provider $([string]$ev.ProviderName)"
                Kind          = $parsed.Kind
                Address       = $parsed.Address
                IsLocal       = $parsed.IsLocal
                TimeText      = ([datetime]$ev.TimeCreated).ToString('yyyy-MM-dd HH:mm:ss')
                Time          = [datetime]$ev.TimeCreated
                TimeAmbiguous = $false
            }
        }
    }
    $out.Events = $events
    return $out
}

function Get-DVUltraVncLogFindings {
    <#
    .SYNOPSIS
        Ricostruisce le connessioni passate a UltraVNC dai suoi registri (sola lettura).
    .OUTPUTS
        Hashtable: Files, Events, EventLog, RemoteConnectionCount, FailedAttemptCount,
        DistinctRemoteAddresses, FirstSeenText, LastSeenText, AnyFileRead.
    .NOTES
        Il conteggio delle connessioni e' il MASSIMO tra le fonti, non la somma: lo stesso
        accesso puo' comparire sia in winvnc.log sia in mslogon.log sia nel registro eventi,
        e sommarli conterebbe due volte lo stesso fatto.
    #>
    param(
        [object]$UltraVncConfig = $null,
        [string[]]$ExtraPaths = @(),
        [int64]$MaxBytes = 8388608,
        [int]$EventLogDays = 30,
        [switch]$SkipEventLog,
        [int]$MaxEventsKept = 500
    )

    $files = @()
    $events = New-Object System.Collections.Generic.List[object]

    foreach ($path in (Get-DVUltraVncLogCandidatePaths -UltraVncConfig $UltraVncConfig -ExtraPaths $ExtraPaths)) {
        $exists = $false
        try { $exists = Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop } catch { $exists = $false }
        $rec = [ordered]@{
            Path = $path; Exists = $exists; Readable = $false; Error = ''
            SizeBytes = [int64]0; LastWrite = $null; BytesRead = [int64]0
            Truncated = $false; Sha256 = ''; ConnectionLines = 0
        }
        if ($exists) {
            $read = Read-DVLogFileTail -Path $path -MaxBytes $MaxBytes
            $rec.Readable = [bool]$read.Readable
            $rec.Error = [string]$read.Error
            $rec.SizeBytes = [int64]$read.SizeBytes
            $rec.LastWrite = $read.LastWrite
            $rec.BytesRead = [int64]$read.BytesRead
            $rec.Truncated = [bool]$read.Truncated
            $rec.Sha256 = [string]$read.Sha256
            $n = 0
            foreach ($line in @($read.Lines)) {
                $p = ConvertFrom-DVVncLogLine -Line ([string]$line)
                if (-not $p) { continue }
                $n++
                [void]$events.Add([PSCustomObject]@{
                    Source = $path; Kind = $p.Kind; Address = $p.Address; IsLocal = $p.IsLocal
                    TimeText = $p.TimeText; Time = $p.Time; TimeAmbiguous = $p.TimeAmbiguous
                })
            }
            $rec.ConnectionLines = $n
        }
        $files += [PSCustomObject]$rec
    }

    $eventLog = $null
    if (-not $SkipEventLog) {
        try { $eventLog = Get-DVUltraVncEventLogEvents -DaysBack $EventLogDays } catch { $eventLog = @{ Readable = $false; Error = $_.Exception.Message; ProviderEvents = 0; Events = @() } }
        foreach ($e in @($eventLog.Events)) { [void]$events.Add($e) }
    }

    # Conteggio per fonte: poi si prende il massimo (non la somma).
    $isConn = { param($e) $e.Kind -in @('Connessione accettata', 'Connessione ricevuta') -and -not $e.IsLocal }
    $bySource = @{}
    foreach ($e in $events) {
        if (& $isConn $e) {
            if (-not $bySource.ContainsKey($e.Source)) { $bySource[$e.Source] = 0 }
            $bySource[$e.Source]++
        }
    }
    $remoteCount = 0
    foreach ($k in $bySource.Keys) { if ($bySource[$k] -gt $remoteCount) { $remoteCount = $bySource[$k] } }

    # Sessioni: nel registro mslogon.log una sola connessione genera piu' righe
    # ("Connection received from" ripetuta). Contare le righe moltiplicherebbe i fatti.
    # Una sessione = righe consecutive dello stesso indirizzo, senza una disconnessione
    # in mezzo e a meno di 5 minuti l'una dall'altra (o con la stessa ora scritta, se la
    # data non e' interpretabile).
    $sessBySource = @{}
    $evBySrc = @{}
    foreach ($e in $events) { if (-not $evBySrc.ContainsKey($e.Source)) { $evBySrc[$e.Source] = New-Object System.Collections.Generic.List[object] }; [void]$evBySrc[$e.Source].Add($e) }
    foreach ($src in $evBySrc.Keys) {
        $n = 0; $prevAddr = $null; $prevTime = $null; $prevText = $null; $open = $false
        foreach ($e in $evBySrc[$src]) {
            if ($e.IsLocal) { continue }
            if ($e.Kind -eq 'Disconnessione') { $open = $false; continue }
            if (-not (& $isConn $e)) { continue }
            $txt = if ($e.TimeText) { ([string]$e.TimeText -replace ':\d{2}$', '') } else { '' }
            $same = $open -and ($e.Address -eq $prevAddr)
            if ($same) {
                if ($e.Time -and $prevTime) { $same = ([math]::Abs(($e.Time - $prevTime).TotalMinutes) -le 5) }
                elseif ($txt -or $prevText) { $same = ($txt -eq $prevText) }
            }
            if (-not $same) { $n++ }
            $open = $true; $prevAddr = $e.Address; $prevTime = $e.Time; $prevText = $txt
        }
        $sessBySource[$src] = $n
    }
    $sessionCount = 0
    foreach ($k in $sessBySource.Keys) { if ($sessBySource[$k] -gt $sessionCount) { $sessionCount = $sessBySource[$k] } }

    $failedBySource = @{}
    foreach ($e in $events) {
        if ($e.Kind -eq 'Tentativo di accesso non valido' -and -not $e.IsLocal) {
            if (-not $failedBySource.ContainsKey($e.Source)) { $failedBySource[$e.Source] = 0 }
            $failedBySource[$e.Source]++
        }
    }
    $failedCount = 0
    foreach ($k in $failedBySource.Keys) { if ($failedBySource[$k] -gt $failedCount) { $failedCount = $failedBySource[$k] } }

    $addresses = @($events | Where-Object { -not $_.IsLocal -and $_.Kind -ne 'Disconnessione' } | ForEach-Object { $_.Address } | Where-Object { $_ } | Select-Object -Unique)

    # Prima e ultima data: solo da ore non ambigue o dal registro eventi di Windows.
    $dated = @($events | Where-Object { -not $_.IsLocal -and $_.Time -and (& $isConn $_) } | Sort-Object Time)
    $first = ''; $last = ''
    if ($dated.Count -gt 0) {
        $first = $dated[0].Time.ToString('yyyy-MM-dd HH:mm:ss')
        $last = $dated[$dated.Count - 1].Time.ToString('yyyy-MM-dd HH:mm:ss')
    }

    $kept = @($events | Select-Object -Last $MaxEventsKept)

    return @{
        Files                   = $files
        Events                  = $kept
        EventLog                = $eventLog
        RemoteConnectionCount   = [int]$remoteCount
        RemoteSessionCount      = [int]$sessionCount
        FailedAttemptCount      = [int]$failedCount
        DistinctRemoteAddresses = @($addresses)
        FirstSeenText           = $first
        LastSeenText            = $last
        AnyFileRead             = (@($files | Where-Object { $_.Readable }).Count -gt 0)
        AnyFileFound            = (@($files | Where-Object { $_.Exists }).Count -gt 0)
    }
}

Export-ModuleMember -Function Test-DVLoopbackAddress, ConvertTo-DVLogAddress, ConvertFrom-DVLogTimestamp, `
    ConvertFrom-DVVncLogLine, Read-DVLogFileTail, Get-DVUltraVncLogCandidatePaths, `
    Get-DVUltraVncEventLogEvents, Get-DVUltraVncLogFindings
