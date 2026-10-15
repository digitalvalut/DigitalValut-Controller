# DigitalValut Controller v5.0 - EventLogAnalyzer Module
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
# ANALISI STORICA DEI REGISTRI EVENTI DI WINDOWS
#
# Tutti gli altri controlli dello strumento fotografano il presente: cosa e'
# attivo ADESSO. Un software di controllo puo' pero' essere stato installato,
# usato e poi disinstallato. Questo modulo guarda indietro nel tempo leggendo i
# registri eventi di Windows, per rispondere a "cosa e' successo su questo PC".
#
# Eventi analizzati:
# - 7045 (System)   : installazione di un nuovo servizio di sistema
# - 1102 (Security) : cancellazione del registro di sicurezza (potenziale
#                     occultamento di tracce) - richiede privilegi
# - 4624 tipo 10    : accesso interattivo remoto riuscito (RDP) - richiede privilegi
#
# LIMITI DICHIARATI (vedi DISCLAIMER.md):
# - Il registro Security richiede privilegi di amministratore: senza, quella
#   parte viene semplicemente saltata e il report lo dichiara apertamente.
#   L'assenza di riscontri NON significa che non sia successo nulla.
# - I registri eventi hanno dimensione limitata e ruotano: eventi piu' vecchi
#   possono essere gia' stati sovrascritti, del tutto legittimamente.
# - L'installazione di un servizio e' un'operazione normalissima: driver,
#   aggiornamenti e software aziendale ne installano di continuo. La presenza
#   in elenco NON e' di per se' indice di un problema.

function Test-DVCanReadSecurityLog {
    <#
    .SYNOPSIS
        Verifica se il registro Security e' leggibile (di norma richiede privilegi
        amministrativi). Non solleva eccezioni.
    #>
    try {
        Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Get-DVServiceInstallEvents {
    <#
    .SYNOPSIS
        Elenca i servizi installati di recente (evento 7045 nel registro System),
        segnalando quelli il cui nome o percorso corrisponde a software di
        controllo remoto noto.
    #>
    param(
        [int]$DaysBack = 30,
        [hashtable]$ProcessDb = @{}
    )

    $results = @()
    try {
        $since = (Get-Date).AddDays(-$DaysBack)
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since } -ErrorAction Stop)
    } catch {
        # Nessun evento nel periodo, o registro non accessibile: caso normale.
        return $results
    }

    foreach ($ev in $events) {
        $serviceName = ""
        $imagePath = ""
        try {
            $xml = [xml]$ev.ToXml()
            foreach ($d in $xml.Event.EventData.Data) {
                switch ($d.Name) {
                    'ServiceName' { $serviceName = $d.'#text' }
                    'ImagePath'   { $imagePath = $d.'#text' }
                }
            }
        } catch { continue }

        $haystack = ("$serviceName $imagePath").ToLower()
        $matchedName = $null
        foreach ($key in $ProcessDb.Keys) {
            if ($ProcessDb[$key].Alert -eq $true -and $haystack.Contains($key.ToString().ToLower())) {
                $matchedName = $ProcessDb[$key].Name
                break
            }
        }

        $results += [PSCustomObject]@{
            TimeCreated = $ev.TimeCreated
            ServiceName = $serviceName
            ImagePath   = $imagePath
            MatchedTool = $matchedName
            Risk        = if ($matchedName) { "HIGH" } else { "INFO" }
        }
    }

    return $results
}

function Get-DVSecurityLogClearedEvents {
    <#
    .SYNOPSIS
        Rileva cancellazioni del registro di sicurezza (evento 1102): operazione
        legittima per un amministratore, ma anche tecnica per occultare tracce.
        Richiede privilegi amministrativi.
    #>
    param([int]$DaysBack = 90)

    $results = @()
    try {
        $since = (Get-Date).AddDays(-$DaysBack)
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102; StartTime = $since } -ErrorAction Stop)
    } catch {
        return $results
    }

    foreach ($ev in $events) {
        $results += [PSCustomObject]@{
            TimeCreated = $ev.TimeCreated
            Message     = "Registro di sicurezza cancellato"
            Risk        = "HIGH"
        }
    }
    return $results
}

function Get-DVRemoteLogonEvents {
    <#
    .SYNOPSIS
        Elenca gli accessi remoti interattivi riusciti (evento 4624, LogonType 10:
        tipicamente RDP). Richiede privilegi amministrativi.
    #>
    param(
        [int]$DaysBack = 30,
        [int]$MaxEvents = 200
    )

    $results = @()
    try {
        $since = (Get-Date).AddDays(-$DaysBack)
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction Stop)
    } catch {
        return $results
    }

    foreach ($ev in $events) {
        try {
            $xml = [xml]$ev.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            if ($data['LogonType'] -ne '10') { continue }
            $results += [PSCustomObject]@{
                TimeCreated = $ev.TimeCreated
                Account     = "$($data['TargetDomainName'])\$($data['TargetUserName'])"
                SourceIP    = $data['IpAddress']
                Risk        = "MEDIUM"
            }
        } catch { continue }
    }
    return $results
}

function Test-DVLocalSessionAddress {
    <#
    .SYNOPSIS
        Indica se l'indirizzo di origine di una sessione corrisponde alla console locale.
    .DESCRIPTION
        Nei registri dei Servizi Desktop remoto il campo indirizzo vale "LOCAL" (o la
        sua traduzione, es. "LOCALE") per gli accessi effettuati sulla console fisica
        del PC, e un indirizzo IP per gli accessi remoti. Un campo vuoto non permette
        di stabilire l'origine: in quel caso NON si considera locale, per non
        nascondere un possibile accesso remoto.
    #>
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $a = $Address.Trim()
    if ($a -match '^(?i)(LOCAL|LOCALE|LOCALHOST|LOKAL|LOCAL\s*SESSION)$') { return $true }
    if ($a -match '^127\.') { return $true }
    if ($a -eq '::1') { return $true }
    return $false
}

function Get-DVRdpOperationalEvents {
    <#
    .SYNOPSIS
        Ricostruisce la cronologia degli accessi RDP dai registri operativi dei
        Servizi Desktop remoto, che in molte configurazioni sono leggibili anche
        SENZA privilegi di amministratore.
    .DESCRIPTION
        Il registro Security (evento 4624) richiede privilegi elevati, che un
        dipendente normalmente non ha sulla postazione assegnata. Questi due
        registri operativi contengono però lo stesso dato essenziale - chi si e'
        collegato, quando e da quale indirizzo - e sono spesso accessibili:

          Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
            1149  autenticazione utente riuscita (Param1 utente, Param2 dominio,
                  Param3 indirizzo di origine)

          Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
            21    accesso alla sessione riuscito (User, SessionID, Address)
            24    sessione disconnessa
            25    riconnessione alla sessione riuscita

        Per un lavoratore senza privilegi questa e' spesso l'unica strada per
        sapere se qualcuno si e' effettivamente collegato in passato. Se nemmeno
        questi registri sono leggibili, il risultato lo dichiara: il dato esiste
        ma e' nella disponibilita' esclusiva del titolare del trattamento, che
        puo' essere chiamato a produrlo.
    .OUTPUTS
        Hashtable con Readable, Events, ChannelsRead, ChannelsDenied.
    #>
    param(
        [int]$DaysBack = 30,
        [int]$MaxEvents = 200
    )

    $since = (Get-Date).AddDays(-$DaysBack)
    $events = @()
    $read = @()
    $denied = @()

    $channels = @(
        @{ Name = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids = @(1149) }
        @{ Name = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';      Ids = @(21, 24, 25) }
    )

    foreach ($ch in $channels) {
        $raw = @()
        try {
            $raw = @(Get-WinEvent -FilterHashtable @{ LogName = $ch.Name; Id = $ch.Ids; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction Stop)
            $read += [string]$ch.Name
        } catch {
            # "No events were found" non e' un errore di accesso: il registro e'
            # leggibile ma vuoto. Distinguere i due casi e' essenziale, perche' un
            # registro vuoto e un registro inaccessibile hanno significati opposti.
            $msg = [string]$_.Exception.Message
            if ($msg -match 'No events were found|Nessun evento') {
                $read += [string]$ch.Name
            } else {
                $denied += [PSCustomObject]@{ Channel = [string]$ch.Name; Reason = $msg }
            }
            continue
        }

        foreach ($ev in $raw) {
            try {
                $xml = [xml]$ev.ToXml()
                $user = ''
                $address = ''
                $domain = ''

                $ud = $xml.Event.UserData
                if ($ud) {
                    $node = $ud.FirstChild
                    if ($node) {
                        foreach ($c in $node.ChildNodes) {
                            switch ($c.Name) {
                                'Param1' { $user = [string]$c.InnerText }
                                'Param2' { $domain = [string]$c.InnerText }
                                'Param3' { $address = [string]$c.InnerText }
                                'User'    { $user = [string]$c.InnerText }
                                'Address' { $address = [string]$c.InnerText }
                                default { }
                            }
                        }
                    }
                }
                if ($domain -and $user -and $user -notmatch '\\') { $user = "$domain\$user" }

                $kind = switch ([int]$ev.Id) {
                    1149 { 'Autenticazione riuscita' }
                    21   { 'Accesso alla sessione' }
                    24   { 'Sessione disconnessa' }
                    25   { 'Riconnessione alla sessione' }
                    default { "Evento $($ev.Id)" }
                }

                # Un indirizzo "LOCALE"/"LOCAL"/loopback indica la sessione sulla console del
                # PC (l'utente che accede alla propria postazione), NON un accesso remoto.
                # Contarla come remota darebbe un falso positivo clamoroso: le righe del
                # LocalSessionManager (eventi 21/24/25) registrano ANCHE gli accessi locali.
                $isLocal = Test-DVLocalSessionAddress -Address $address

                $events += [PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated
                    EventId     = [int]$ev.Id
                    Kind        = $(if ($isLocal -and $ev.Id -eq 21) { 'Accesso locale (console)' } elseif ($isLocal -and $ev.Id -eq 24) { 'Disconnessione locale' } elseif ($isLocal -and $ev.Id -eq 25) { 'Riconnessione locale' } else { $kind })
                    Account     = $user
                    SourceIP    = $address
                    IsLocal     = $isLocal
                    Channel     = [string]$ch.Name
                }
            } catch { continue }
        }
    }

    return @{
        Readable       = (@($read).Count -gt 0)
        Events         = @($events | Sort-Object TimeCreated -Descending)
        ChannelsRead   = $read
        ChannelsDenied = $denied
    }
}

function Get-DVEventLogFindings {
    <#
    .SYNOPSIS
        Esegue tutte le analisi storiche disponibili e restituisce punteggio e
        riscontri testuali, dichiarando esplicitamente se il registro Security
        non era leggibile (privilegi insufficienti).
    #>
    param(
        [int]$DaysBack = 30,
        [hashtable]$ProcessDb = @{}
    )

    $securityReadable = Test-DVCanReadSecurityLog

    $serviceEvents = Get-DVServiceInstallEvents -DaysBack $DaysBack -ProcessDb $ProcessDb
    $clearedEvents = @()
    $remoteLogons = @()
    if ($securityReadable) {
        $clearedEvents = Get-DVSecurityLogClearedEvents -DaysBack 90
        $remoteLogons = Get-DVRemoteLogonEvents -DaysBack $DaysBack
    }

    # Tentata comunque: questi registri non richiedono di norma privilegi elevati
    # e sono spesso l'unica fonte disponibile a chi non e' amministratore.
    $rdpOperational = Get-DVRdpOperationalEvents -DaysBack $DaysBack

    $score = 0
    $textFindings = @()

    foreach ($s in ($serviceEvents | Where-Object { $_.MatchedTool })) {
        $score += 30
        $textFindings += "[STORICO] Installato servizio riconducibile a $($s.MatchedTool) il $($s.TimeCreated.ToString('yyyy-MM-dd HH:mm'))"
    }
    foreach ($c in $clearedEvents) {
        $score += 25
        $textFindings += "[STORICO] Registro di sicurezza cancellato il $($c.TimeCreated.ToString('yyyy-MM-dd HH:mm'))"
    }
    if (@($remoteLogons).Count -gt 0) {
        $score += 15
        $textFindings += "[STORICO] $(@($remoteLogons).Count) accessi remoti (RDP) negli ultimi $DaysBack giorni"
    }

    # Gli accessi dai registri operativi sono gli stessi che comparirebbero nel
    # registro Security: si conteggiano solo se quello non era leggibile, per non
    # attribuire punti due volte al medesimo fatto.
    $rdpSessions = @($rdpOperational.Events | Where-Object { ($_.EventId -eq 1149 -or $_.EventId -eq 21) -and -not $_.IsLocal })
    $localSessions = @($rdpOperational.Events | Where-Object { $_.IsLocal -and $_.EventId -eq 21 })
    if (@($rdpSessions).Count -gt 0 -and @($remoteLogons).Count -eq 0) {
        $score += 15
        $sources = @($rdpSessions | Where-Object { $_.SourceIP } | ForEach-Object { $_.SourceIP } | Select-Object -Unique)
        $srcText = if (@($sources).Count -gt 0) { " da $(@($sources).Count) indirizzo/i di origine" } else { '' }
        $textFindings += "[STORICO] $(@($rdpSessions).Count) accessi remoti (Desktop remoto) negli ultimi $DaysBack giorni$srcText, rilevati dai registri operativi dei Servizi Desktop remoto"
    }

    return @{
        SecurityLogReadable = $securityReadable
        ServiceInstalls     = $serviceEvents
        SecurityLogCleared  = $clearedEvents
        RemoteLogons        = $remoteLogons
        RdpOperational      = $rdpOperational
        LocalSessionCount   = @($localSessions).Count
        DaysAnalyzed        = $DaysBack
        Score               = $score
        Findings            = $textFindings
    }
}

Export-ModuleMember -Function Test-DVCanReadSecurityLog, Test-DVLocalSessionAddress, Get-DVServiceInstallEvents, `
    Get-DVSecurityLogClearedEvents, Get-DVRemoteLogonEvents, Get-DVRdpOperationalEvents, `
    Get-DVEventLogFindings
