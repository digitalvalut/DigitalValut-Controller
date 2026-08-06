# DigitalValut Controller v4.2 - EventLogAnalyzer Module
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

    return @{
        SecurityLogReadable = $securityReadable
        ServiceInstalls     = $serviceEvents
        SecurityLogCleared  = $clearedEvents
        RemoteLogons        = $remoteLogons
        DaysAnalyzed        = $DaysBack
        Score               = $score
        Findings            = $textFindings
    }
}

Export-ModuleMember -Function Test-DVCanReadSecurityLog, Get-DVServiceInstallEvents, `
    Get-DVSecurityLogClearedEvents, Get-DVRemoteLogonEvents, Get-DVEventLogFindings
