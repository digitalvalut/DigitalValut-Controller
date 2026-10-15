# DigitalValut Controller v5.2 - RemoteToolConfig Module
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
# ---------------------------------------------------------------------------
# PERCHE' QUESTO MODULO ESISTE
#
# Sapere che un software di accesso remoto e' installato dice poco. Cambia tutto
# sapere COME e' configurato: se all'utente compare una richiesta di consenso
# prima che qualcuno entri, se l'icona che segnala il server attivo e' nascosta,
# se e' possibile prelevare file, se il PC chiama attivamente un indirizzo
# prestabilito. Un'assistenza tecnica richiesta dall'utente e un accesso
# silenzioso e invisibile sono due fatti giuridicamente diversi, anche quando il
# software e' lo stesso.
#
# Questa lettura NON richiede privilegi di amministratore: i file di
# configurazione in Program Files sono leggibili da qualunque utente. E' quindi
# l'informazione piu' rilevante a cui un dipendente senza privilegi puo' arrivare
# da solo.
#
# Le semantiche delle impostazioni UltraVNC riportate qui provengono dalla
# documentazione ufficiale del produttore:
#   https://uvnc.com/docs/ultravnc-server/69-ultravnc-ini.html
#   https://uvnc.com/docs/documentation/144-ultravnc-user-notification.html
# Ogni interpretazione e' dichiarata come tale e accompagnata dal valore grezzo
# letto dal file, perche' un tecnico terzo possa verificarla.
# ---------------------------------------------------------------------------

function Test-DVSecretSettingName {
    <#
    .SYNOPSIS
        Stabilisce se il nome di una impostazione contiene presumibilmente una credenziale.
    .DESCRIPTION
        I file di configurazione degli strumenti di accesso remoto contengono le
        password di accesso, spesso con cifrature reversibili (UltraVNC e TightVNC
        usano DES con chiave fissa e nota). Un report destinato a essere allegato a
        una PEC o consegnato a terzi non deve MAI riportare quei valori: sarebbe una
        divulgazione delle credenziali dell'accesso che si sta cercando di
        documentare. Il criterio e' volutamente largo: in caso di dubbio si oscura.
    #>
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return ($Name -match '(?i)pass|pwd|secret|token|credential|cred$|hash|\bpin\b|auth.?key|api.?key|private')
}

function Protect-DVSettingValue {
    <#
    .SYNOPSIS
        Restituisce il valore da riportare nel report, oscurando le credenziali.
    .DESCRIPTION
        Per una credenziale il report dichiara soltanto se e' valorizzata: e' il dato
        utile (esiste un accesso protetto da password / non protetto) senza il rischio
        di divulgare la password.
    #>
    param([string]$Name, [object]$Value)
    if (Test-DVSecretSettingName -Name $Name) {
        if ([string]::IsNullOrEmpty([string]$Value)) { return '[vuoto - nessuna credenziale impostata]' }
        return '[valorizzato - valore non riportato per non divulgare la credenziale]'
    }
    return [string]$Value
}

function Get-DVUltraVncConfigPath {
    <#
    .SYNOPSIS
        Individua il file ultravnc.ini nei percorsi di installazione noti.
    #>
    param([string[]]$ExtraPaths = @())

    $candidates = @()
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:ALLUSERSPROFILE)) {
        if (-not $base) { continue }
        $candidates += (Join-Path $base 'uvnc bvba\UltraVNC\ultravnc.ini')
        $candidates += (Join-Path $base 'UltraVNC\ultravnc.ini')
        $candidates += (Join-Path $base 'uvnc bvba\UltraVnc\ultravnc.ini')
    }
    $candidates += $ExtraPaths

    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c -PathType Leaf -ErrorAction SilentlyContinue)) { return $c }
    }
    return $null
}

function ConvertFrom-DVIniFile {
    <#
    .SYNOPSIS
        Converte un file .ini in una hashtable di sezioni.
    .DESCRIPTION
        Parser deliberatamente tollerante: righe malformate vengono ignorate
        senza interrompere la lettura. I valori sono restituiti come stringhe,
        esattamente come scritti nel file.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $result = [ordered]@{}
    $section = 'root'
    $result[$section] = [ordered]@{}

    $lines = @()
    try {
        $lines = [System.IO.File]::ReadAllLines($Path)
    } catch {
        throw "Impossibile leggere $Path : $($_.Exception.Message)"
    }

    foreach ($raw in $lines) {
        $line = ([string]$raw).Trim()
        if (-not $line) { continue }
        if ($line.StartsWith(';') -or $line.StartsWith('#')) { continue }
        if ($line.StartsWith('[') -and $line.EndsWith(']')) {
            $section = $line.Substring(1, $line.Length - 2).Trim()
            if (-not $result.Contains($section)) { $result[$section] = [ordered]@{} }
            continue
        }
        $idx = $line.IndexOf('=')
        if ($idx -lt 1) { continue }
        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim()
        $result[$section][$key] = $val
    }
    return $result
}

function Get-DVUltraVncSettingCatalog {
    <#
    .SYNOPSIS
        Catalogo delle impostazioni rilevanti, con il significato documentato dal
        produttore e la lettura in chiaro di ciascun valore.
    .DESCRIPTION
        'Governs' riporta la funzione dell'impostazione secondo la documentazione
        ufficiale. 'Readings' associa a un valore specifico la sua conseguenza
        pratica. 'Points' e' il peso attribuito al punteggio e vale piu' di zero
        solo per le configurazioni che indicano assenza di consenso od occultamento:
        le altre caratteristiche sono riportate a titolo informativo, perche'
        descrivono quanto e' invasivo uno strumento gia' conteggiato e non
        costituiscono un fatto ulteriore.
    #>
    return @(
        [PSCustomObject]@{
            Key = 'QuerySetting'; Default = '2'
            Governs = "Stabilisce quando compare la richiesta di consenso, in base al prefisso (+ ammesso, ? chiedi, - rifiuta) con cui l'indirizzo e' elencato in AuthHosts. Documentazione: 0 e 1 accettano senza chiedere sia gli indirizzi '+' sia quelli '?'; 2 (predefinito) accetta '+' e chiede per '?'; 3 chiede per entrambi; 4 chiede per '+' e rifiuta gli altri."
            Readings = @{
                '0' = @{ Text = "Nessuna richiesta di consenso: le connessioni dagli indirizzi ammessi e da quelli marcati '?' vengono accettate automaticamente."; Risk = 'HIGH'; Points = 15 }
                '1' = @{ Text = "Nessuna richiesta di consenso: le connessioni dagli indirizzi ammessi e da quelli marcati '?' vengono accettate automaticamente."; Risk = 'HIGH'; Points = 15 }
                '2' = @{ Text = "Valore predefinito: la richiesta di consenso compare solo per gli indirizzi elencati in AuthHosts con il prefisso '?'."; Risk = 'INFO'; Points = 0 }
                '3' = @{ Text = "La richiesta di consenso compare per gli indirizzi ammessi e per quelli marcati '?'."; Risk = 'INFO'; Points = 0 }
                '4' = @{ Text = "La richiesta di consenso compare per gli indirizzi ammessi; gli altri sono rifiutati."; Risk = 'INFO'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'QueryAccept'; Default = '0'
            Governs = "Azione applicata allo scadere del tempo di visualizzazione della richiesta di consenso. Documentazione: 0 = rifiuta, 1 = accetta, 2 = rifiuta."
            Readings = @{
                '1' = @{ Text = "Se nessuno risponde alla richiesta entro il tempo previsto, la connessione viene accettata automaticamente."; Risk = 'HIGH'; Points = 15 }
                '0' = @{ Text = "Se nessuno risponde entro il tempo previsto, la connessione viene rifiutata."; Risk = 'INFO'; Points = 0 }
                '2' = @{ Text = "Se nessuno risponde entro il tempo previsto, la connessione viene rifiutata."; Risk = 'INFO'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'QueryTimeout'; Default = ''
            Governs = "Tempo di visualizzazione della richiesta di consenso (la documentazione non specifica l'unita' di misura; nell'uso corrente sono secondi)."
            Readings = @{}
        }
        [PSCustomObject]@{
            Key = 'QueryIfNoLogon'; Default = ''
            Governs = "Abilita o disabilita la richiesta di consenso quando nessun utente risulta collegato. La documentazione indica che con QueryAccept=2 e QueryIfNoLogon=0 nessun messaggio viene mostrato a schermo bloccato."
            Readings = @{}
        }
        [PSCustomObject]@{
            Key = 'AuthHosts'; Default = ''
            Governs = "Elenco di indirizzi IP, anche parziali, con prefisso: + ammesso, - rifiutato, ? consenso richiesto. Un indirizzo parziale (es. 192.168.1) corrisponde a tutto l'intervallo."
            Readings = @{}
        }
        [PSCustomObject]@{
            Key = 'DisableTrayIcon'; Default = '0'
            Governs = "1 nasconde l'icona del server nell'area di notifica."
            Readings = @{
                '1' = @{ Text = "L'icona che segnala il server attivo e' nascosta: non e' visibile alcun indicatore del fatto che il PC accetta connessioni remote."; Risk = 'HIGH'; Points = 15 }
                '0' = @{ Text = "L'icona del server e' visibile nell'area di notifica."; Risk = 'INFO'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'InputsEnabled'; Default = '1'
            Governs = "Consente a chi si collega di controllare il server (mouse e tastiera)."
            Readings = @{
                '1' = @{ Text = "Chi si collega puo' usare mouse e tastiera, non solo vedere lo schermo."; Risk = 'INFO'; Points = 0 }
                '0' = @{ Text = "Chi si collega puo' solo vedere lo schermo, senza comandare il PC."; Risk = 'INFO'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'LocalInputsDisabled'; Default = '0'
            Governs = "1 blocca mouse e tastiera locali, lasciando il controllo soltanto a chi e' collegato da remoto."
            Readings = @{
                '1' = @{ Text = "Durante una sessione remota mouse e tastiera locali risultano bloccati."; Risk = 'MEDIUM'; Points = 0 }
                '0' = @{ Text = "Mouse e tastiera locali restano utilizzabili durante una sessione remota."; Risk = 'INFO'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'BlankMonitorEnabled'; Default = '0'
            Governs = "1 consente a chi si collega di oscurare lo schermo del PC controllato."
            Readings = @{
                '1' = @{ Text = "Chi si collega puo' oscurare il tuo schermo: le operazioni svolte da remoto possono non essere visibili a chi sta davanti al PC."; Risk = 'MEDIUM'; Points = 0 }
                '0' = @{ Text = "Lo schermo non puo' essere oscurato da chi si collega."; Risk = 'INFO'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'FileTransferEnabled'; Default = '1'
            Governs = "1 abilita il trasferimento di file tra il PC e chi si collega."
            Readings = @{
                '1' = @{ Text = "E' possibile prelevare file dal PC e depositarne altri."; Risk = 'MEDIUM'; Points = 0 }
                '0' = @{ Text = "Il trasferimento di file non e' abilitato."; Risk = 'INFO'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'MSLogonRequired'; Default = '0'
            Governs = "1 richiede le credenziali Windows al posto della sola password VNC."
            Readings = @{
                '0' = @{ Text = "L'accesso non richiede credenziali Windows: e' protetto dalla sola password del server VNC."; Risk = 'MEDIUM'; Points = 0 }
                '1' = @{ Text = "L'accesso richiede credenziali Windows, quindi risulta associabile a un'utenza nominativa."; Risk = 'INFO'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'LoopbackOnly'; Default = '0'
            Governs = "1 accetta soltanto connessioni provenienti dallo stesso PC; prevale su AllowLoopback e AuthHosts."
            Readings = @{
                '1' = @{ Text = "Il server accetta solo connessioni locali: non e' raggiungibile dalla rete."; Risk = 'INFO'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'IdleTimeout'; Default = '0'
            Governs = "Secondi di inattivita' dopo i quali la sessione viene chiusa; 0 disattiva la chiusura automatica."
            Readings = @{
                '0' = @{ Text = "Una sessione remota non viene chiusa automaticamente per inattivita'."; Risk = 'INFO'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'AllowProperties'; Default = '1'
            Governs = "0 rimuove dal menu la voce che consente di vedere e modificare le impostazioni del server."
            Readings = @{
                '0' = @{ Text = "L'utente del PC non puo' consultare ne' modificare le impostazioni del server."; Risk = 'MEDIUM'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'AllowShutdown'; Default = '1'
            Governs = "0 rimuove dal menu la voce che consente di arrestare il server."
            Readings = @{
                '0' = @{ Text = "L'utente del PC non puo' arrestare il server di accesso remoto."; Risk = 'MEDIUM'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'DebugLevel'; Default = '0'
            Governs = "Livello di registrazione diagnostica: 0 non produce alcun output; valori intorno a 10-12 producono una registrazione completa."
            Readings = @{
                '0' = @{ Text = "Il server non tiene alcun registro locale: delle connessioni avvenute non resta traccia nel file di log del programma."; Risk = 'MEDIUM'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'PortNumber'; Default = '5900'
            Governs = "Porta su cui il server resta in ascolto (predefinita 5900)."
            Readings = @{}
        }
        [PSCustomObject]@{
            Key = 'UseRegistry'; Default = '0'
            Governs = "1 indica che le impostazioni in uso sono quelle del registro di Windows e non quelle di questo file."
            Readings = @{
                '1' = @{ Text = "Le impostazioni effettive risiedono nel registro di Windows: i valori di questo file potrebbero non essere quelli applicati."; Risk = 'MEDIUM'; Points = 0 }
            }
        }
        [PSCustomObject]@{
            Key = 'service_commandline'; Default = ''
            Governs = "Argomenti con cui il server viene avviato in modalita' servizio. La presenza di -connect configura una connessione inversa: e' il PC a contattare un indirizzo prestabilito."
            Readings = @{}
        }
    )
}

function Get-DVUltraVncConsentAssessment {
    <#
    .SYNOPSIS
        Determina se, secondo la configurazione letta, all'utente venga mostrata
        una richiesta di consenso prima di una connessione remota.
    .DESCRIPTION
        La conclusione e' deliberatamente prudente: quando il file non consente di
        stabilirlo con certezza il risultato e' 'Non determinabile', con la
        motivazione, invece di un'affermazione non dimostrabile.
    #>
    param([hashtable]$Settings = @{})

    $get = {
        param($k, $def)
        if ($Settings.ContainsKey($k) -and -not [string]::IsNullOrWhiteSpace([string]$Settings[$k])) { return [string]$Settings[$k] }
        return $def
    }

    $loopback = & $get 'LoopbackOnly' '0'
    if ($loopback -eq '1') {
        return [PSCustomObject]@{
            Outcome = 'Non applicabile'
            Reason  = "Il server e' configurato per accettare soltanto connessioni locali (LoopbackOnly=1): non e' raggiungibile dalla rete."
            Risk    = 'INFO'
            Points  = 0
        }
    }

    $qs = & $get 'QuerySetting' '2'
    $authHosts = & $get 'AuthHosts' ''
    $queryAccept = & $get 'QueryAccept' '0'

    if ($qs -eq '0' -or $qs -eq '1') {
        return [PSCustomObject]@{
            Outcome = 'Non previsto'
            Reason  = "QuerySetting=$qs. Secondo la documentazione ufficiale, con questo valore le connessioni dagli indirizzi ammessi e da quelli marcati '?' vengono accettate senza mostrare alcuna richiesta all'utente del PC."
            Risk    = 'HIGH'
            Points  = 15
        }
    }

    if ($qs -eq '3' -or $qs -eq '4') {
        $extra = if ($queryAccept -eq '1') { " Da notare che QueryAccept=1: se nessuno risponde entro il tempo previsto, la connessione viene comunque accettata." } else { '' }
        return [PSCustomObject]@{
            Outcome = 'Previsto'
            Reason  = ("QuerySetting=${qs}: la richiesta di consenso e' prevista per gli indirizzi ammessi." + $extra)
            Risk    = 'INFO'
            Points  = 0
        }
    }

    # QuerySetting=2 (predefinito): il dialogo compare solo per gli indirizzi '?'
    if ([string]::IsNullOrWhiteSpace($authHosts)) {
        return [PSCustomObject]@{
            Outcome = 'Non determinabile'
            Reason  = "QuerySetting=2 (valore predefinito): secondo la documentazione la richiesta di consenso compare soltanto per gli indirizzi elencati in AuthHosts con il prefisso '?'. In questa configurazione AuthHosts e' vuoto, quindi nessun indirizzo risulta marcato '?'. Il file non permette di stabilire con certezza se all'utente venga mostrato un avviso: e' un punto da chiedere espressamente al servizio informatico."
            Risk    = 'MEDIUM'
            Points  = 0
        }
    }

    if ($authHosts -match '\?') {
        return [PSCustomObject]@{
            Outcome = 'Previsto solo per alcuni indirizzi'
            Reason  = "QuerySetting=2 e AuthHosts contiene indirizzi marcati '?': per quelli la richiesta di consenso e' prevista, per gli indirizzi marcati '+' la connessione e' accettata senza chiedere. Elenco letto: $authHosts"
            Risk    = 'MEDIUM'
            Points  = 0
        }
    }

    return [PSCustomObject]@{
        Outcome = 'Non previsto'
        Reason  = "QuerySetting=2 e nessun indirizzo in AuthHosts e' marcato '?': secondo la documentazione la richiesta di consenso compare solo per gli indirizzi '?', quindi per gli indirizzi configurati le connessioni vengono accettate senza mostrare alcun avviso. Elenco letto: $authHosts"
        Risk    = 'HIGH'
        Points  = 15
    }
}

function Get-DVUltraVncConfigReport {
    <#
    .SYNOPSIS
        Legge e interpreta la configurazione di UltraVNC.
    #>
    param([string]$ConfigPath)

    if (-not $ConfigPath) { $ConfigPath = Get-DVUltraVncConfigPath }
    $report = [PSCustomObject]@{
        Tool        = 'UltraVNC'
        ConfigPath  = $ConfigPath
        Found       = $false
        Error       = ''
        Settings    = @{}
        Interpreted = @()
        Consent     = $null
        ReverseConnection = $null
        LogFile     = ''
        Score       = 0
        Findings    = @()
    }
    if (-not $ConfigPath) { return $report }

    $ini = $null
    try {
        $ini = ConvertFrom-DVIniFile -Path $ConfigPath
    } catch {
        $report.Error = $_.Exception.Message
        return $report
    }
    $report.Found = $true

    # Le impostazioni rilevanti stanno in [admin]; alcune installazioni le pongono
    # altrove, quindi si cerca in tutte le sezioni senza sovrascrivere [admin].
    $flat = @{}
    foreach ($sec in $ini.Keys) {
        foreach ($k in $ini[$sec].Keys) {
            if ($sec -eq 'admin' -or -not $flat.ContainsKey($k)) { $flat[$k] = $ini[$sec][$k] }
        }
    }
    # Oscuramento delle credenziali (passwd, passwd2, ...) PRIMA di qualunque uso:
    # $report viene esportato nel JSON incorporato nel report allegabile a terzi.
    $safeFlat = @{}
    foreach ($k in $flat.Keys) { $safeFlat[$k] = Protect-DVSettingValue -Name ([string]$k) -Value $flat[$k] }
    $flat = $safeFlat
    $report.Settings = $flat

    $score = 0
    $findings = @()
    $interpreted = @()
    foreach ($entry in Get-DVUltraVncSettingCatalog) {
        $present = $flat.ContainsKey($entry.Key)
        $value = if ($present) { [string]$flat[$entry.Key] } else { '' }
        $isDefault = (-not $present)
        $effective = if ($present -and -not [string]::IsNullOrWhiteSpace($value)) { $value } else { [string]$entry.Default }

        $reading = ''
        $risk = 'INFO'
        $pts = 0
        if ($entry.Readings -and $entry.Readings.ContainsKey($effective)) {
            $r = $entry.Readings[$effective]
            $reading = [string]$r.Text
            $risk = [string]$r.Risk
            $pts = [int]$r.Points
        }

        # La connessione inversa si riconosce dal contenuto, non dal valore esatto.
        if ($entry.Key -eq 'service_commandline' -and $value -match '-connect') {
            $reading = "La riga di avvio del servizio contiene -connect: il PC e' configurato per contattare attivamente un indirizzo prestabilito, senza che sia necessario che qualcuno si colleghi dall'esterno."
            $risk = 'HIGH'
            $pts = 25
            $report.ReverseConnection = $value
        }

        # QueryAccept governa l'azione allo scadere del dialogo di consenso: se per
        # QuerySetting quel dialogo non compare affatto, non e' un fatto ulteriore.
        $qsEffective = if ($flat.ContainsKey('QuerySetting') -and -not [string]::IsNullOrWhiteSpace([string]$flat['QuerySetting'])) { [string]$flat['QuerySetting'] } else { '2' }
        if ($entry.Key -eq 'QueryAccept' -and ($qsEffective -eq '0' -or $qsEffective -eq '1')) {
            $pts = 0
            $risk = 'INFO'
            $reading = "Ininfluente in questa configurazione: con QuerySetting=$qsEffective la richiesta di consenso non viene mostrata."
        }

        if ($pts -gt 0) {
            $score += $pts
            $findings += "[CONFIGURAZIONE] UltraVNC: $reading"
        }

        $interpreted += [PSCustomObject]@{
            Key       = $entry.Key
            Value     = if ($present) { $value } else { '(non presente nel file)' }
            IsDefault = $isDefault
            Effective = $effective
            Governs   = [string]$entry.Governs
            Reading   = $reading
            Risk      = $risk
            Points    = $pts
        }
    }

    $consent = Get-DVUltraVncConsentAssessment -Settings $flat
    $report.Consent = $consent
    if ([int]$consent.Points -gt 0) {
        # Il peso del consenso e' gia' conteggiato tramite QuerySetting quando deriva
        # da quel valore: si somma solo se non vi e' una riga di catalogo che lo copre.
        $alreadyCounted = @($interpreted | Where-Object { $_.Key -eq 'QuerySetting' -and [int]$_.Points -gt 0 }).Count -gt 0
        if (-not $alreadyCounted) {
            $score += [int]$consent.Points
            $findings += "[CONFIGURAZIONE] UltraVNC: nessuna richiesta di consenso prevista prima di una connessione remota"
        }
    }

    if ($flat.ContainsKey('path') -and $flat['path']) {
        $candidate = Join-Path ([string]$flat['path']) 'winvnc.log'
        $report.LogFile = $candidate
    }

    $report.Interpreted = $interpreted
    $report.Score = $score
    $report.Findings = $findings
    return $report
}

function Get-DVOtherToolConfigs {
    <#
    .SYNOPSIS
        Rileva la configurazione di altri strumenti di accesso remoto noti.
    .DESCRIPTION
        Per questi strumenti i valori sono riportati senza interpretazione: il
        significato esatto di ciascuna chiave va verificato nella documentazione
        del rispettivo produttore. Riportare un valore grezzo e' utile; attribuirgli
        un significato non verificato lo e' molto meno.
    #>
    $results = @()
    $registryTargets = @(
        @{ Tool = 'TightVNC';   Path = 'HKLM:\SOFTWARE\TightVNC\Server' }
        @{ Tool = 'RealVNC';    Path = 'HKLM:\SOFTWARE\RealVNC\vncserver' }
        @{ Tool = 'TeamViewer'; Path = 'HKLM:\SOFTWARE\TeamViewer' }
        @{ Tool = 'TeamViewer'; Path = 'HKLM:\SOFTWARE\WOW6432Node\TeamViewer' }
    )
    $interesting = 'query|notif|accept|prompt|permission|unattended|confirm|filetransfer|file_transfer|log|port|password|access'

    foreach ($t in $registryTargets) {
        try {
            if (-not (Test-Path -LiteralPath $t.Path -ErrorAction SilentlyContinue)) { continue }
            $props = Get-ItemProperty -LiteralPath $t.Path -ErrorAction Stop
            $vals = [ordered]@{}
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -like 'PS*') { continue }
                if ($p.Name -notmatch $interesting) { continue }
                $vals[$p.Name] = Protect-DVSettingValue -Name $p.Name -Value $p.Value
            }
            if ($vals.Count -eq 0) { continue }
            $results += [PSCustomObject]@{
                Tool     = [string]$t.Tool
                Source   = [string]$t.Path
                Settings = $vals
            }
        } catch {
            Write-Verbose "Configurazione non leggibile: $($t.Path) - $($_.Exception.Message)"
        }
    }

    $fileTargets = @(
        @{ Tool = 'AnyDesk'; Path = (Join-Path ([string]$env:ProgramData) 'AnyDesk\service.conf') }
        @{ Tool = 'AnyDesk'; Path = (Join-Path ([string]$env:APPDATA) 'AnyDesk\service.conf') }
    )
    foreach ($t in $fileTargets) {
        try {
            if (-not $t.Path -or -not (Test-Path -LiteralPath $t.Path -PathType Leaf -ErrorAction SilentlyContinue)) { continue }
            $vals = [ordered]@{}
            foreach ($line in [System.IO.File]::ReadAllLines($t.Path)) {
                $idx = ([string]$line).IndexOf('=')
                if ($idx -lt 1) { continue }
                $k = ([string]$line).Substring(0, $idx).Trim()
                if ($k -notmatch $interesting) { continue }
                $vals[$k] = Protect-DVSettingValue -Name $k -Value (([string]$line).Substring($idx + 1).Trim())
            }
            if ($vals.Count -eq 0) { continue }
            $results += [PSCustomObject]@{ Tool = [string]$t.Tool; Source = [string]$t.Path; Settings = $vals }
        } catch {
            Write-Verbose "Configurazione non leggibile: $($t.Path)"
        }
    }

    return $results
}

function Get-DVRemoteToolConfigFindings {
    <#
    .SYNOPSIS
        Analisi complessiva della configurazione degli strumenti di accesso remoto.
    .OUTPUTS
        Hashtable con UltraVNC, OtherTools, Score e Findings.
    #>
    param([string]$UltraVncConfigPath)

    $uvnc = $null
    try {
        $uvnc = Get-DVUltraVncConfigReport -ConfigPath $UltraVncConfigPath
    } catch {
        $uvnc = [PSCustomObject]@{ Tool = 'UltraVNC'; Found = $false; Error = $_.Exception.Message; Score = 0; Findings = @(); Interpreted = @(); Settings = @{}; Consent = $null; ConfigPath = ''; ReverseConnection = $null; LogFile = '' }
    }

    $others = @()
    try { $others = @(Get-DVOtherToolConfigs) } catch { $others = @() }

    $score = 0
    $findings = @()
    if ($uvnc -and $uvnc.Found) {
        $score += [int]$uvnc.Score
        $findings += @($uvnc.Findings)
    }

    return @{
        UltraVNC   = $uvnc
        OtherTools = $others
        Score      = $score
        Findings   = $findings
    }
}

Export-ModuleMember -Function Get-DVUltraVncConfigPath, ConvertFrom-DVIniFile, `
    Get-DVUltraVncSettingCatalog, Get-DVUltraVncConsentAssessment, `
    Get-DVUltraVncConfigReport, Get-DVOtherToolConfigs, Get-DVRemoteToolConfigFindings, `
    Test-DVSecretSettingName, Protect-DVSettingValue
