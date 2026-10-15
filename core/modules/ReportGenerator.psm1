# DigitalValut Controller v5.1 - ReportGenerator Module
# Strumento Tutela Privacy Lavoratori PA
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

# ---------------------------------------------------------------------------
# MOTORE DI PUNTEGGIO "DV-SCORE-2"
#
# Principio: ogni punto attribuito deve essere verificabile da un terzo.
# Per questo ogni voce di punteggio produce un record di evidenza con:
#   - la regola applicata (id del file in core\rules, quando disponibile)
#   - la fonte tecnica del dato (quale comando/registro lo ha prodotto)
#   - lo stato del fatto (presenza, esposizione in rete, sessione attiva, storico)
#   - cosa il rilievo NON dimostra
#
# Secondo principio: un medesimo fatto non si conta piu' volte. Se la porta 5900
# e' tenuta aperta dallo stesso processo di controllo remoto gia' rilevato, non e'
# un secondo fatto: e' la conferma del primo, e pesa solo per l'esposizione in rete
# che aggiunge. Il doppio conteggio e' il difetto piu' facile da contestare in un
# report tecnico, perche' gonfia il risultato senza aggiungere prove.
# ---------------------------------------------------------------------------

$script:DVScoreWeights = [ordered]@{
    ActiveRemoteSession          = @{ Points = 40; Why = "Sessione di accesso remoto in corso: e' un evento, non una semplice possibilita'" }
    Spyware                      = @{ Points = 100; Why = 'Software la cui funzione tipica e la raccolta occulta di dati' }
    EmployeeMonitor              = @{ Points = 50;  Why = 'Software di monitoraggio del lavoratore: richiede base giuridica e informativa' }
    RemoteControlProcessCritical = @{ Points = 30;  Why = 'Processo di controllo remoto in esecuzione (rischio CRITICAL da regola)' }
    PortIndependentCritical      = @{ Points = 30;  Why = 'Canale di accesso remoto distinto, in ascolto (rischio CRITICAL da regola)' }
    RemoteControlProcessHigh     = @{ Points = 20;  Why = 'Processo di controllo remoto in esecuzione (rischio HIGH da regola)' }
    PortIndependentHigh          = @{ Points = 20;  Why = 'Canale di accesso remoto distinto, in ascolto (rischio HIGH da regola)' }
    SuspiciousService            = @{ Points = 25;  Why = 'Servizio di sistema riconducibile a controllo remoto: parte senza intervento utente' }
    FirewallNotFullyActive       = @{ Points = 25;  Why = 'Firewall non attivo su tutti i profili: amplia chi puo raggiungere il PC' }
    RemoteConfigConcealment      = @{ Points = 15;  Why = "Configurazione che non prevede richiesta di consenso all'utente, o che nasconde l'indicatore del server attivo" }
    PortIndependentMedium        = @{ Points = 10;  Why = 'Porta di accesso remoto in ascolto (rischio MEDIUM da regola)' }
    PortExposureSameSoftware     = @{ Points = 10;  Why = "Esposizione in rete dello stesso software gia' conteggiato (non un fatto nuovo)" }
    InstalledSoftwareOnly        = @{ Points = 10;  Why = 'Software di controllo remoto installato ma non in esecuzione al momento della scansione' }
    UnsignedExecutable           = @{ Points = 10;  Why = 'Eseguibile privo di firma digitale valida: elemento a supporto, non decisivo' }
    PastRemoteAccessLog          = @{ Points = 10;  Why = "Il registro dello strumento riporta connessioni remote avvenute in passato: e' un evento, non una possibilita'" }
}

$script:DVScoreThresholds = [ordered]@{
    SICURO  = @{ Min = 0;  Max = 0;    Text = 'SICURO';  Color = '#2ed573'; Icon = '&#x2705;';    Class = 'secure';   Meaning = 'Nessun indicatore rilevato dai controlli eseguiti.' }
    BASSO   = @{ Min = 1;  Max = 24;   Text = 'BASSO';   Color = '#7bed9f'; Icon = '&#x1F7E2;'; Class = 'low';      Meaning = 'Indicatori marginali: in genere configurazioni ordinarie.' }
    MEDIO   = @{ Min = 25; Max = 49;   Text = 'MEDIO';   Color = '#ffa502'; Icon = '&#x1F7E1;'; Class = 'medium';   Meaning = 'Elementi che meritano una verifica, senza segni di accesso in corso.' }
    ALTO    = @{ Min = 50; Max = 79;   Text = 'ALTO';    Color = '#ff6348'; Icon = '&#x1F7E0;'; Class = 'high';     Meaning = "Strumenti di accesso remoto presenti e/o esposti in rete, nessuna sessione attiva rilevata: va verificata l'autorizzazione." }
    CRITICO = @{ Min = 80; Max = [int]::MaxValue; Text = 'CRITICO'; Color = '#ff4757'; Icon = '&#x1F534;'; Class = 'critical'; Meaning = 'Sessione di accesso remoto attiva, o indicatori di sorveglianza/raccolta occulta: verifica immediata.' }
}

function Get-DVScoreWeights { return $script:DVScoreWeights }
function Get-DVScoreThresholds { return $script:DVScoreThresholds }

function Add-DVScoreEvidence {
    <#
    .SYNOPSIS
        Registra una voce di evidenza che concorre (o non concorre) al punteggio.
    .DESCRIPTION
        Restituisce il record creato e lo accoda alla lista passata. Ogni record e'
        una riga della tabella "Come e' stato calcolato il punteggio" nel report:
        un terzo deve poter rifare il conto e risalire alla fonte di ogni dato.
    #>
    param(
        [Parameter(Mandatory)][System.Collections.IList]$Evidence,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Finding,
        [string]$Severity = 'INFO',
        [int]$Points = 0,
        [string]$Rule = '',
        [string]$Source = '',
        [string]$State = '',
        [string]$Note = '',
        [string]$Label = ''
    )
    if (-not $Label) { $Label = "[$Severity] $Finding" }
    $record = [PSCustomObject]@{
        Id       = ('R-{0:D2}' -f ($Evidence.Count + 1))
        Category = $Category
        Finding  = $Finding
        Severity = $Severity
        Points   = $Points
        Rule     = $Rule
        Source   = $Source
        State    = $State
        Note     = $Note
        Label    = $Label
    }
    [void]$Evidence.Add($record)
    return $record
}

function Get-DVSeverityFromLabel {
    <#
    .SYNOPSIS
        Ricava la gravita' dal prefisso usato dai moduli specializzati, es. "[CRITICO] ...".
    #>
    param([string]$Label)
    if ($Label -match '^\s*\[([A-Z''\s]+)\]') { return $Matches[1].Trim() }
    return 'INFO'
}

function Add-DVModuleScoreEvidence {
    <#
    .SYNOPSIS
        Riporta nel registro delle evidenze il risultato di un modulo che calcola
        un proprio punteggio (sorveglianza A/V, persistenza, DLL, registri eventi).
    .DESCRIPTION
        Il punteggio di questi moduli e' aggregato per categoria: viene attribuito a
        una sola riga e dichiarato come tale, cosi' la somma della colonna "Punti"
        corrisponde esattamente al totale del report.
    #>
    param(
        [Parameter(Mandatory)][System.Collections.IList]$Evidence,
        [Parameter(Mandatory)][string]$Category,
        [object]$Result,
        [string]$Source = '',
        [string]$Note = ''
    )
    if (-not $Result) { return 0 }
    $points = 0
    if ($Result.Score) { $points = [int]$Result.Score }
    $findings = @()
    if ($Result.Findings) { $findings = @($Result.Findings) }
    if ($points -le 0 -and $findings.Count -eq 0) { return 0 }

    if ($findings.Count -eq 0) {
        [void](Add-DVScoreEvidence -Evidence $Evidence -Category $Category `
            -Finding 'Punteggio attribuito dal modulo specializzato' -Severity 'MEDIO' `
            -Points $points -Source $Source -State 'Aggregato' `
            -Note $Note -Label "[MEDIO] $Category")
        return $points
    }

    $isFirst = $true
    foreach ($f in $findings) {
        $text = [string]$f
        $sev = Get-DVSeverityFromLabel $text
        $rowPoints = 0
        $rowNote = $Note
        if ($isFirst) {
            $rowPoints = $points
            $rowNote = ("Punteggio della categoria ({0} punti) calcolato dal modulo e attribuito a questa riga per non duplicare il conteggio. {1}" -f $points, $Note).Trim()
            $isFirst = $false
        }
        [void](Add-DVScoreEvidence -Evidence $Evidence -Category $Category `
            -Finding ($text -replace '^\s*\[[A-Z''\s]+\]\s*', '') -Severity $sev `
            -Points $rowPoints -Source $Source -State 'Rilevato' -Note $rowNote -Label $text)
    }
    return $points
}

function Test-DVSameSoftware {
    <#
    .SYNOPSIS
        Stabilisce se due nomi (processo/software) si riferiscono allo stesso programma.
    .DESCRIPTION
        Serve a non contare due volte lo stesso fatto. Il confronto e' volutamente
        conservativo: in caso di dubbio NON correla, cosi' un'eventuale imprecisione
        produce un punteggio piu' alto solo per fatti realmente distinti, mai una
        correlazione inventata.
    #>
    param([string]$A, [string]$B)
    if ([string]::IsNullOrWhiteSpace($A) -or [string]::IsNullOrWhiteSpace($B)) { return $false }
    $x = ($A -replace '\.exe$', '' -replace '[^a-zA-Z0-9]', '').ToLower()
    $y = ($B -replace '\.exe$', '' -replace '[^a-zA-Z0-9]', '').ToLower()
    if (-not $x -or -not $y) { return $false }
    if ($x -eq $y) { return $true }
    if ($x.Length -ge 4 -and $y.Contains($x)) { return $true }
    if ($y.Length -ge 4 -and $x.Contains($y)) { return $true }
    return $false
}

function Test-DVSoftwareMatchesProcess {
    <#
    .SYNOPSIS
        Stabilisce se un software installato corrisponde a un processo gia' conteggiato.
    .DESCRIPTION
        Il nome commerciale del prodotto e il nome del processo spesso differiscono
        (es. prodotto "UltraVnc", processo "winvnc.exe"): il collegamento affidabile e'
        il percorso dell'eseguibile, che contiene di norma il nome del prodotto o
        dell'editore. Il percorso, pero', non e' leggibile senza privilegi elevati:
        in quel caso la funzione restituisce 'Indeterminato' e il report lo dichiara,
        invece di attribuire punti a un fatto che potrebbe essere lo stesso.
    .OUTPUTS
        'Corrisponde' | 'Distinto' | 'Indeterminato'
    #>
    param(
        [string]$SoftwareName,
        [string]$Publisher,
        [object[]]$CountedProcesses = @()
    )
    $norm = { param($t) ([string]$t -replace '\.exe$', '' -replace '[^a-zA-Z0-9]', '').ToLower() }
    $swN = & $norm $SoftwareName
    $pubN = & $norm $Publisher
    if (-not $swN) { return 'Distinto' }
    if (@($CountedProcesses).Count -eq 0) { return 'Distinto' }

    $anyPathKnown = $false
    foreach ($proc in @($CountedProcesses)) {
        foreach ($n in @($proc.Name, $proc.ProcessName)) {
            if (Test-DVSameSoftware -A $SoftwareName -B ([string]$n)) { return 'Corrisponde' }
        }
        $pathN = & $norm ([string]$proc.Path)
        if ($pathN) {
            $anyPathKnown = $true
            if ($swN.Length -ge 4 -and $pathN.Contains($swN))   { return 'Corrisponde' }
            if ($pubN -and $pubN.Length -ge 5 -and $pathN.Contains($pubN)) { return 'Corrisponde' }
        }
    }
    # Nessuna corrispondenza: e' un fatto distinto solo se i percorsi erano leggibili
    # e hanno permesso di escluderlo. Altrimenti resta indeterminato.
    if ($anyPathKnown) { return 'Distinto' }
    return 'Indeterminato'
}

function Get-DVThreatScore {
    <#
    .SYNOPSIS
        Calcola il livello di rischio e il registro delle evidenze che lo motiva.
    .OUTPUTS
        Hashtable con Score, Level, Findings (compatibilita'), Evidence (tabella di
        calcolo), Model e Weights.
    #>
    param(
        [object]$PortAnalysis,
        [object]$ProcessAnalysis,
        [object]$ServiceAnalysis,
        [object]$SoftwareAnalysis,
        [object]$FirewallStatus,
        [object]$NetworkConnections,
        [hashtable]$PortsDb = @{},
        [object]$SurveillanceCapabilities = $null,
        [object]$PersistenceFindings = $null,
        [object]$ModuleFindings = $null,
        [object]$EventLogFindings = $null,
        [object]$ActiveRemoteConnections = @(),
        [object]$RemoteToolConfig = $null,
        [object]$UltraVncLog = $null
    )

    $w = $script:DVScoreWeights
    $evidence = [System.Collections.Generic.List[object]]::new()

    # -- 1. Processi di controllo remoto in esecuzione (fatto primario) ------------
    $remoteControl = @()
    $spyware = @()
    $employeeMonitor = @()
    if ($ProcessAnalysis) {
        if ($ProcessAnalysis.RemoteControl)   { $remoteControl = @($ProcessAnalysis.RemoteControl) }
        if ($ProcessAnalysis.Spyware)         { $spyware = @($ProcessAnalysis.Spyware) }
        if ($ProcessAnalysis.EmployeeMonitor) { $employeeMonitor = @($ProcessAnalysis.EmployeeMonitor) }
    }

    $countedSoftware = @()     # nomi gia' conteggiati: evita il doppio conteggio
    $countedProcesses = @()    # processi gia' conteggiati (nome + percorso) per la correlazione
    $seenRc = @{}
    foreach ($proc in $remoteControl) {
        $swName = if ($proc.Name) { [string]$proc.Name } else { [string]$proc.ProcessName }
        $key = $swName.ToLower()
        $procName = if ($proc.ProcessName) { [string]$proc.ProcessName } else { $swName }
        if ($seenRc.ContainsKey($key)) {
            # Piu' processi dello stesso software (es. due winvnc): un solo rilievo.
            $seenRc[$key].Instances += 1
            continue
        }
        $risk = if ($proc.Risk) { [string]$proc.Risk } else { 'HIGH' }
        $pts = if ($risk -eq 'CRITICAL') { $w.RemoteControlProcessCritical.Points } else { $w.RemoteControlProcessHigh.Points }
        $sev = if ($risk -eq 'CRITICAL') { 'CRITICO' } else { 'ALTO' }
        $rec = Add-DVScoreEvidence -Evidence $evidence -Category 'Processi' `
            -Finding "Software controllo remoto: $swName" -Severity $sev -Points $pts `
            -Rule ([string]$proc.RuleId) -Source 'Get-CimInstance Win32_Process / Get-Process' `
            -State 'In esecuzione' `
            -Note "Non dimostra un uso illecito: uno strumento di assistenza remota puo' essere autorizzato. Va verificata l'esistenza di informativa, base giuridica e, ove richiesto, accordo sindacale o autorizzazione." `
            -Label "[$sev] Software controllo remoto: $swName"
        $seenRc[$key] = [PSCustomObject]@{ Record = $rec; Names = @($swName, $procName); Instances = 1 }
        $countedSoftware += $swName
        $countedSoftware += $procName
        $countedProcesses += [PSCustomObject]@{ Name = $swName; ProcessName = $procName; Path = [string]$proc.Path }
    }

    foreach ($spy in $spyware) {
        $n = if ($spy.Name) { [string]$spy.Name } else { [string]$spy.ProcessName }
        [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Processi' `
            -Finding "Potenziale spyware: $n" -Severity 'ALLARME' -Points $w.Spyware.Points `
            -Rule ([string]$spy.RuleId) -Source 'Get-CimInstance Win32_Process / Get-Process' -State 'In esecuzione' `
            -Note 'Corrispondenza con una regola di rilevamento spyware. Va confermata da un perito: un omonimia di processo e possibile.' `
            -Label "[ALLARME] Potenziale spyware: $n")
        $countedSoftware += $n
        $countedProcesses += [PSCustomObject]@{ Name = $n; ProcessName = [string]$spy.ProcessName; Path = [string]$spy.Path }
    }

    foreach ($mon in $employeeMonitor) {
        $n = if ($mon.Name) { [string]$mon.Name } else { [string]$mon.ProcessName }
        [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Processi' `
            -Finding "Software monitoraggio dipendenti: $n" -Severity 'ATTENZIONE' -Points $w.EmployeeMonitor.Points `
            -Rule ([string]$mon.RuleId) -Source 'Get-CimInstance Win32_Process / Get-Process' -State 'In esecuzione' `
            -Note "Software di questo tipo richiede in ogni caso informativa e base giuridica; l'eventuale accordo sindacale va verificato." `
            -Label "[ATTENZIONE] Software monitoraggio dipendenti: $n")
        $countedSoftware += $n
        $countedProcesses += [PSCustomObject]@{ Name = $n; ProcessName = [string]$mon.ProcessName; Path = [string]$mon.Path }
    }

    # -- 2. Porte in ascolto: correlate al processo che le detiene -----------------
    $suspiciousPorts = @()
    if ($PortAnalysis -and $PortAnalysis.SuspiciousPorts) { $suspiciousPorts = @($PortAnalysis.SuspiciousPorts) }
    foreach ($port in $suspiciousPorts) {
        $risk = if ($port.Risk) { [string]$port.Risk } else { 'MEDIUM' }
        $owner = [string]$port.OwnerProcessName
        $ownerPid = if ($port.OwnerProcessId) { [int]$port.OwnerProcessId } else { 0 }
        $ownerText = if ($owner) { "$owner (PID $ownerPid)" } elseif ($ownerPid -gt 0) { "PID $ownerPid (non identificabile senza privilegi elevati)" } else { 'processo non identificato' }

        $linkedTo = $null
        foreach ($k in $seenRc.Keys) {
            foreach ($n in $seenRc[$k].Names) {
                if (Test-DVSameSoftware -A $owner -B $n) { $linkedTo = $seenRc[$k].Record; break }
            }
            if ($linkedTo) { break }
        }

        if ($linkedTo) {
            [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Porte' `
                -Finding "Porta $($port.Port) ($($port.Name)) in ascolto, tenuta aperta da $ownerText" `
                -Severity 'ALTO' -Points $w.PortExposureSameSoftware.Points `
                -Rule ([string]$port.RuleId) -Source 'Get-NetTCPConnection -State Listen' `
                -State "Conferma di $($linkedTo.Id) + esposizione in rete" `
                -Note "Stesso software del rilievo $($linkedTo.Id): non e' un fatto ulteriore. I punti attribuiti riguardano solo l'esposizione in rete (il PC accetta connessioni su questa porta, nei limiti consentiti dal firewall)." `
                -Label "[ALTO] Porta $($port.Port) ($($port.Name)) in ascolto - $ownerText")
            continue
        }

        $pts = switch ($risk) {
            'CRITICAL' { $w.PortIndependentCritical.Points }
            'HIGH'     { $w.PortIndependentHigh.Points }
            'MEDIUM'   { $w.PortIndependentMedium.Points }
            default    { 0 }
        }
        if ($pts -le 0) { continue }
        $sev = switch ($risk) { 'CRITICAL' { 'CRITICO' } 'HIGH' { 'ALTO' } default { 'MEDIO' } }
        [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Porte' `
            -Finding "Porta $($port.Port) ($($port.Name)) in ascolto, tenuta aperta da $ownerText" `
            -Severity $sev -Points $pts -Rule ([string]$port.RuleId) `
            -Source 'Get-NetTCPConnection -State Listen' -State 'In ascolto' `
            -Note "Canale di accesso remoto distinto da quelli gia' elencati. Una porta in ascolto indica che il PC puo' accettare connessioni, non che qualcuno le stia usando. $([string]$port.FalsePositiveNote)".Trim() `
            -Label "[$sev] Porta $($port.Port) ($($port.Name)) aperta - $ownerText")
    }

    # -- 3. Sessioni di accesso remoto attive (il fatto piu' rilevante) -----------
    $activeSessions = @()
    foreach ($c in @($ActiveRemoteConnections)) {
        if ($c -and [string]$c.Stato -like 'CONNESSO*') { $activeSessions += $c }
    }
    $seenSession = @{}
    foreach ($s in $activeSessions) {
        $sk = "$($s.IPRemoto)|$($s.PortaLocale)"
        if ($seenSession.ContainsKey($sk)) { continue }
        $seenSession[$sk] = $true
        [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Sessioni attive' `
            -Finding "Sessione di accesso remoto in corso da $($s.IPRemoto) verso la porta $($s.PortaLocale) (processo $($s.Processo), PID $($s.PID))" `
            -Severity 'CRITICO' -Points $w.ActiveRemoteSession.Points `
            -Source 'Get-NetTCPConnection -State Established' -State 'Sessione attiva al momento della scansione' `
            -Note "Una sessione attiva e' un evento, non una possibilita': l'orario e l'IP di origine sono elementi verificabili nei log dell'ente. Puo' trattarsi di assistenza tecnica autorizzata: chiedere chi era collegato e per quale finalita'." `
            -Label "[CRITICO] Sessione di accesso remoto attiva da $($s.IPRemoto) su porta $($s.PortaLocale)")
    }

    # -- 4. Servizi -----------------------------------------------------------------
    foreach ($svc in @($ServiceAnalysis)) {
        if (-not $svc) { continue }
        $svcName = if ($svc.Name) { [string]$svc.Name } elseif ($svc.ServiceName) { [string]$svc.ServiceName } else { [string]$svc }
        [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Servizi' `
            -Finding "Servizio riconducibile a controllo remoto: $svcName" -Severity 'ALTO' `
            -Points $w.SuspiciousService.Points -Rule ([string]$svc.RuleId) `
            -Source 'Get-Service / Get-CimInstance Win32_Service' -State 'Registrato nel sistema' `
            -Note "Un servizio si avvia senza intervento dell'utente: e' l'elemento che rende l'accesso possibile anche quando nessuno ha aperto il programma." `
            -Label "[ALTO] Servizio controllo remoto: $svcName")
    }

    # -- 5. Software installato (correlato ai processi gia' conteggiati) -----------
    foreach ($sw in @($SoftwareAnalysis)) {
        if (-not $sw) { continue }
        $swName = [string]$sw.Name
        $ver = if ($sw.Version) { " $($sw.Version)" } else { '' }
        $pub = [string]$sw.Publisher
        $match = Test-DVSoftwareMatchesProcess -SoftwareName $swName -Publisher $pub -CountedProcesses $countedProcesses

        if ($match -eq 'Corrisponde') {
            [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Software installato' `
                -Finding "$swName$ver risulta installato (editore: $pub)" -Severity 'INFO' -Points 0 `
                -Rule ([string]$sw.RuleId) -Source 'Registro: HKLM/HKCU ...\Uninstall' -State 'Conferma di un rilievo precedente' `
                -Note 'Stesso software di un processo gia conteggiato: riportato come conferma documentale (versione ed editore), senza punteggio aggiuntivo.' `
                -Label "[INFO] Installato: $swName$ver")
            continue
        }

        if ($match -eq 'Indeterminato') {
            [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Software installato' `
                -Finding "$swName$ver risulta installato (editore: $pub)" -Severity 'INFO' -Points 0 `
                -Rule ([string]$sw.RuleId) -Source 'Registro: HKLM/HKCU ...\Uninstall' `
                -State 'Correlazione con i processi non verificabile' `
                -Note "Non e' stato possibile stabilire se si tratti dello stesso software di un processo gia' conteggiato, perche' il percorso degli eseguibili non e' leggibile senza privilegi di amministratore. Per non gonfiare il punteggio con un possibile doppio conteggio, questa voce non attribuisce punti: ripetere la scansione come amministratore per una classificazione certa." `
                -Label "[INFO] Installato: $swName$ver (correlazione da verificare)")
            continue
        }

        [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Software installato' `
            -Finding "$swName$ver installato ma non in esecuzione al momento della scansione" -Severity 'MEDIO' `
            -Points $w.InstalledSoftwareOnly.Points -Rule ([string]$sw.RuleId) `
            -Source 'Registro: HKLM/HKCU ...\Uninstall' -State 'Installato' `
            -Note "Il programma e' presente e puo' essere avviato. Non essendo attivo, pesa meno di un processo in esecuzione." `
            -Label "[MEDIO] Software installato: $swName$ver")
    }

    # -- 6. Firewall ----------------------------------------------------------------
    if ($FirewallStatus -and -not $FirewallStatus.AllEnabled) {
        [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Firewall' `
            -Finding 'Firewall di Windows non attivo su tutti i profili' -Severity 'RISCHIO' `
            -Points $w.FirewallNotFullyActive.Points -Source 'Get-NetFirewallProfile' -State 'Configurazione' `
            -Note "Con il firewall disattivo su un profilo, le porte in ascolto sono raggiungibili da piu' reti. In dominio la configurazione e' spesso imposta centralmente dall'ente." `
            -Label '[RISCHIO] Firewall non completamente attivo')
    }

    # -- 7. Firma digitale degli eseguibili rilevati --------------------------------
    $unsignedFlagged = @()
    foreach ($proc in @($remoteControl) + @($spyware) + @($employeeMonitor)) {
        if ($proc.SignatureStatus -and $proc.SignatureStatus -notin @('Valid', 'Inaccessible', 'Unknown')) {
            $unsignedFlagged += [string]$proc.ProcessName
        }
    }
    $unsignedUnique = @($unsignedFlagged | Select-Object -Unique)
    if ($unsignedUnique.Count -gt 0) {
        [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Firma digitale' `
            -Finding "Eseguibile senza firma digitale valida: $($unsignedUnique -join ', ')" -Severity 'FIRMA' `
            -Points ($unsignedUnique.Count * $w.UnsignedExecutable.Points) `
            -Source 'Get-AuthenticodeSignature' -State 'Verifica Authenticode' `
            -Note "L'assenza di firma valida non dimostra da sola malevolenza, ne' la firma dimostra un uso autorizzato: e' un elemento a supporto." `
            -Label "[FIRMA] Eseguibile senza firma digitale valida: $($unsignedUnique -join ', ')")
    }

    # -- 8. Moduli con punteggio proprio -------------------------------------------
    if ($SurveillanceCapabilities -and $SurveillanceCapabilities.OverallAudioVideoRisk) {
        $avScore = [int]$SurveillanceCapabilities.OverallAudioVideoRisk.Score
        if ($avScore -gt 0) {
            [void](Add-DVModuleScoreEvidence -Evidence $evidence -Category 'Sorveglianza audio/video' `
                -Result @{ Score = $avScore; Findings = @($SurveillanceCapabilities.SurveillanceFindings) } `
                -Source 'ConsentStore (registro), moduli caricati dai processi, dispositivi audio' `
                -Note 'Dettaglio e limiti nella sezione Sorveglianza audio/video.')
        }
    }
    [void](Add-DVModuleScoreEvidence -Evidence $evidence -Category 'Persistenza avanzata' -Result $PersistenceFindings `
        -Source 'Sottoscrizioni WMI, AppInit_DLLs, IFEO, Task pianificati' `
        -Note 'Tecniche usate sia da malware sia da strumenti di gestione IT legittimi: valutare nel contesto.')
    [void](Add-DVModuleScoreEvidence -Evidence $evidence -Category 'DLL da percorsi anomali' -Result $ModuleFindings `
        -Source 'Moduli caricati dai processi (Get-Process -Module)' `
        -Note "Non rileva le tecniche di iniezione avanzate: l'assenza di righe non dimostra l'assenza di iniezione.")
    [void](Add-DVModuleScoreEvidence -Evidence $evidence -Category 'Analisi storica (registri eventi)' -Result $EventLogFindings `
        -Source 'Registri eventi di Windows (System, Security, Servizi Desktop remoto)' `
        -Note 'I registri ruotano: eventi piu vecchi possono essere stati sovrascritti legittimamente.')
    [void](Add-DVModuleScoreEvidence -Evidence $evidence -Category 'Configurazione accesso remoto' -Result $RemoteToolConfig `
        -Source 'File di configurazione dello strumento (es. ultravnc.ini), leggibile senza privilegi elevati' `
        -Note "Pesano solo le impostazioni che indicano assenza di consenso od occultamento: le altre caratteristiche sono riportate nella sezione dedicata senza attribuire punti, perche' descrivono quanto e' invasivo uno strumento gia' conteggiato.")

    # Registro locale dello strumento: connessioni remote avvenute in passato. E' l'unico
    # dato che mostra l'USO effettivo, non la sola possibilita'. Una sola riga di punteggio,
    # indipendentemente dal numero di connessioni.
    if ($UltraVncLog -and [int]$UltraVncLog.RemoteConnectionCount -gt 0) {
        $addrList = @($UltraVncLog.DistinctRemoteAddresses | Select-Object -First 10)
        $addrText = ($addrList -join ', ')
        if (@($UltraVncLog.DistinctRemoteAddresses).Count -gt 10) { $addrText += ', ...' }
        $period = ''
        if ($UltraVncLog.FirstSeenText -and $UltraVncLog.LastSeenText) { $period = " tra il $($UltraVncLog.FirstSeenText) e il $($UltraVncLog.LastSeenText)" }
        $readFiles = @($UltraVncLog.Files | Where-Object { $_.Readable -and $_.ConnectionLines -gt 0 })
        $fileText = ($readFiles | ForEach-Object { "$([IO.Path]::GetFileName([string]$_.Path)) (SHA-256 dei byte letti: $(([string]$_.Sha256).Substring(0,16))...)" }) -join '; '
        if (-not $fileText) { $fileText = 'registro eventi di Windows' }
        [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Storico accessi (registro dello strumento)' `
            -Finding "Il registro dello strumento riporta $([int]$UltraVncLog.RemoteSessionCount) sessioni ($([int]$UltraVncLog.RemoteConnectionCount) righe di connessione) da $(@($UltraVncLog.DistinctRemoteAddresses).Count) indirizzi non locali ($addrText)$period" `
            -Severity 'STORICO' -Points $w.PastRemoteAccessLog.Points `
            -Source "Lettura in sola lettura di: $fileText" -State 'Storico' `
            -Note "Una connessione registrata indica che lo strumento e' stato usato, non che l'uso sia illecito: puo' trattarsi di assistenza autorizzata. Gli indirizzi vanno attribuiti a un soggetto dall'ente. Il registro e' un file modificabile: la sua integrita' non e' garantita, quindi il dato va confermato dall'ente. Se piu' fonti riportano lo stesso accesso, e' contato una volta sola." `
            -Label "[STORICO] Registro dello strumento: $([int]$UltraVncLog.RemoteSessionCount) sessioni da $(@($UltraVncLog.DistinctRemoteAddresses).Count) indirizzi non locali")
    }

    # -- 9. Connessioni verso porte RAT note (canale in uscita) --------------------
    $suspiciousConns = @()
    if ($NetworkConnections -and $NetworkConnections.Suspicious) { $suspiciousConns = @($NetworkConnections.Suspicious) }
    foreach ($conn in $suspiciousConns) {
        $remotePort = if ($conn.RemotePort) { [int]$conn.RemotePort } else { 0 }
        if ($PortsDb -and $PortsDb.ContainsKey($remotePort) -and $PortsDb[$remotePort].Risk -match 'CRITICAL|HIGH') {
            $remoteIP = if ($conn.RemoteAddress) { $conn.RemoteAddress } else { $conn.RemoteIP }
            [void](Add-DVScoreEvidence -Evidence $evidence -Category 'Connessioni in uscita' `
                -Finding "Connessione in uscita verso $remoteIP sulla porta $remotePort ($($PortsDb[$remotePort].Name))" `
                -Severity 'SOSPETTO' -Points 20 -Rule ([string]$PortsDb[$remotePort].RuleId) `
                -Source 'Get-NetTCPConnection -State Established' -State 'Connessione in corso' `
                -Note 'Una connessione in uscita verso una porta tipica di accesso remoto puo indicare un canale inverso, oppure un normale servizio sulla stessa porta.' `
                -Label "[SOSPETTO] Connessione verso $remoteIP`:$remotePort")
        }
    }

    # -- Totale e livello -----------------------------------------------------------
    $score = 0
    foreach ($e in $evidence) { $score += [int]$e.Points }

    $t = $script:DVScoreThresholds
    $level = $t.CRITICO
    foreach ($k in @('SICURO', 'BASSO', 'MEDIO', 'ALTO')) {
        if ($score -ge $t[$k].Min -and $score -le $t[$k].Max) { $level = $t[$k]; break }
    }
    $levelOut = @{
        Text = $level.Text; Color = $level.Color; Icon = $level.Icon
        Class = $level.Class; Meaning = $level.Meaning
    }

    $findings = @()
    foreach ($e in $evidence) {
        if ($e.Severity -ne 'INFO') { $findings += [string]$e.Label }
    }

    return @{
        Score     = $score
        Level     = $levelOut
        Findings  = $findings
        Evidence  = @($evidence)
        Model     = 'DV-SCORE-2'
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }
}

function Get-DVLegalSectionHTML {
    # Al momento e' disponibile solo il testo normativo in italiano (contesto: lavoratori PA in Italia).
    return @"
<div class="legal-section">
    <h2>&#x2696;&#xFE0F; Riferimenti normativi completi</h2>
    <article class="law-article">
        <h3>STATUTO DEI LAVORATORI - Art. 4 (L. 300/1970)</h3>
        <blockquote>Gli impianti audiovisivi e gli altri strumenti dai quali derivi anche la possibilit&agrave; di controllo a distanza dell'attivit&agrave; dei lavoratori possono essere impiegati esclusivamente per esigenze organizzative e produttive, per la sicurezza del lavoro e per la tutela del patrimonio aziendale e possono essere installati <strong>previo accordo collettivo</strong> stipulato dalla rappresentanza sindacale unitaria o dalle rappresentanze sindacali aziendali [...] In mancanza di accordo, gli impianti e gli strumenti di cui al primo periodo possono essere installati <strong>previa autorizzazione</strong> della sede territoriale dell'Ispettorato nazionale del lavoro.</blockquote>
        <p class="law-note"><strong>NOTA:</strong> se un software di accesso remoto sia uno &quot;strumento di lavoro&quot; (art. 4, comma 2) o uno strumento da cui deriva la possibilit&agrave; di controllo a distanza (art. 4, comma 1) dipende dalle sue funzioni effettive e dall'uso che ne viene fatto: va valutato caso per caso. In ogni caso il datore di lavoro deve poter documentare finalit&agrave;, informativa ai lavoratori (art. 4, comma 3) e, ove richiesto, accordo sindacale o autorizzazione INL. Verifica con un legale o con il tuo sindacato.</p>
    </article>
    <article class="law-article">
        <h3>GDPR - Art. 5 (Principi)</h3>
        <blockquote>I dati personali sono trattati in modo lecito, corretto e <strong>trasparente</strong> nei confronti dell'interessato.</blockquote>
    </article>
    <article class="law-article">
        <h3>GDPR - Art. 13 (Informazioni da fornire)</h3>
        <blockquote>Il titolare del trattamento fornisce all'interessato, nel momento in cui i dati personali sono ottenuti, le seguenti informazioni: [...] le finalit&agrave; del trattamento [...] i destinatari o le categorie di destinatari dei dati personali.</blockquote>
        <p class="law-note"><strong>IN PRATICA:</strong> il datore di lavoro deve informarti se ha installato software di controllo, perch&eacute; lo usa e chi pu&ograve; accedervi. Se non hai ricevuto tale informativa, hai diritto a chiederla. L'eventuale illegittimit&agrave; del trattamento pu&ograve; essere accertata solo caso per caso: potrebbero esistere un accordo sindacale, un'autorizzazione INL o un'informativa che non ti sono stati notificati.</p>
    </article>
    <article class="law-article">
        <h3>CODICE PRIVACY - Art. 171 (Sanzioni penali)</h3>
        <blockquote>La violazione delle disposizioni di cui all'articolo 4 della legge 20 maggio 1970, n. 300 [...] &egrave; punita con le sanzioni di cui all'articolo 38 della medesima legge.</blockquote>
        <p class="law-note"><strong>SANZIONE:</strong> Ammenda da 154 &euro; a 1.549 &euro; o arresto da 15 giorni a 1 anno.</p>
    </article>
    <article class="law-article">
        <h3>GARANTE PRIVACY - Linee guida su posta elettronica e Internet nel rapporto di lavoro (1 marzo 2007)</h3>
        <p>Il Garante ha indicato che i controlli sui lavoratori devono rispettare i principi di necessit&agrave;, correttezza, pertinenza e non eccedenza, con adeguata informativa preventiva. Per le pronunce specifiche sul software di assistenza/controllo remoto consulta il sito del Garante o un legale: questo report non ne riporta il contenuto.</p>
    </article>
    <div class="sanctions-box">
        <h3>&#x1F6A8; SANZIONI ASTRATTAMENTE PREVISTE PER IL DATORE DI LAVORO</h3>
        <p style="font-size:0.85rem;">Massimi edittali previsti dalla legge in caso di violazione accertata. Non costituiscono una previsione dell'esito di un caso concreto.</p>
        <table class="data-table"><tr><td>GDPR - Art. 83</td><td>Fino a <strong>20.000.000 &euro;</strong> o 4% del fatturato</td></tr><tr><td>Codice Privacy - Art. 171</td><td>Ammenda + arresto fino a <strong>1 anno</strong></td></tr><tr><td>Conseguenza processuale</td><td>Dati raccolti in violazione dell'Art. 4 possono, secondo le circostanze, risultare <strong>non utilizzabili</strong> in sede disciplinare (da valutare con un legale)</td></tr></table>
    </div>
    <div class="sanctions-box" style="border-color:#888;">
        <h3>&#x26A0;&#xFE0F; AVVERTENZA - LIMITI DI QUESTO DOCUMENTO</h3>
        <p style="font-size:0.9rem;">I riferimenti normativi riportati hanno <strong>finalit&agrave; esclusivamente informativa e divulgativa</strong> e non costituiscono consulenza legale, parere pro veritate n&eacute; assistenza professionale.</p>
        <p style="font-size:0.9rem;">Questo report &egrave; il risultato di un'analisi tecnica <strong>automatizzata</strong>: pu&ograve; produrre <strong>falsi positivi</strong> (software legittimo segnalato come sospetto) e <strong>falsi negativi</strong> (strumenti di controllo non rilevati). La presenza di un software in elenco <strong>non dimostra</strong> di per s&eacute; un uso illecito, cos&igrave; come la sua assenza non dimostra l'assenza di controllo.</p>
        <p style="font-size:0.9rem;">Prima di assumere qualsiasi iniziativa disciplinare, sindacale, amministrativa o giudiziaria fondata su questo documento, &egrave; <strong>necessario</strong> rivolgersi a un avvocato e, per gli aspetti tecnici, a un perito informatico forense.</p>
        <p style="font-size:0.9rem;">L'autore del software declina ogni responsabilit&agrave; per l'interpretazione dei risultati e per le conseguenze di qualsiasi azione intrapresa sulla base di questo report. Vedi il file <code>DISCLAIMER.md</code> e la licenza Apache 2.0 (sezioni 7 e 8).</p>
    </div>
</div>
"@
}

function Get-DVRemoteConfigHTML {
    <#
    .SYNOPSIS
        Sezione sulla configurazione degli strumenti di accesso remoto.
    .DESCRIPTION
        Risponde alla domanda che conta davvero per un lavoratore: quando qualcuno
        si collega, me ne accorgo? Ogni riga riporta il valore grezzo letto dal
        file, la funzione dell'impostazione secondo la documentazione del
        produttore e la conseguenza pratica, cosi' che un tecnico terzo possa
        verificare l'interpretazione invece di doverla accettare.
    #>
    param([object]$RemoteToolConfig)

    if (-not $RemoteToolConfig) { return '' }
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $uvnc = $RemoteToolConfig.UltraVNC
    $others = @($RemoteToolConfig.OtherTools)
    if ((-not $uvnc -or -not $uvnc.Found) -and $others.Count -eq 0) { return '' }

    $body = ''

    if ($uvnc -and $uvnc.Found) {
        $c = $uvnc.Consent
        $consentClass = switch ([string]$c.Risk) {
            'HIGH'   { 'badge-critical' }
            'MEDIUM' { 'badge-medium' }
            default  { 'badge-low' }
        }
        $rows = ''
        foreach ($i in @($uvnc.Interpreted)) {
            if (-not $i.Reading -and $i.Value -eq '(non presente nel file)') { continue }
            $riskClass = switch ([string]$i.Risk) {
                'HIGH'   { 'badge-critical' }
                'MEDIUM' { 'badge-medium' }
                default  { 'badge-low' }
            }
            $ptsCell = if ([int]$i.Points -gt 0) { "<strong>+$([int]$i.Points)</strong>" } else { '0' }
            $defaultNote = if ($i.IsDefault) { ' <span style="font-size:0.75rem;opacity:0.7;">(valore predefinito: chiave non presente nel file)</span>' } else { '' }
            $rows += @"
<tr>
  <td><code>$(& $enc $i.Key)</code></td>
  <td><code>$(& $enc $i.Value)</code>$defaultNote</td>
  <td style="font-size:0.82rem;">$(& $enc $i.Governs)</td>
  <td style="font-size:0.85rem;">$(& $enc $i.Reading)</td>
  <td style="text-align:right;"><span class="badge $riskClass">$(& $enc $i.Risk)</span><br>$ptsCell</td>
</tr>
"@
        }

        $reverseBlock = ''
        if ($uvnc.ReverseConnection) {
            $reverseBlock = @"
<div class="warning-box">
    <strong>&#x26A0;&#xFE0F; CONNESSIONE INVERSA CONFIGURATA</strong>
    <p>La riga di avvio del servizio contiene <code>-connect</code>: il PC e' configurato per <strong>contattare attivamente un indirizzo prestabilito</strong>, senza che sia necessario che qualcuno lo raggiunga dall'esterno. Questo rende l'accesso possibile anche da reti diverse e indipendentemente dal firewall in ingresso. Valore letto: <code>$(& $enc $uvnc.ReverseConnection)</code></p>
</div>
"@
        }

        $logBlock = ''
        if ($uvnc.LogFile) {
            $logBlock = "<p style=`"font-size:0.85rem;`">Il file indica come cartella del registro locale del programma: <code>$(& $enc $uvnc.LogFile)</code>. Se presente e leggibile, quel file puo' contenere la traccia delle connessioni avvenute.</p>"
        }

        $body += @"
<h3>UltraVNC</h3>
<p style="font-size:0.85rem;">Configurazione letta da <code>$(& $enc $uvnc.ConfigPath)</code>. Il significato di ciascuna impostazione e' quello dichiarato dalla documentazione ufficiale del produttore (uvnc.com); i valori sono riportati come scritti nel file.</p>
<div class="warning-box">
    <strong>Quando qualcuno si collega, ti viene chiesto il consenso?</strong>
    <p style="margin-top:0.4rem;"><span class="badge $consentClass">$(& $enc $c.Outcome)</span></p>
    <p>$(& $enc $c.Reason)</p>
</div>
$reverseBlock
<table class="data-table">
    <thead><tr><th>Impostazione</th><th>Valore letto</th><th>Cosa governa (documentazione del produttore)</th><th>Conseguenza pratica</th><th style="text-align:right;">Rischio / Punti</th></tr></thead>
    <tbody>$rows</tbody>
</table>
$logBlock
"@
    }

    foreach ($o in $others) {
        $orows = ''
        foreach ($k in $o.Settings.Keys) {
            $orows += "<tr><td><code>$(& $enc $k)</code></td><td><code>$(& $enc $o.Settings[$k])</code></td></tr>`n"
        }
        $body += @"
<h3>$(& $enc $o.Tool)</h3>
<p style="font-size:0.85rem;">Valori letti da <code>$(& $enc $o.Source)</code>, <strong>riportati senza interpretazione</strong>: il significato di ciascuna chiave va verificato nella documentazione del rispettivo produttore.</p>
<table class="data-table"><thead><tr><th>Chiave</th><th>Valore</th></tr></thead><tbody>$orows</tbody></table>
"@
    }

    return @"
<section class="card">
    <h2>&#x1F527; COME E' CONFIGURATO L'ACCESSO REMOTO</h2>
    <p style="font-size:0.9rem;">Sapere che un software di accesso remoto e' installato dice poco: cambia tutto sapere <strong>come e' configurato</strong>. Un'assistenza tecnica che ti chiede il permesso e un accesso silenzioso, senza avviso e senza icona visibile, sono due fatti giuridicamente diversi anche quando il programma e' lo stesso. Questa lettura <strong>non richiede privilegi di amministratore</strong>.</p>
    $body
</section>
"@
}

function Get-DVUltraVncLogHTML {
    <#
    .SYNOPSIS
        Sezione del report con le connessioni passate ricavate dal registro dello strumento.
    .DESCRIPTION
        Tre esiti distinti, perche' hanno significati opposti: file illeggibile (dato in
        possesso dell'ente), file letto senza connessioni riconosciute (non prova
        l'assenza), file con connessioni (evento, da attribuire a un soggetto).
    #>
    param([object]$UltraVncLog = $null)
    if (-not $UltraVncLog) { return '' }
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }

    $fileRows = ''
    foreach ($f in @($UltraVncLog.Files | Where-Object { $_.Exists })) {
        $esito = if ($f.Readable) { '<span class="badge badge-low">LETTO</span>' } else { '<span class="badge badge-high">NON LEGGIBILE</span>' }
        $tr = if ($f.Truncated) { ' (solo la parte finale, per dimensione)' } else { '' }
        $lw = if ($f.LastWrite) { try { ([datetime]$f.LastWrite).ToString('yyyy-MM-dd HH:mm:ss') } catch { [string]$f.LastWrite } } else { 'n.d.' }
        $sha = if ($f.Sha256) { "<code style=`"font-size:0.72rem;word-break:break-all;`">$(& $enc $f.Sha256)</code>" } else { '-' }
        $err = if ($f.Error) { "<br><span style=`"font-size:0.78rem;opacity:0.8;`">$(& $enc $f.Error)</span>" } else { '' }
        $fileRows += "<tr><td><code style=`"font-size:0.8rem;`">$(& $enc $f.Path)</code></td><td>$esito$err</td><td>$([int64]$f.SizeBytes) byte$(& $enc $tr)</td><td>$(& $enc $lw)</td><td>$sha</td><td>$([int]$f.ConnectionLines)</td></tr>`n"
    }
    $filesTable = ''
    if ($fileRows) {
        $filesTable = "<table class=`"data-table`"><thead><tr><th>File</th><th>Esito</th><th>Dimensione</th><th>Ultima modifica</th><th>SHA-256 dei byte letti</th><th>Righe di connessione</th></tr></thead><tbody>$fileRows</tbody></table>"
    }

    $evLogNote = ''
    if ($UltraVncLog.EventLog) {
        if ($UltraVncLog.EventLog.Readable) {
            $evLogNote = "<p style=`"font-size:0.85rem;`">Registro eventi di Windows (Applicazione): letto; eventi di provider UltraVNC trovati: <strong>$([int]$UltraVncLog.EventLog.ProviderEvents)</strong>.</p>"
        } else {
            $evLogNote = "<p style=`"font-size:0.85rem;color:#ffa502;`">Registro eventi di Windows (Applicazione): non leggibile con i privilegi disponibili.</p>"
        }
    }

    $verdict = ''
    $count = [int]$UltraVncLog.RemoteConnectionCount
    if ($count -gt 0) {
        $rows = ''
        $shown = @($UltraVncLog.Events | Where-Object { -not $_.IsLocal } | Select-Object -Last 50)
        foreach ($e in $shown) {
            $when = if ($e.Time) { ([datetime]$e.Time).ToString('yyyy-MM-dd HH:mm:ss') } elseif ($e.TimeText) { [string]$e.TimeText + ' (come scritta nel file)' } else { 'non indicata' }
            $rows += "<tr><td>$(& $enc $when)</td><td>$(& $enc $e.Kind)</td><td><code>$(& $enc $e.Address)</code></td><td style=`"font-size:0.78rem;`">$(& $enc ([IO.Path]::GetFileName([string]$e.Source)))</td></tr>`n"
        }
        $verdict = @"
<p style="font-size:0.95rem;"><strong>Il registro riporta $([int]$UltraVncLog.RemoteSessionCount) sessioni remote</strong> ($count righe di connessione: una sessione ne genera piu' di una) da $(@($UltraVncLog.DistinctRemoteAddresses).Count) indirizzi non locali$(if ($UltraVncLog.FirstSeenText) { ", tra il $(& $enc $UltraVncLog.FirstSeenText) e il $(& $enc $UltraVncLog.LastSeenText)" }). E' il dato che distingue un accesso <em>possibile</em> da un accesso <em>avvenuto</em>. Non dice se l'uso fosse autorizzato: puo' essere assistenza tecnica. Dice che lo strumento e' stato usato, e che l'ente puo' e deve poter attribuire quegli indirizzi.</p>
<table class="data-table"><thead><tr><th>Ora</th><th>Evento</th><th>Indirizzo di origine</th><th>Fonte</th></tr></thead><tbody>$rows</tbody></table>
"@
        if ([int]$UltraVncLog.FailedAttemptCount -gt 0) {
            $verdict += "<p style=`"font-size:0.9rem;`">Tentativi di accesso non validi registrati da indirizzi non locali: <strong>$([int]$UltraVncLog.FailedAttemptCount)</strong>.</p>"
        }
    } elseif ($UltraVncLog.AnyFileRead -or ($UltraVncLog.EventLog -and $UltraVncLog.EventLog.Readable)) {
        $verdict = "<p style=`"font-size:0.9rem;`"><strong>Nessuna connessione remota riconosciuta</strong> nelle fonti lette. <strong>Questo non prova che non vi siano stati accessi</strong>: il registro registra le connessioni solo se il livello di registrazione impostato lo prevede, il file puo' essere stato ruotato, svuotato o modificato, e le righe sono riconosciute solo nei formati documentati dal produttore.</p>"
    } elseif ($UltraVncLog.AnyFileFound) {
        $verdict = "<p style=`"font-size:0.9rem;`"><strong>Il registro dello strumento esiste ma non e' leggibile</strong> con i privilegi disponibili. Il dato e' nella disponibilita' dell'ente e puo' essere richiesto formalmente.</p>"
    } else {
        $verdict = "<p style=`"font-size:0.9rem;`">Nessun file di registro dello strumento e' stato trovato nei percorsi noti. Se la registrazione e' disattivata o salvata altrove, il dato non e' accessibile da qui.</p>"
    }

    return @"
<section class="card">
    <h2>&#x1F4D3; REGISTRO DELLO STRUMENTO - ACCESSI PASSATI</h2>
    <p style="font-size:0.9rem;">La sola presenza di un software di accesso remoto dice che l'accesso e' <strong>possibile</strong>. Il suo registro puo' dire se e' <strong>avvenuto</strong>. I file sono letti in <strong>sola lettura</strong>, senza bloccarli e senza modificarli. Da ogni riga si estraggono <strong>solo ora, tipo di evento e indirizzo di origine</strong>: la riga non viene conservata, perche' potrebbe contenere nomi di persone.</p>
    $verdict
    $evLogNote
    <details style="margin-top:0.8rem;"><summary style="cursor:pointer;font-weight:700;">File letti e impronte di verifica</summary>
    <p style="font-size:0.82rem;margin-top:0.5rem;">L'impronta SHA-256 e' calcolata sui byte effettivamente letti: un terzo puo' verificare di avere esaminato lo stesso contenuto. L'ora e' riportata come scritta nel file e interpretata solo quando il formato la rende certa.</p>
    $filesTable
    </details>
</section>
"@
}

function Get-DVNonAdminGuidanceHTML {
    <#
    .SYNOPSIS
        Sezione per chi esegue la verifica senza privilegi di amministratore.
    .DESCRIPTION
        Non essere amministratore della propria postazione non e' soltanto un
        limite tecnico della scansione: e' un elemento di fatto rilevante, perche'
        esclude che l'utente possa aver installato lui stesso il software e colloca
        i registri degli accessi nella disponibilita' esclusiva del titolare del
        trattamento. Va quindi dichiarato nella richiesta, non nascosto.
    #>
    param([object]$EventLogFindings = $null)

    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }

    $rdpBlock = ''
    if ($EventLogFindings -and $EventLogFindings.RdpOperational) {
        $rdp = $EventLogFindings.RdpOperational
        $allEv = @($rdp.Events)
        $remoteEv = @($allEv | Where-Object { -not $_.IsLocal })
        $localCount = @($allEv | Where-Object { $_.IsLocal -and $_.EventId -eq 21 }).Count
        $localNote = ''
        if ($localCount -gt 0) {
            $localNote = "<p style=`"font-size:0.85rem;opacity:0.9;`">Nel periodo risultano inoltre <strong>$localCount sessioni locali</strong> (origine &quot;LOCALE&quot;): sono i normali accessi dell'utente alla console del proprio PC e <strong>non sono accessi remoti</strong>. Non concorrono al punteggio.</p>"
        }
        if (@($remoteEv).Count -gt 0) {
            $rows = ''
            foreach ($e in ($remoteEv | Select-Object -First 50)) {
                $ip = if ($e.SourceIP) { [string]$e.SourceIP } else { 'non indicato' }
                $acc = if ($e.Account) { [string]$e.Account } else { 'non indicato' }
                $when = try { ([datetime]$e.TimeCreated).ToString('yyyy-MM-dd HH:mm:ss') } catch { [string]$e.TimeCreated }
                $rows += "<tr><td>$(& $enc $when)</td><td>$(& $enc $e.Kind)</td><td>$(& $enc $acc)</td><td><code>$(& $enc $ip)</code></td></tr>`n"
            }
            $rdpBlock = @"
<h3>Accessi Desktop remoto da altri indirizzi, rilevati senza privilegi di amministratore</h3>
<p style="font-size:0.85rem;">Letti dai registri operativi dei Servizi Desktop remoto, che non richiedono privilegi elevati. Sono accessi con un indirizzo di origine diverso dalla console locale.</p>
<table class="data-table"><thead><tr><th>Data e ora</th><th>Evento</th><th>Utenza</th><th>Indirizzo di origine</th></tr></thead><tbody>$rows</tbody></table>
$localNote
"@
        } elseif ($rdp.Readable) {
            $rdpBlock = "<p style=`"font-size:0.9rem;`"><strong>Accessi Desktop remoto:</strong> i registri operativi dei Servizi Desktop remoto sono stati letti e <strong>non contengono accessi remoti</strong> nel periodo analizzato. Si tratta di un dato positivo e verificato, non di un controllo saltato.</p>$localNote<p style=`"font-size:0.85rem;opacity:0.85;`"><strong>Limite:</strong> questi registri riguardano il solo Desktop remoto di Windows. Un accesso effettuato con altri strumenti (es. UltraVNC) non vi compare.</p>"
        } else {
            $denied = @($rdp.ChannelsDenied | ForEach-Object { $_.Channel })
            $rdpBlock = "<p style=`"font-size:0.9rem;`"><strong>Accessi Desktop remoto:</strong> nemmeno i registri operativi dei Servizi Desktop remoto sono risultati leggibili con i privilegi disponibili$(if (@($denied).Count -gt 0) { ' (' + (& $enc ($denied -join ', ')) + ')' }). Il dato esiste ma e' nella disponibilita' esclusiva dell'ente: puo' essere richiesto formalmente.</p>"
        }
    }

    return @"
<section class="card">
    <h2>&#x1F511; VERIFICA ESEGUITA SENZA PRIVILEGI DI AMMINISTRATORE</h2>
    <p style="font-size:0.9rem;">L'assenza di privilegi amministrativi riduce il perimetro della scansione, ma e' essa stessa <strong>un elemento di fatto rilevante</strong>. Va dichiarata nella richiesta, perche' ha tre conseguenze.</p>
    <ol style="font-size:0.9rem;line-height:1.65;">
        <li><strong>L'utente non puo' aver installato questi strumenti.</strong> L'installazione di un software di accesso remoto e di un servizio di sistema richiede privilegi amministrativi. Se l'utente non li possiede, l'installazione e' stata effettuata da chi li possiede. Questo esclude in anticipo l'obiezione secondo cui lo strumento sarebbe stato introdotto dall'utente stesso.</li>
        <li><strong>I registri degli accessi sono nella disponibilita' esclusiva del titolare.</strong> L'utente non puo' leggere il registro di sicurezza della propria postazione. Non potendo verificare da se', ha un interesse concreto a che il dato venga prodotto da chi lo detiene: e' esattamente l'oggetto del diritto di accesso ex Art. 15 GDPR.</li>
        <li><strong>L'utente non puo' modificare ne' disattivare lo strumento.</strong> La configurazione non e' nella sua sfera di controllo: eventuali impostazioni che non prevedono avvisi o che nascondono l'indicatore del server non gli sono imputabili.</li>
    </ol>
    <p style="font-size:0.85rem;opacity:0.85;">Le voci che la scansione non ha potuto accertare sono elencate come <strong>parziali</strong> nella sezione &quot;Metodo e perimetro della verifica&quot;: un controllo non eseguito non va letto come &quot;nessun problema&quot;.</p>
    $rdpBlock
</section>
"@
}

function Get-DVScoreTableHTML {
    <#
    .SYNOPSIS
        Tabella di calcolo del punteggio: una riga per ogni punto attribuito.
    .DESCRIPTION
        E' la sezione che consente a un terzo (DPO, perito di parte avversa, giudice)
        di rifare il conto e di contestare una singola riga invece del risultato nel
        suo complesso. Un punteggio non spiegato e' il primo appiglio per liquidare
        un report come allarmistico.
    #>
    param(
        [object]$ThreatScore,
        [string]$Model = 'DV-SCORE-2'
    )

    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $evidence = @()
    if ($ThreatScore -and $ThreatScore.Evidence) { $evidence = @($ThreatScore.Evidence) }

    $rows = ''
    foreach ($e in $evidence) {
        $sevClass = switch -Regex ([string]$e.Severity) {
            'CRITICO|ALLARME' { 'critical' }
            'ALTO|RISCHIO|ATTENZIONE' { 'high' }
            'MEDIO|SOSPETTO|FIRMA' { 'medium' }
            default { 'low' }
        }
        $ruleCell = if ($e.Rule) { "<code>$(& $enc $e.Rule)</code>" } else { '<span style="opacity:0.6;">&mdash;</span>' }
        $ptsCell = if ([int]$e.Points -gt 0) { "<strong>+$([int]$e.Points)</strong>" } else { '0' }
        $rows += @"
<tr>
  <td><code>$(& $enc $e.Id)</code></td>
  <td>$(& $enc $e.Category)</td>
  <td>$(& $enc $e.Finding)<br><span style="font-size:0.8rem;opacity:0.75;">$(& $enc $e.Note)</span></td>
  <td>$(& $enc $e.State)</td>
  <td><span style="font-size:0.8rem;"><code>$(& $enc $e.Source)</code></span></td>
  <td>$ruleCell</td>
  <td style="text-align:right;"><span class="badge badge-$sevClass">$(& $enc $e.Severity)</span><br>$ptsCell</td>
</tr>
"@
    }
    if (-not $rows) {
        $rows = '<tr><td colspan="7" style="text-align:center;color:#7eb8e8;">Nessun elemento ha concorso al punteggio.</td></tr>'
    }

    $total = if ($ThreatScore) { [int]$ThreatScore.Score } else { 0 }

    $weightRows = ''
    foreach ($k in (Get-DVScoreWeights).Keys) {
        $wv = (Get-DVScoreWeights)[$k]
        $weightRows += "<tr><td style=`"text-align:right;`"><strong>+$($wv.Points)</strong></td><td>$(& $enc $wv.Why)</td></tr>`n"
    }

    $thrRows = ''
    foreach ($k in (Get-DVScoreThresholds).Keys) {
        $tv = (Get-DVScoreThresholds)[$k]
        $range = if ($tv.Max -eq [int]::MaxValue) { "$($tv.Min) e oltre" } elseif ($tv.Min -eq $tv.Max) { "$($tv.Min)" } else { "$($tv.Min) - $($tv.Max)" }
        $thrRows += "<tr><td><span style=`"color:$($tv.Color);font-weight:700;`">$($tv.Text)</span></td><td>$range</td><td>$(& $enc $tv.Meaning)</td></tr>`n"
    }

    return @"
<section class="card">
    <h2>&#x1F9EE; COME E' STATO CALCOLATO IL PUNTEGGIO</h2>
    <p style="font-size:0.9rem;">Ogni punto attribuito e' riportato con la sua fonte tecnica e la regola applicata. La somma della colonna di destra e' esattamente il punteggio mostrato in testa al report: <strong>$total</strong>. Modello di calcolo: <code>$(& $enc $Model)</code>.</p>
    <p style="font-size:0.85rem;opacity:0.85;">Un medesimo fatto non viene conteggiato due volte. Se una porta in ascolto appartiene a un software di controllo remoto gia' rilevato, la riga e' marcata come conferma di quel rilievo e pesa solo per l'esposizione in rete che aggiunge.</p>
    <table class="data-table">
        <thead><tr><th>Rif.</th><th>Categoria</th><th>Rilievo e limiti</th><th>Stato del fatto</th><th>Fonte tecnica del dato</th><th>Regola</th><th style="text-align:right;">Gravita' / Punti</th></tr></thead>
        <tbody>
        $rows
        <tr style="border-top:2px solid rgba(255,255,255,0.35);"><td colspan="6" style="text-align:right;"><strong>PUNTEGGIO TOTALE</strong></td><td style="text-align:right;"><strong>$total</strong></td></tr>
        </tbody>
    </table>
    <details style="margin-top:1rem;">
        <summary style="cursor:pointer;font-weight:700;">Pesi e soglie usati (clicca per espandere)</summary>
        <p style="font-size:0.85rem;margin-top:0.6rem;">I pesi non sono arbitrari: distinguono cio' che e' solo possibile (software presente) da cio' che e' avvenuto (sessione attiva). Sono definiti nel codice sorgente, verificabili e modificabili (licenza Apache 2.0).</p>
        <table class="data-table"><thead><tr><th style="text-align:right;">Punti</th><th>Motivazione del peso</th></tr></thead><tbody>$weightRows</tbody></table>
        <h3 style="margin-top:1rem;">Soglie di classificazione</h3>
        <table class="data-table"><thead><tr><th>Livello</th><th>Punteggio</th><th>Significato</th></tr></thead><tbody>$thrRows</tbody></table>
    </details>
</section>
"@
}

function Get-DVMethodologyHTML {
    <#
    .SYNOPSIS
        Dichiarazione di metodo e perimetro: cosa e' stato controllato, come, e cosa no.
    .DESCRIPTION
        Dichiarare per primi i limiti di una verifica e' cio' che la rende difendibile:
        toglie all'altra parte l'argomento "il report non dice di non aver potuto
        controllare X". Un controllo non eseguito viene elencato come non eseguito,
        mai omesso.
    #>
    param(
        [bool]$IsElevated = $true,
        [object]$SurveillanceCapabilities = $null,
        [object]$RulesInfo = $null,
        [string]$Version = ''
    )

    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }

    # Catalogo dei controlli. NeedsAdmin: il controllo (o il suo dettaglio) richiede
    # privilegi elevati; in tal caso senza amministratore l'esito e' dichiarato parziale.
    $catalog = @(
        @{ N = 'Porte in ascolto';                 Src = 'Get-NetTCPConnection -State Listen';                  Admin = $false; Limit = "Indica che il PC puo' accettare connessioni, non chi possa effettivamente raggiungerlo: dipende da firewall e segmentazione di rete." }
        @{ N = 'Attribuzione porta - processo';    Src = 'OwningProcess + Get-Process';                         Admin = $true;  Limit = "Il percorso dell'eseguibile di processi di altri utenti non e' leggibile senza privilegi elevati." }
        @{ N = 'Sessioni remote attive';           Src = 'Get-NetTCPConnection -State Established';             Admin = $false; Limit = "Fotografia dell'istante: una sessione chiusa prima della scansione non appare." }
        @{ N = 'Processi in esecuzione';           Src = 'Get-CimInstance Win32_Process / Get-Process';          Admin = $true;  Limit = 'Senza privilegi elevati percorso e riga di comando di processi di altri utenti restano vuoti.' }
        @{ N = 'Firma digitale (Authenticode)';    Src = 'Get-AuthenticodeSignature';                           Admin = $true;  Limit = "Richiede il percorso dell'eseguibile. Firma valida non significa uso autorizzato." }
        @{ N = 'Servizi di sistema';               Src = 'Get-Service / Win32_Service';                         Admin = $true;  Limit = 'Alcune proprieta dei servizi non sono leggibili da utente standard.' }
        @{ N = 'Software installato';              Src = 'Registro: HKLM/HKCU ...\Uninstall';                   Admin = $false; Limit = 'Un software installato senza passare dal registro (portable) non compare.' }
        @{ N = 'Programmi in avvio automatico';    Src = 'Registro: ...\CurrentVersion\Run, RunOnce';           Admin = $false; Limit = 'Non copre tutte le posizioni di avvio possibili (cartelle Startup, GPO).' }
        @{ N = 'Stato del firewall';               Src = 'Get-NetFirewallProfile';                              Admin = $false; Limit = 'In dominio la configurazione e spesso imposta centralmente.' }
        @{ N = 'Antivirus';                        Src = 'SecurityCenter2 / Win32 provider';                    Admin = $false; Limit = 'Lo stato riportato e quello dichiarato dal provider di sicurezza.' }
        @{ N = 'Cronologia microfono e webcam';    Src = 'Registro: CapabilityAccessManager\ConsentStore';      Admin = $false; Limit = "Copre l'utente corrente; alcune voci di sistema non sono determinabili. Un uso tramite driver che non passa dal ConsentStore non compare." }
        @{ N = 'Dispositivi audio/video virtuali'; Src = 'Get-PnpDevice, dispositivi audio';                    Admin = $false; Limit = 'Un PC senza webcam o scheda audio produce legittimamente un elenco vuoto.' }
        @{ N = 'Persistenza avanzata';             Src = 'WMI root\subscription, AppInit_DLLs, IFEO, Task';     Admin = $true;  Limit = 'Le sottoscrizioni WMI e alcune chiavi IFEO non sono leggibili da utente standard.' }
        @{ N = 'DLL da percorsi anomali';          Src = 'Get-Process -Module';                                 Admin = $true;  Limit = "Non rileva reflective loading / manual mapping: l'assenza di righe non dimostra l'assenza di iniezione." }
        @{ N = 'Registro eventi Sistema';          Src = 'Get-WinEvent -LogName System';                        Admin = $false; Limit = 'I registri ruotano: eventi piu vecchi possono essere stati sovrascritti.' }
        @{ N = 'Registro eventi Sicurezza';        Src = 'Get-WinEvent -LogName Security';                      Admin = $true;  Limit = 'Richiede obbligatoriamente privilegi di amministratore: contiene accessi RDP e cancellazioni del log.' }
        @{ N = 'Accessi Desktop remoto (registri operativi)'; Src = 'TerminalServices-RemoteConnectionManager/Operational (1149), TerminalServices-LocalSessionManager/Operational (21, 24, 25)'; Admin = $false; Limit = "Spesso leggibili senza privilegi elevati; se il canale non e' accessibile il report lo dichiara. Registra gli accessi Desktop remoto, non quelli effettuati con altri strumenti." }
        @{ N = 'Registro locale dello strumento (accessi passati)'; Src = 'winvnc.log, mslogon.log (sola lettura); registro eventi Applicazione'; Admin = $false; Limit = "Mostra le connessioni registrate dallo strumento, se il livello di registrazione le prevede. Un file assente, vuoto o senza righe riconosciute NON prova l'assenza di accessi. Il file e' modificabile: la sua integrita' non e' garantita. Dal file si estraggono solo ora, tipo di evento e indirizzo, mai nomi di persone." }
        @{ N = 'Configurazione accesso remoto';    Src = 'File di configurazione dello strumento (es. ultravnc.ini)'; Admin = $false; Limit = "Riflette il file presente sul disco: se l'impostazione UseRegistry e' attiva, i valori effettivi risiedono nel registro di Windows. Una modifica successiva alla scansione non e' rilevata." }
    )

    $rows = ''
    $notRun = 0
    foreach ($c in $catalog) {
        if ($c.Admin -and -not $IsElevated) {
            $esito = '<span class="badge badge-medium">PARZIALE</span>'
            $esitoNote = 'eseguito senza privilegi elevati: risultato incompleto per questa voce'
            $notRun++
        } else {
            $esito = '<span class="badge badge-low">ESEGUITO</span>'
            $esitoNote = if ($c.Admin) { 'eseguito con privilegi di amministratore' } else { 'non richiede privilegi elevati' }
        }
        $rows += "<tr><td>$(& $enc $c.N)</td><td><code style=`"font-size:0.8rem;`">$(& $enc $c.Src)</code></td><td>$esito<br><span style=`"font-size:0.78rem;opacity:0.75;`">$(& $enc $esitoNote)</span></td><td style=`"font-size:0.82rem;`">$(& $enc $c.Limit)</td></tr>`n"
    }

    $avRows = ''
    if ($SurveillanceCapabilities -and $SurveillanceCapabilities.Checks) {
        foreach ($chk in @($SurveillanceCapabilities.Checks)) {
            $st = [string]$chk.Status
            $cls = if ($st -eq 'OK') { 'badge-low' } else { 'badge-high' }
            $avRows += "<tr><td>$(& $enc $chk.Name)</td><td><span class=`"badge $cls`">$(& $enc $st)</span></td><td style=`"font-size:0.82rem;`">$(& $enc $chk.Detail)</td></tr>`n"
        }
    }
    $avSection = ''
    if ($avRows) {
        $avSection = @"
<h3 style="margin-top:1.2rem;">Esito tecnico dei singoli controlli audio/video</h3>
<p style="font-size:0.85rem;">Un controllo non completato significa che per quella categoria il risultato non e' affidabile: non va letto come &quot;nessun problema&quot;.</p>
<table class="data-table"><thead><tr><th>Controllo</th><th>Esito</th><th>Dettaglio tecnico</th></tr></thead><tbody>$avRows</tbody></table>
"@
    }

    # Attenzione: $RulesInfo e' una hashtable, quindi .Count restituirebbe il numero di
    # chiavi, non di regole. I campi corretti sono Loaded e SourceCount.
    $rulesLine = ''
    if ($RulesInfo) {
        if ($RulesInfo.UsedFallback) {
            $rulesLine = "<li><strong>Regole di rilevamento applicate:</strong> database interno di riserva (nessun file di regole esterno caricato).</li>"
        } else {
            $rulesLine = "<li><strong>Regole di rilevamento applicate:</strong> $([int]$RulesInfo.Loaded) regole caricate da $([int]$RulesInfo.SourceCount) file di dati in <code>core\rules</code> (non codificate nel programma: ispezionabili e modificabili).</li>"
        }
    }

    $elevLine = if ($IsElevated) {
        "<li><strong>Privilegi:</strong> la scansione e' stata eseguita con privilegi di amministratore. Tutti i controlli previsti erano disponibili.</li>"
    } else {
        "<li><strong>Privilegi:</strong> la scansione e' stata eseguita come utente standard. <strong>$notRun controlli su $($catalog.Count)</strong> hanno prodotto un risultato parziale. Per un esito completo la scansione va ripetuta come amministratore: questo report resta valido per quanto rilevato, ma il perimetro ridotto va dichiarato in ogni sede.</li>"
    }

    return @"
<section class="card">
    <h2>&#x1F9EA; METODO E PERIMETRO DELLA VERIFICA</h2>
    <p style="font-size:0.9rem;">Questa sezione dichiara <strong>cosa e' stato controllato, con quale comando e con quali limiti</strong>. Serve a rendere la verifica ripetibile da un tecnico terzo e a dichiarare per primi cio' che non e' stato possibile accertare.</p>
    <ul style="font-size:0.88rem;line-height:1.6;">
        <li><strong>Natura dell'accertamento:</strong> lettura non invasiva dello stato del sistema. Il programma non installa nulla, non modifica configurazioni e <strong>non trasmette dati in rete</strong>: l'eventuale invio di richieste resta un atto dell'interessato.</li>
        <li><strong>Strumento:</strong> DigitalValut Controller $(& $enc $Version), software libero con codice sorgente pubblico (licenza Apache 2.0). Metodo e soglie sono ispezionabili da chiunque.</li>
        $elevLine
        $rulesLine
        <li><strong>Natura del risultato:</strong> segnalazione tecnica di primo livello. <strong>Non e' una perizia informatica forense</strong> e non ha di per se' valore di prova: una verifica con piena spendibilita' probatoria richiede acquisizione eseguita da un perito qualificato.</li>
    </ul>
    <h3 style="margin-top:1.2rem;">Catalogo dei controlli</h3>
    <table class="data-table">
        <thead><tr><th>Controllo</th><th>Fonte tecnica</th><th>Esito</th><th>Limite dichiarato</th></tr></thead>
        <tbody>$rows</tbody>
    </table>
    $avSection
</section>
"@
}

function New-DVReportHTML {
    param(
        [hashtable]$SystemInfo,
        [hashtable]$ThreatScore,
        [object]$PortAnalysis,
        [object]$ServiceAnalysis,
        [object]$SoftwareAnalysis,
        [object]$FirewallStatus,
        [object]$ExternalConnections = @(),
        [object]$StartupPrograms = @(),
        [object]$AntivirusStatus = @(),
        [object]$ActiveRemoteConnections = @(),
        [object]$Capabilities = $null,
        [object]$SurveillanceCapabilities = $null,
        [object]$ProcessAnalysis = $null,
        [object]$PersistenceFindings = $null,
        [object]$ScanDiff = $null,
        [object]$OllamaExplanation = $null,
        [object]$ModuleFindings = $null,
        [object]$EventLogFindings = $null,
        [object]$RulesInfo = $null,
        [object]$RemoteToolConfig = $null,
        [object]$UltraVncLog = $null,
        [object]$SentinelSummary = $null,
        [string]$ControllerRoot,
        [string]$OutputPath,
        [string]$JsonData = "",
        [string]$ContentHash = "",
        [bool]$IsElevated = $true,
        [string]$AdminGroupMember = 'Indeterminato'
    )

    $cssContent = ""
    $cssPath = Join-Path $ControllerRoot "templates\assets\styles.css"
    if ($ControllerRoot -and (Test-Path $cssPath)) {
        $cssContent = "<style>`n" + [System.IO.File]::ReadAllText($cssPath) + "`n</style>"
    } else {
        $cssContent = "<link rel=`"stylesheet`" href=`"assets/styles.css`">"
    }

    $level = $ThreatScore.Level
    $titleEmoji = switch ($level.Class) {
        "critical" { "&#x1F534;" }
        "high"     { "&#x1F7E0;" }
        "medium"   { "&#x1F7E1;" }
        "low"      { "&#x1F7E2;" }
        default    { "&#x2705;" }
    }

    $findingsHtml = ""
    foreach ($f in $ThreatScore.Findings) {
        $findingsHtml += "<li class=`"finding-item`">$([System.Net.WebUtility]::HtmlEncode($f))</li>`n"
    }
    if ([string]::IsNullOrEmpty($findingsHtml)) {
        $findingsHtml = "<li class=`"finding-item safe`">Nessun elemento sospetto rilevato.</li>"
    }

    $portsHtml = ""
    $suspiciousPorts = @()
    if ($PortAnalysis -and $PortAnalysis.SuspiciousPorts) { $suspiciousPorts = $PortAnalysis.SuspiciousPorts }
    foreach ($p in $suspiciousPorts) {
        $riskClass = ($p.Risk -replace ' ','').ToLower()
        $ownerCell = if ($p.OwnerProcessName) {
            "$([System.Net.WebUtility]::HtmlEncode([string]$p.OwnerProcessName)) (PID $($p.OwnerProcessId))"
        } elseif ($p.OwnerProcessId) {
            "PID $($p.OwnerProcessId) <span style=`"font-size:0.78rem;opacity:0.75;`">(nome non leggibile senza privilegi elevati)</span>"
        } else { "<span style=`"opacity:0.6;`">non determinato</span>" }
        $ownerPathCell = if ($p.OwnerPath) {
            "<br><span style=`"font-size:0.78rem;opacity:0.75;`"><code>$([System.Net.WebUtility]::HtmlEncode([string]$p.OwnerPath))</code></span>"
        } else { "" }
        $portsHtml += "<tr><td>$($p.Port)</td><td>$($p.Name)</td><td>$ownerCell$ownerPathCell</td><td><span class=`"badge badge-$riskClass`">$($p.Risk)</span></td><td>$([System.Net.WebUtility]::HtmlEncode($p.Description))</td></tr>`n"
    }
    if ([string]::IsNullOrEmpty($portsHtml)) { $portsHtml = "<tr><td colspan=`"5`" style=`"text-align:center;color:#7eb8e8;`">Nessuna porta sospetta in ascolto.</td></tr>" }

    $allProcs = @()
    if ($ProcessAnalysis) {
        $allProcs = @($ProcessAnalysis.RemoteControl) + @($ProcessAnalysis.Spyware) + @($ProcessAnalysis.EmployeeMonitor) + @($ProcessAnalysis.OtherSuspicious)
    }
    $groupedProcs = $allProcs | Group-Object -Property { if ($_.ProcessName) { $_.ProcessName } else { $_.Name } }
    $processHtml = ""
    foreach ($grp in $groupedProcs) {
        $first = $grp.Group[0]
        $riskClass = ($first.Risk -replace ' ','').ToLower()
        $procName = if ($first.ProcessName) { $first.ProcessName } else { $first.Name }
        $countStr = if ($grp.Count -gt 1) { " (x$($grp.Count))" } else { "" }
        $pids = ($grp.Group | ForEach-Object { $_.ProcessId }) -join ", "
        $path = $first.Path
        if (-not $path) { $path = "-" }
        $pathDisplay = $path
        if ($pathDisplay.Length -gt 60) { $pathDisplay = $pathDisplay.Substring(0, 57) + "..." }
        $mem = if ($first.MemoryMB) { "$($first.MemoryMB) MB" } else { "-" }
        if ($grp.Count -gt 1) {
            $totalMem = ($grp.Group | ForEach-Object { $_.MemoryMB } | Where-Object { $_ } | Measure-Object -Sum).Sum
            if ($totalMem) { $mem = "$([math]::Round($totalMem, 2)) MB (tot)" }
        }
        $sigStatus = $first.SignatureStatus
        $sigBadge = switch ($sigStatus) {
            "Valid"        { "<span class=`"badge badge-low`">Firmato</span>" }
            "Inaccessible" { "<span title=`"File non raggiungibile per la verifica`">N/D</span>" }
            $null          { "<span title=`"Verifica non eseguita`">N/D</span>" }
            default        { "<span class=`"badge badge-critical`" title=`"$([System.Net.WebUtility]::HtmlEncode([string]$sigStatus))`">Non firmato</span>" }
        }
        if ($first.SignerSubject) { $sigBadge += " <small title=`"$([System.Net.WebUtility]::HtmlEncode($first.SignerSubject))`">&#x2139;&#xFE0F;</small>" }
        $processHtml += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($procName))$countStr</td><td>$pids</td><td title=`"$([System.Net.WebUtility]::HtmlEncode($path))`">$([System.Net.WebUtility]::HtmlEncode($pathDisplay))</td><td>$mem</td><td><span class=`"badge badge-$riskClass`">$($first.Risk)</span></td><td>$($first.Type)</td><td>$sigBadge</td></tr>`n"
    }
    if ([string]::IsNullOrEmpty($processHtml)) { $processHtml = "<tr><td colspan=`"7`" style=`"text-align:center;color:#7eb8e8;`">Nessun processo sospetto rilevato.</td></tr>" }

    $servicesHtml = ""
    $services = @($ServiceAnalysis)
    if ($services.Count -eq 0) {
        $servicesHtml = "<tr><td colspan=`"3`" style=`"text-align:center;color:#7eb8e8;`">Nessun servizio sospetto rilevato.</td></tr>"
    } else {
        foreach ($svc in $services) {
            $riskClass = ($svc.Risk -replace ' ','').ToLower()
            $svcName = if ($svc.DisplayName) { $svc.DisplayName } else { $svc.ServiceName }
            $servicesHtml += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($svcName))</td><td><span class=`"badge badge-$riskClass`">$($svc.Risk)</span></td><td>$($svc.Status)</td></tr>`n"
        }
    }

    $fwRows = ""
    if ($FirewallStatus) {
        $profiles = @(
            @{ N = "Domain";  V = $FirewallStatus.DomainProfile }
            @{ N = "Private"; V = $FirewallStatus.PrivateProfile }
            @{ N = "Public";  V = $FirewallStatus.PublicProfile }
        )
        foreach ($pr in $profiles) {
            $badge = if ($pr.V) { "<span class=`"badge badge-low`">ATTIVO</span>" } else { "<span class=`"badge badge-critical`">DISATTIVO</span>" }
            $fwRows += "<tr><td>$($pr.N)</td><td>$badge</td><td>Block</td><td>Allow</td></tr>`n"
        }
    }
    if ([string]::IsNullOrEmpty($fwRows)) { $fwRows = "<tr><td colspan=`"4`">Dati non disponibili.</td></tr>" }

    $extConnHtml = ""
    $extConns = @($ExternalConnections)
    if ($extConns.Count -eq 0) {
        $extConnHtml = "<tr><td colspan=`"4`" style=`"text-align:center;color:#7eb8e8;`">Nessuna connessione esterna attiva.</td></tr>"
    } else {
        foreach ($c in $extConns) {
            $extConnHtml += "<tr><td>$($c.RemoteIP)</td><td>$($c.RemotePort)</td><td>$($c.Process)</td><td>$($c.PID)</td></tr>`n"
        }
    }

    $softwareHtml = ""
    $softwareList = @($SoftwareAnalysis)
    if ($softwareList.Count -eq 0) {
        $softwareHtml = "<tr><td colspan=`"4`" style=`"text-align:center;color:#7eb8e8;`">Nessun software di controllo remoto rilevato tra gli installati.</td></tr>"
    } else {
        foreach ($s in $softwareList) {
            $ver = if ($s.DisplayVersion) { $s.DisplayVersion } else { "-" }
            $pub = if ($s.Publisher) { $s.Publisher } else { "-" }
            $softwareHtml += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($s.DisplayName))</td><td>$ver</td><td>$([System.Net.WebUtility]::HtmlEncode($pub))</td><td>$($s.Risk)</td></tr>`n"
        }
    }

    $startupHtml = ""
    $startupList = @($StartupPrograms)
    if ($startupList.Count -eq 0) {
        $startupHtml = "<tr><td colspan=`"4`" style=`"text-align:center;color:#7eb8e8;`">Nessuna voce di avvio automatico rilevata.</td></tr>"
    } else {
        foreach ($s in $startupList) {
            $cmdShort = $s.Command
            if ($cmdShort.Length -gt 80) { $cmdShort = $cmdShort.Substring(0, 77) + "..." }
            $susBadge = if ($s.Suspicious) { "<span class=`"badge badge-high`">Sospetto</span>" } else { "-" }
            $startupHtml += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($s.Name))</td><td title=`"$([System.Net.WebUtility]::HtmlEncode($s.Command))`">$([System.Net.WebUtility]::HtmlEncode($cmdShort))</td><td>$($s.Location)</td><td>$susBadge</td></tr>`n"
        }
    }

    $avHtml = ""
    $avList = @($AntivirusStatus)
    if ($avList.Count -eq 0) {
        $avHtml = "<tr><td colspan=`"4`" style=`"text-align:center;color:#7eb8e8;`">Stato antivirus non disponibile.</td></tr>"
    } else {
        foreach ($a in $avList) {
            $enBadge = if ($a.Enabled) { "<span class=`"badge badge-low`">Attivo</span>" } else { "<span class=`"badge badge-critical`">Disattivo</span>" }
            $upBadge = if ($a.UpToDate) { "<span class=`"badge badge-low`">Aggiornato</span>" } else { "<span class=`"badge badge-medium`">Non aggiornato</span>" }
            $avHtml += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($a.Name))</td><td>$enBadge</td><td>$upBadge</td><td>$([System.Net.WebUtility]::HtmlEncode($a.Path))</td></tr>`n"
        }
    }

    $legalHtml = Get-DVLegalSectionHTML

    $activeConnHtml = ""
    $activeConns = @($ActiveRemoteConnections)
    if ($activeConns.Count -eq 0) {
        $activeConnHtml = "<tr><td colspan=`"6`" style=`"text-align:center;color:#7eb8e8;`">Nessuna connessione remota attiva in questo momento.</td></tr>"
    } else {
        foreach ($ac in $activeConns) {
            $r = if ($ac.Rischio) { $ac.Rischio.ToUpper() } else { "ALTO" }
            $riskClass = if ($r -eq "CRITICO") { "critical" } elseif ($r -eq "ALTO") { "high" } elseif ($r -eq "BASSO") { "low" } else { "medium" }
            $activeConnHtml += "<tr><td>$($ac.IPRemoto)</td><td>$([System.Net.WebUtility]::HtmlEncode($ac.HostRemoto))</td><td>$($ac.PortaLocale)</td><td>$($ac.Processo)</td><td>$($ac.PID)</td><td><span class=`"badge badge-$riskClass`">$([System.Net.WebUtility]::HtmlEncode($ac.Stato))</span></td></tr>`n"
        }
    }

    $capabilityHtml = ""
    if (-not $Capabilities -and $ThreatScore.Score -ge 50) {
        $Capabilities = @{ PuoVedereLOSchermo = $true; PuoUsareMouseTastiera = $true; PuoLeggereFile = $true; PuoVedereClipboard = $true }
    }
    if ($Capabilities) {
        $caps = @(
            @{ Icon = "&#x1F441;&#xFE0F;"; Label = "VEDERE IL TUO SCHERMO"; Detail = "In tempo reale, tutto cio' che fai"; Active = $Capabilities.PuoVedereLOSchermo }
            @{ Icon = "&#x1F5B1;&#xFE0F;"; Label = "CONTROLLARE MOUSE E TASTIERA"; Detail = "Possono operare sul tuo PC"; Active = $Capabilities.PuoUsareMouseTastiera }
            @{ Icon = "&#x1F4E7;"; Label = "LEGGERE LE TUE EMAIL"; Detail = "Email, PEC, messaggi aperti"; Active = $Capabilities.PuoLeggereFile }
            @{ Icon = "&#x1F4C1;"; Label = "ACCEDERE AI TUOI FILE"; Detail = "Documenti, cartelle, dati sanitari"; Active = $Capabilities.PuoLeggereFile }
            @{ Icon = "&#x1F4CB;"; Label = "VEDERE APPUNTI COPIATI"; Detail = "Tutto cio' che copi/incolli"; Active = $Capabilities.PuoVedereClipboard }
        )
        foreach ($c in $caps) {
            $cls = if ($c.Active) { "capability active" } else { "capability" }
            $capabilityHtml += "<div class=`"$cls`"><span class=`"icon`">$($c.Icon)</span><span class=`"label`">$($c.Label)</span><span class=`"detail`">$($c.Detail)</span></div>`n"
        }
    }

    $cosaFareHtml = @"
<div class="step"><div class="step-number">1</div><div class="step-content"><h3>CONSERVA QUESTO REPORT</h3><p>Salva il file HTML e stampalo. E' una <strong>segnalazione tecnica documentata</strong> con data, ora e hash SHA-256 di verifica: utile a supportare una richiesta al DPO o una successiva analisi forense. <strong>Non sostituisce una perizia informatica forense</strong> e non ha di per se' valore di prova legale.</p></div></div>
<div class="step"><div class="step-number">2</div><div class="step-content"><h3>NON MODIFICARE NULLA SUL PC</h3><p>Non disinstallare software, non cambiare impostazioni. Se intendi far valere quanto rilevato, rivolgiti a un perito informatico forense: solo un'acquisizione forense eseguita da un tecnico qualificato ha piena spendibilita' probatoria.</p></div></div>
<div class="step"><div class="step-number">3</div><div class="step-content"><h3>RICHIEDI INFORMAZIONI AL DPO</h3><p>Invia una <strong>richiesta scritta</strong> (PEC o raccomandata) al Data Protection Officer chiedendo: copia dell'informativa, base giuridica, accordo sindacale o autorizzazione INL, elenco soggetti autorizzati.</p></div></div>
<div class="step"><div class="step-number">4</div><div class="step-content"><h3>CONTATTA IL SINDACATO</h3><p>RSU, RSA o sindacato di categoria. L'Art. 4 prevede accordo sindacale PRIMA dell'installazione.</p></div></div>
<div class="step"><div class="step-number">5</div><div class="step-content"><h3>SEGNALA AL GARANTE PRIVACY</h3><p>Se non ottieni risposte, puoi segnalare al <a href=`"https://www.garanteprivacy.it`" target=`"_blank`">Garante per la Protezione dei Dati Personali</a>.</p></div></div>
"@

    $reportHash = if ($ContentHash) { $ContentHash.Substring(0, [Math]::Min(16, $ContentHash.Length)) } else { "N/D" }
    $reportDate = $SystemInfo.ScanDate
    $pcName = $SystemInfo.ComputerName

    # Elenco dei fatti rilevati: la lettera deve riportare solo cio' che la scansione
    # ha effettivamente accertato, con il riferimento della riga nella tabella di calcolo.
    # Affermazioni che il programma non puo' verificare (categorie di dati trattati,
    # mancata consegna dell'informativa) restano segnaposto da compilare a cura
    # dell'interessato: un'affermazione non verificabile indebolisce l'intera richiesta.
    $dpoFactsHtml = ""
    foreach ($e in @($ThreatScore.Evidence)) {
        if ([string]$e.Severity -eq 'INFO') { continue }
        $dpoFactsHtml += "<li>$([System.Net.WebUtility]::HtmlEncode([string]$e.Finding)) (rif. $([string]$e.Id), stato: $([System.Net.WebUtility]::HtmlEncode([string]$e.State)));</li>`n"
    }
    if (-not $dpoFactsHtml) {
        $dpoFactsHtml = "<li>[nessun indicatore rilevato dalla scansione: indicare qui il motivo della richiesta];</li>"
    }
    $elevationClause = if ($IsElevated) {
        "La scansione e' stata eseguita con privilegi di amministratore."
    } else {
        "La scansione e' stata eseguita come utente standard: per alcune categorie di controllo il risultato e' parziale, come dichiarato nel report."
    }

    # Clausole aggiuntive per chi non dispone di privilegi amministrativi: sono fatti
    # rilevanti, non limiti da nascondere.
    $nonAdminClauses = ''
    if (-not $IsElevated -and $AdminGroupMember -ne 'No') {
        # Non elevato, ma l'account e' (o potrebbe essere) membro del gruppo Amministratori:
        # NON si afferma di non avere privilegi. Dichiararlo senza esserne certi sarebbe
        # una affermazione falsa in una richiesta formale.
        $nonAdminClauses = "<li>[DA COMPLETARE PRIMA DELL'INVIO - se, e solo se, e' vero: lo scrivente non dispone di privilegi amministrativi sulla postazione assegnata. Il programma non ha potuto escluderlo: il suo account risulta $(if ($AdminGroupMember -eq 'Si') { 'membro del gruppo Amministratori (con token ridotto dal Controllo account utente)' } else { 'di appartenenza non determinabile' }). Se e' amministratore, ripeta la scansione con 'Esegui come amministratore' e cancelli questa riga];</li>`n"
    }
    if (-not $IsElevated -and $AdminGroupMember -eq 'No') {
        $nonAdminClauses = @"
<li>Lo scrivente <strong>non dispone di privilegi amministrativi</strong> sulla postazione assegnata: non ha quindi la possibilita' tecnica di installare, configurare, modificare o disattivare gli strumenti sopra indicati, ne' di consultare il registro di sicurezza del sistema che documenta gli accessi effettuati;</li>
<li>Il dato relativo agli accessi remoti effettuati sulla postazione risulta pertanto nella <strong>disponibilita' esclusiva del titolare del trattamento</strong>, unico soggetto in grado di produrlo;</li>
"@
    }

    # Esito della configurazione dello strumento, se letto: e' il punto piu' rilevante
    # per distinguere un'assistenza richiesta da un accesso silenzioso.
    # Esito del registro dello strumento: e' il dato che mostra l'uso effettivo.
    $logClause = ''
    if ($UltraVncLog -and [int]$UltraVncLog.RemoteConnectionCount -gt 0) {
        $la = @($UltraVncLog.DistinctRemoteAddresses | Select-Object -First 10)
        $logPeriod = if ($UltraVncLog.FirstSeenText -and $UltraVncLog.LastSeenText) { ", registrate tra il $($UltraVncLog.FirstSeenText) e il $($UltraVncLog.LastSeenText)" } else { '' }
        $logClause = "<li>Dalla lettura del registro locale dello strumento risultano <strong>$([int]$UltraVncLog.RemoteSessionCount) sessioni da $(@($UltraVncLog.DistinctRemoteAddresses).Count) indirizzi non locali</strong> ($([System.Net.WebUtility]::HtmlEncode(($la -join ', '))))$([System.Net.WebUtility]::HtmlEncode($logPeriod)); si chiede di indicare a quali soggetti appartengano tali indirizzi, con quale finalita' e in forza di quale autorizzazione siano state effettuate;</li>`n"
    }
    $configClause = ''
    if ($RemoteToolConfig -and $RemoteToolConfig.UltraVNC -and $RemoteToolConfig.UltraVNC.Found -and $RemoteToolConfig.UltraVNC.Consent) {
        $co = $RemoteToolConfig.UltraVNC.Consent
        $configClause = "<li>Dalla lettura del file di configurazione dello strumento risulta, quanto alla richiesta di consenso all'utente prima di una connessione remota: <strong>$([System.Net.WebUtility]::HtmlEncode([string]$co.Outcome))</strong>. Motivazione tecnica: $([System.Net.WebUtility]::HtmlEncode([string]$co.Reason))</li>`n"
    }
    $dpoLetterHtml = @"
<div class="template-text" id="dpo-request">
<p>Spett.le<br>Data Protection Officer<br>[Nome dell'Ente]<br>PEC: [indirizzo PEC DPO]</p>
<p><strong>OGGETTO: Richiesta informazioni ex Art. 15 GDPR - Software controllo remoto</strong></p>
<p>Il/La sottoscritto/a [NOME COGNOME], dipendente presso [DIPARTIMENTO], in servizio presso la postazione PC identificata come <strong>$([System.Net.WebUtility]::HtmlEncode($pcName))</strong>,</p>
<p><strong>PREMESSO CHE</strong></p>
<ul>
<li>In data $reportDate ho effettuato sulla postazione assegnatami una verifica tecnica non invasiva, con strumento a codice sorgente aperto, che ha prodotto i seguenti rilievi:</li>
</ul>
<ul>
$dpoFactsHtml</ul>
<ul>
$configClause$logClause<li>$elevationClause I rilievi sopra elencati sono constatazioni tecniche: non costituiscono accertamento di illiceita', che non spetta allo scrivente;</li>
$nonAdminClauses
<li>Non risulta allo scrivente di aver ricevuto informativa specifica relativa a tali strumenti; ove essa esista, si chiede cortesemente di indicarne gli estremi;</li>
<li>Nell'esercizio delle mie funzioni tratto le seguenti categorie di dati: [INDICARE: es. dati personali di utenti, dati relativi alla salute ex Art. 9 GDPR, corrispondenza istituzionale, atti amministrativi] e utilizzo i seguenti strumenti: [INDICARE: es. casella PEC, applicativi gestionali];</li>
</ul>
<p><strong>CHIEDE</strong></p>
<ol>
<li>Copia dell'informativa ex Art. 13 GDPR relativa agli strumenti di accesso remoto presenti sulla postazione;</li>
<li>Indicazione della base giuridica del trattamento (Art. 6 GDPR) e della finalita' perseguita;</li>
<li>Copia dell'accordo collettivo ex Art. 4, comma 1, L. 300/1970 oppure dell'autorizzazione rilasciata dalla sede territoriale competente, ovvero indicazione delle ragioni per cui tali atti non sarebbero necessari;</li>
<li>Elenco dei soggetti autorizzati all'accesso remoto alla postazione e titolo della loro autorizzazione (designazione ex Art. 29 GDPR o atto equivalente);</li>
<li>Registro o log degli accessi remoti effettuati sulla postazione indicata, con data, ora, operatore e finalita';</li>
<li>Indicazione se il trattamento sia stato oggetto di valutazione d'impatto ex Art. 35 GDPR e, in caso affermativo, i relativi esiti;</li>
<li>Indicazione dei tempi di conservazione dei dati raccolti tramite tali strumenti;</li>
<li>Indicazione se la configurazione in uso preveda la visualizzazione di un avviso o la richiesta di consenso all'utente prima dell'instaurazione di una sessione remota e, in caso negativo, delle ragioni di tale scelta;</li>
<li>Indicazione dei soggetti titolari dei privilegi amministrativi sulla postazione e dell'atto con cui tali privilegi sono stati attribuiti.</li>
</ol>
<p>Si allega il report tecnico completo, comprensivo della dichiarazione di metodo, del perimetro della verifica e dei limiti dichiarati (impronta SHA-256: <code>$reportHash</code>).</p>
<p>La presente istanza e' proposta al solo fine di esercitare il diritto di accesso ai sensi dell'Art. 15 GDPR e non contiene addebiti di sorta.</p>
<p>Ai sensi dell'Art. 12, par. 3 GDPR, si richiede riscontro senza ingiustificato ritardo e comunque entro un mese dal ricevimento (prorogabile di due mesi con comunicazione motivata).</p>
<p>Distinti saluti.</p>
<p>[Luogo], [Data]<br>[Firma]</p>
</div>
<button type="button" onclick="var t=document.getElementById('dpo-request');var s=document.createElement('textarea');s.value=t.innerText;document.body.appendChild(s);s.select();document.execCommand('copy');document.body.removeChild(s);alert('Testo copiato negli appunti.');" class="btn btn-primary no-print">&#x1F4CB; Copia Testo</button>
"@

    $alertBox = ""
    if ($ThreatScore.Score -ge 50) {
        $alertBox = @"
<div class="alert alert-danger">
    <div class="alert-icon">&#x26A0;&#xFE0F;</div>
    <div class="alert-content">
        <strong>DA VERIFICARE</strong>
        <p>Strumenti di questo tipo, se usati, permettono a chi li gestisce di vedere il tuo schermo, controllare mouse e tastiera, leggere email e PEC, accedere ai dati sanitari. <strong>La presenza di questi strumenti non e' di per se' irregolare</strong>: lo diventa se manca la base giuridica, l'informativa (GDPR Art. 13) o l'accordo/autorizzazione previsti dall'Art. 4 Statuto dei Lavoratori. Chiedi al DPO e al CED se sono autorizzati.</p>
    </div>
</div>
"@
    }

    $elevationBox = ""
    if (-not $IsElevated) {
        $elevationBox = @"
<div class="alert alert-danger">
    <div class="alert-icon">&#x1F512;</div>
    <div class="alert-content">
        <strong>SCANSIONE ESEGUITA SENZA PRIVILEGI DI AMMINISTRATORE</strong>
        <p>Alcune informazioni (servizi di sistema, percorsi completi dei processi, alcune connessioni di rete) potrebbero non essere visibili o essere incomplete. Per una scansione completa, riavvia con &quot;Esegui come amministratore&quot;. Questo report resta comunque valido per quanto rilevato, ma va dichiarato che non e' stato eseguito con privilegi elevati.</p>
    </div>
</div>
"@
    }

    $infoGrid = ""
    $infoItems = @(
        @{ L = "Computer"; V = $SystemInfo.ComputerName }
        @{ L = "Utente"; V = $SystemInfo.UserName }
        @{ L = "Dominio"; V = $SystemInfo.Domain }
        @{ L = "Sistema Operativo"; V = $SystemInfo.OSVersion }
        @{ L = "Architettura"; V = $SystemInfo.Architecture }
        @{ L = "Indirizzo IP"; V = $SystemInfo.IPAddress }
        @{ L = "Fuso Orario"; V = $SystemInfo.TimeZone }
        @{ L = "Ultimo Avvio"; V = $SystemInfo.LastBoot }
    )
    foreach ($item in $infoItems) {
        $val = if ($item.V) { $item.V } else { "-" }
        $infoGrid += "<div class=`"info-item`"><span class=`"info-label`">$($item.L)</span><span class=`"info-value`">$([System.Net.WebUtility]::HtmlEncode($val))</span></div>`n"
    }

    $actionButtons = @"
<div class="action-buttons no-print">
    <button type="button" onclick="window.print()" class="btn btn-primary">&#x1F5A8;&#xFE0F; Stampa Report</button>
    <button type="button" onclick="var a=document.createElement('a');a.href=location.href;a.download=document.title.replace(/\\s/g,'_')+'.html';a.click();" class="btn btn-secondary">&#x1F4BE; Salva Copia</button>
</div>
"@

    $jsonSection = ""
    if ($JsonData) {
        $jsonEscaped = [System.Net.WebUtility]::HtmlEncode($JsonData)
        $jsonSection = @"
<details class="card">
    <summary style="cursor:pointer;color:var(--primary);">&#x1F4CA; Dati Grezzi (JSON) - Clicca per espandere</summary>
    <pre style="margin-top:1rem;background:#0a0a1a;padding:1rem;border-radius:10px;overflow-x:auto;font-size:0.8rem;white-space:pre-wrap;">$jsonEscaped</pre>
</details>
"@
    }

    $cfg = $Global:DVConfig

    # Costruite qui, e non prima, perche' hanno bisogno di $cfg (numero di versione).
    $scoreTableHtml = Get-DVScoreTableHTML -ThreatScore $ThreatScore -Model ([string]$ThreatScore.Model)
    $methodologyHtml = Get-DVMethodologyHTML -IsElevated $IsElevated `
        -SurveillanceCapabilities $SurveillanceCapabilities -RulesInfo $RulesInfo -Version ([string]$cfg.Version)
    $remoteConfigHtml = Get-DVRemoteConfigHTML -RemoteToolConfig $RemoteToolConfig
    $ultraVncLogHtml = Get-DVUltraVncLogHTML -UltraVncLog $UltraVncLog
    $nonAdminHtml = if ($IsElevated) { '' }
        elseif ($AdminGroupMember -eq 'No') { Get-DVNonAdminGuidanceHTML -EventLogFindings $EventLogFindings }
        else {
            "<section class=`"card`"><h2>&#x1F511; SCANSIONE NON ELEVATA</h2><p style=`"font-size:0.9rem;`">La scansione e' stata eseguita senza elevazione, ma il programma <strong>non ha potuto stabilire che l'utente sia privo di privilegi amministrativi</strong> (account $(if ($AdminGroupMember -eq 'Si') { 'membro del gruppo Amministratori, con token ridotto dal Controllo account utente' } else { 'di appartenenza non determinabile' })). Per questo il report <strong>non afferma</strong> che l'installazione o la configurazione degli strumenti non siano riconducibili all'utente: tale affermazione va resa solo se vera. Per una scansione completa riavviare con &quot;Esegui come amministratore&quot;.</p></section>"
        }
    $copyrightHtml = "&copy; 2024-2026 Digital Valut APS (CF 90036980846) - Licenza Apache 2.0."

    $capabilitySection = ""
    if ($capabilityHtml) {
        $capabilitySection = @"
<section class="card danger-card">
    <h2>&#x26A0;&#xFE0F; COSA PERMETTONO QUESTI STRUMENTI</h2>
    <div class="capability-grid">$capabilityHtml</div>
    <div class="warning-box">
        <strong>&#x2139;&#xFE0F; QUANDO E' LEGITTIMO E QUANDO NO</strong>
        <p>Un software di controllo remoto puo' essere legittimo (assistenza tecnica) se e' previsto da informativa, base giuridica e, quando serve, accordo sindacale o autorizzazione (Art. 4 L. 300/1970; Art. 5, 6, 13 GDPR; Art. 114 Codice Privacy). Se non risulta nulla di cio', chiedi spiegazioni formali: per generare le richieste con scadenze usa AVVIA_RICHIESTE.bat. Questo report non accerta violazioni.</p>
    </div>
</section>
"@
    }

    $surveillanceSection = ""
    if ($SurveillanceCapabilities) {
        $sv = $SurveillanceCapabilities
        $avRisk = $sv.OverallAudioVideoRisk
        $avScore = if ($avRisk.Score) { $avRisk.Score } else { 0 }
        $avLevel = if ($avRisk.Level) { $avRisk.Level } else { "N/A" }
        $avSummary = if ($avRisk.Summary) { [System.Net.WebUtility]::HtmlEncode($avRisk.Summary) } else { "" }
        $survFindingsHtml = ""
        if ($sv.SurveillanceFindings -and @($sv.SurveillanceFindings).Count -gt 0) {
            foreach ($f in $sv.SurveillanceFindings) {
                $survFindingsHtml += "<li class=`"finding-item`">$([System.Net.WebUtility]::HtmlEncode($f))</li>`n"
            }
        } else {
            $survFindingsHtml = "<li class=`"finding-item safe`">Nessun indicatore di sorveglianza audio/video.</li>"
        }
        $checksHtml = ""
        foreach ($ck in @($sv.Checks)) {
            if (-not $ck) { continue }
            $ckClass = if ($ck.Status -eq "OK") { "low" } else { "high" }
            $checksHtml += "<tr><td>$([System.Net.WebUtility]::HtmlEncode([string]$ck.Name))</td><td><span class=`"badge badge-$ckClass`">$([System.Net.WebUtility]::HtmlEncode([string]$ck.Status))</span></td><td>$([System.Net.WebUtility]::HtmlEncode([string]$ck.Detail))</td></tr>`n"
        }
        if (-not $checksHtml) { $checksHtml = "<tr><td colspan=`"3`" style=`"text-align:center;color:#7eb8e8;`">Esito dei controlli non disponibile.</td></tr>" }
        $micInUse = if ($sv.Microphone.CurrentlyInUse) { "Sì" } else { "No" }
        $micPerm = if ($null -eq $sv.Microphone.PermissionEnabled) { "non determinabile" } elseif ($sv.Microphone.PermissionEnabled) { "Attivato" } else { "Disattivato" }
        $micProcs = @($sv.Microphone.ActiveProcesses)
        $micProcsHtml = ""
        foreach ($p in $micProcs) {
            $susBadge = if ($p.Suspicious) { " <span class=`"badge badge-high`">Da verificare</span>" } else { "" }
            $micProcsHtml += "<tr><td>$($p.ProcessName)</td><td>$($p.PID)</td><td>$([System.Net.WebUtility]::HtmlEncode($p.Path))</td><td>$(if ($p.StartTime) { $p.StartTime } else { $p.LastUsedStart })</td><td>$susBadge</td></tr>`n"
        }
        if (-not $micProcsHtml) { $micProcsHtml = "<tr><td colspan=`"5`" style=`"text-align:center;color:#7eb8e8;`">Nessuna applicazione risulta usare il microfono in questo momento.</td></tr>" }
        $webcamInUse = if ($sv.Webcam.CurrentlyInUse) { "Sì" } else { "No" }
        $webcamPerm = if ($null -eq $sv.Webcam.PermissionEnabled) { "non determinabile" } elseif ($sv.Webcam.PermissionEnabled) { "Attivato" } else { "Disattivato" }
        $webcamProcs = @($sv.Webcam.ActiveProcesses)
        $webcamProcsHtml = ""
        foreach ($p in $webcamProcs) {
            $susBadge = if ($p.Suspicious) { " <span class=`"badge badge-high`">Da verificare</span>" } else { "" }
            $webcamProcsHtml += "<tr><td>$($p.ProcessName)</td><td>$($p.PID)</td><td>$susBadge</td></tr>`n"
        }
        if (-not $webcamProcsHtml) { $webcamProcsHtml = "<tr><td colspan=`"3`" style=`"text-align:center;color:#7eb8e8;`">Nessuna applicazione risulta usare la webcam in questo momento.</td></tr>" }
        $virtualAudioHtml = ""
        foreach ($d in @($sv.VirtualAudioDevices)) {
            $virtualAudioHtml += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($d.DeviceName))</td><td>$($d.Status)</td><td><span class=`"badge badge-high`">$($d.Risk)</span></td><td>$([System.Net.WebUtility]::HtmlEncode($d.Reason))</td></tr>`n"
        }
        if (-not $virtualAudioHtml) { $virtualAudioHtml = "<tr><td colspan=`"4`" style=`"text-align:center;color:#7eb8e8;`">Nessun dispositivo virtuale audio sospetto.</td></tr>" }
        $spywareHtml = ""
        foreach ($s in @($sv.AudioSpywareIndicators)) {
            $spywareHtml += "<tr><td>$($s.Type)</td><td>$([System.Net.WebUtility]::HtmlEncode($s.Path))</td><td><span class=`"badge badge-critical`">$($s.Risk)</span></td><td>$([System.Net.WebUtility]::HtmlEncode($s.Reason))</td></tr>`n"
        }
        if (-not $spywareHtml) { $spywareHtml = "<tr><td colspan=`"4`" style=`"text-align:center;color:#7eb8e8;`">Nessun indicatore spyware audio.</td></tr>" }
        $surveillanceSection = @"
<section class="card">
    <h2>&#x1F3A4; Sorveglianza Audio/Video</h2>
    <p><strong>Rischio complessivo:</strong> <span class="risk-score" style="color: var(--danger);">$avScore</span> - $avLevel</p>
    <p>$avSummary</p>
    <ul class="findings-list">$survFindingsHtml</ul>
    <p style="font-size:0.85rem;opacity:0.85;">L'esito tecnico di ciascun controllo audio/video (compresi quelli non completati) e' riportato nella sezione <strong>Metodo e perimetro della verifica</strong>.</p>
    <h3>Microfono</h3>
    <p>In uso: $micInUse | Permesso sistema: $micPerm</p>
    <table class="data-table"><thead><tr><th>Processo</th><th>PID</th><th>Percorso</th><th>Avvio</th><th>Nota</th></tr></thead><tbody>$micProcsHtml</tbody></table>
    <h3>Webcam</h3>
    <p>In uso: $webcamInUse | Permesso sistema: $webcamPerm</p>
    <table class="data-table"><thead><tr><th>Processo</th><th>PID</th><th>Nota</th></tr></thead><tbody>$webcamProcsHtml</tbody></table>
    <h3>Dispositivi audio virtuali (a rischio)</h3>
    <table class="data-table"><thead><tr><th>Dispositivo</th><th>Stato</th><th>Rischio</th><th>Motivo</th></tr></thead><tbody>$virtualAudioHtml</tbody></table>
    <h3>Indicatori spyware audio</h3>
    <table class="data-table"><thead><tr><th>Tipo</th><th>Percorso</th><th>Rischio</th><th>Motivo</th></tr></thead><tbody>$spywareHtml</tbody></table>
</section>
"@
    }

    # === PERSISTENZA AVANZATA (WMI, AppInit_DLLs, IFEO, task pianificati) ===
    $persistenceSection = ""
    if ($PersistenceFindings) {
        $pf = $PersistenceFindings
        $wmiHtml = ""
        foreach ($w in @($pf.WmiSubscriptions)) {
            if ($w.Known) { continue }
            $wmiHtml += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($w.Name))</td><td>$($w.ConsumerType)</td><td>$([System.Net.WebUtility]::HtmlEncode($w.Command))</td><td><span class=`"badge badge-high`">$($w.Risk)</span></td></tr>`n"
        }
        if (-not $wmiHtml) { $wmiHtml = "<tr><td colspan=`"4`" style=`"text-align:center;color:#7eb8e8;`">Nessuna sottoscrizione WMI non riconosciuta.</td></tr>" }

        $appInitHtml = if ($pf.AppInitDlls.Configured) {
            "<span class=`"badge badge-high`">Attivo</span> - DLL: $([System.Net.WebUtility]::HtmlEncode(($pf.AppInitDlls.Dlls -join ', ')))"
        } else { "<span class=`"badge badge-low`">Non configurato</span>" }

        $ifeoHtml = ""
        foreach ($i in @($pf.IFEODebuggers)) {
            $ifeoHtml += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($i.TargetExecutable))</td><td>$([System.Net.WebUtility]::HtmlEncode($i.Debugger))</td><td><span class=`"badge badge-critical`">$($i.Risk)</span></td></tr>`n"
        }
        if (-not $ifeoHtml) { $ifeoHtml = "<tr><td colspan=`"3`" style=`"text-align:center;color:#7eb8e8;`">Nessun debugger IFEO configurato.</td></tr>" }

        $tasksHtml = ""
        foreach ($t in @($pf.ScheduledTasks)) {
            $tasksHtml += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($t.TaskName))</td><td title=`"$([System.Net.WebUtility]::HtmlEncode($t.Command))`">$([System.Net.WebUtility]::HtmlEncode($t.Reason))</td><td><span class=`"badge badge-high`">$($t.Risk)</span></td></tr>`n"
        }
        if (-not $tasksHtml) { $tasksHtml = "<tr><td colspan=`"3`" style=`"text-align:center;color:#7eb8e8;`">Nessun task pianificato sospetto.</td></tr>" }

        $persistenceSection = @"
<section class="card">
    <h2>&#x1F9E9; Persistenza avanzata</h2>
    <p style="font-size:0.85rem;opacity:0.8;">Tecniche usate sia da malware sia, piu' raramente, da strumenti di gestione IT legittimi (es. SCCM). Ogni riscontro va valutato nel contesto: la presenza non dimostra da sola una compromissione.</p>
    <h3>Sottoscrizioni WMI non riconosciute</h3>
    <table class="data-table"><thead><tr><th>Nome</th><th>Tipo</th><th>Comando/Script</th><th>Rischio</th></tr></thead><tbody>$wmiHtml</tbody></table>
    <h3>AppInit_DLLs (iniezione DLL globale)</h3>
    <p>$appInitHtml</p>
    <h3>Image File Execution Options - Debugger hijacking</h3>
    <table class="data-table"><thead><tr><th>Eseguibile target</th><th>Debugger configurato</th><th>Rischio</th></tr></thead><tbody>$ifeoHtml</tbody></table>
    <h3>Task pianificati sospetti</h3>
    <table class="data-table"><thead><tr><th>Nome task</th><th>Motivo segnalazione</th><th>Rischio</th></tr></thead><tbody>$tasksHtml</tbody></table>
</section>
"@
    }

    # === DIFF RISPETTO ALL'ULTIMA SCANSIONE ===
    $scanDiffSection = ""
    if ($ScanDiff -and -not $ScanDiff.Unchanged) {
        $deltaText = if ($ScanDiff.ScoreDelta -gt 0) { "+$($ScanDiff.ScoreDelta)" } else { "$($ScanDiff.ScoreDelta)" }
        $deltaColor = if ($ScanDiff.ScoreDelta -gt 0) { "var(--danger)" } elseif ($ScanDiff.ScoreDelta -lt 0) { "#2ed573" } else { "inherit" }
        $newHtml = ""
        foreach ($f in @($ScanDiff.NewFindings)) { $newHtml += "<li class=`"finding-item`">$([System.Net.WebUtility]::HtmlEncode($f))</li>`n" }
        if (-not $newHtml) { $newHtml = "<li class=`"finding-item safe`">Nessun nuovo riscontro.</li>" }
        $resolvedHtml = ""
        foreach ($f in @($ScanDiff.ResolvedFindings)) { $resolvedHtml += "<li class=`"finding-item safe`">$([System.Net.WebUtility]::HtmlEncode($f))</li>`n" }
        if (-not $resolvedHtml) { $resolvedHtml = "<li class=`"finding-item`">Nessun riscontro precedente risolto.</li>" }
        $scanDiffSection = @"
<section class="card">
    <h2>&#x1F504; Cosa e' cambiato dall'ultima scansione</h2>
    <p>Scansione precedente: <strong>$($ScanDiff.PreviousTimestamp)</strong> - punteggio $($ScanDiff.PreviousScore) ($($ScanDiff.PreviousLevel)) &rarr; ora <strong>$($ScanDiff.CurrentScore)</strong> (<span style="color:$deltaColor;">$deltaText</span>)</p>
    <h3>&#x1F195; Nuovi riscontri rispetto all'ultima scansione</h3>
    <ul class="findings-list">$newHtml</ul>
    <h3>&#x2705; Non piu' presenti rispetto all'ultima scansione</h3>
    <ul class="findings-list">$resolvedHtml</ul>
</section>
"@
    } elseif ($ScanDiff -and $ScanDiff.Unchanged) {
        $scanDiffSection = @"
<section class="card">
    <h2>&#x1F504; Cosa e' cambiato dall'ultima scansione</h2>
    <p>Nessuna variazione rispetto alla scansione del <strong>$($ScanDiff.PreviousTimestamp)</strong> (punteggio $($ScanDiff.PreviousScore), invariato).</p>
</section>
"@
    }

    # === SENTINELLA: EVENTI REGISTRATI NEL TEMPO ===
    # E' la sezione con il maggiore peso documentale: non descrive uno stato, ma
    # fatti datati (sessione X, dalle ore Y alle ore Z, dall'indirizzo W).
    $sentinelSection = ""
    if ($SentinelSummary -and $SentinelSummary.Presente) {
        $sessRows = ""
        foreach ($s in @($SentinelSummary.SessioniRemote)) {
            $durataMin = if ($s.DurataSecondi) { [math]::Round([double]$s.DurataSecondi / 60, 1) } else { 0 }
            $notaTxt = if ($s.Nota) { " <em>($([System.Net.WebUtility]::HtmlEncode([string]$s.Nota)))</em>" } else { "" }
            $sessRows += "<tr><td>$([System.Net.WebUtility]::HtmlEncode([string]$s.Inizio))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$s.Fine))</td><td><strong>$($s.DurataSecondi) s</strong> ($durataMin min)</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$s.IPRemoto))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$s.Software))$notaTxt</td><td>$($s.PortaLocale)</td></tr>`n"
        }
        if (-not $sessRows) { $sessRows = "<tr><td colspan=`"6`" style=`"text-align:center;color:#7eb8e8;`">Nessuna sessione di controllo remoto osservata durante i periodi di sorveglianza.</td></tr>" }

        $periodRows = ""
        foreach ($p in @($SentinelSummary.PeriodiSorveglianza)) {
            $min = if ($null -ne $p.Minuti) { "$($p.Minuti) min" } else { "in corso" }
            $periodRows += "<tr><td>$([System.Net.WebUtility]::HtmlEncode([string]$p.Inizio))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$p.Fine))</td><td>$min</td></tr>`n"
        }
        if (-not $periodRows) { $periodRows = "<tr><td colspan=`"3`">-</td></tr>" }

        $mediaRows = ""
        foreach ($m in @($SentinelSummary.UsiPeriferiche)) {
            $mediaRows += "<tr><td>$([System.Net.WebUtility]::HtmlEncode([string]$m.Periferica))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$m.Processo))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$m.Inizio))</td><td>$($m.DurataSecondi) s</td></tr>`n"
        }
        $mediaBlock = if ($mediaRows) {
            "<h3>Uso di microfono e webcam osservato</h3><table class=`"data-table`"><thead><tr><th>Periferica</th><th>Processo</th><th>Inizio</th><th>Durata</th></tr></thead><tbody>$mediaRows</tbody></table>"
        } else { "" }

        $chainBadge = if ($SentinelSummary.ChainValid) {
            "<span class=`"badge badge-low`">Registro integro</span>"
        } else {
            "<span class=`"badge badge-critical`">REGISTRO MANOMESSO</span>"
        }

        $sentinelSection = @"
<section class="card danger-card">
    <h2>&#x1F6E1;&#xFE0F; SENTINELLA - Eventi registrati nel tempo</h2>
    <p style="font-size:0.9rem;">Questa sezione non descrive lo stato attuale del computer: elenca <strong>fatti datati</strong>, osservati mentre accadevano durante i periodi di sorveglianza. $chainBadge</p>
    <p style="font-size:0.85rem;opacity:0.85;">Minuti totali di sorveglianza: <strong>$([math]::Round($SentinelSummary.MinutiSorvegliati,1))</strong> &middot; Eventi registrati: <strong>$($SentinelSummary.TotaleEventi)</strong> &middot; Sessioni remote osservate: <strong>$(@($SentinelSummary.SessioniRemote).Count)</strong></p>

    <h3>Sessioni di controllo remoto osservate</h3>
    <table class="data-table"><thead><tr><th>Inizio</th><th>Fine</th><th>Durata</th><th>IP remoto</th><th>Software</th><th>Porta</th></tr></thead><tbody>$sessRows</tbody></table>

    $mediaBlock

    <h3>Periodi in cui la Sentinella era attiva</h3>
    <p style="font-size:0.85rem;opacity:0.8;">Fuori da questi intervalli non e' stato osservato nulla, perche' la Sentinella non era in esecuzione: l'assenza di eventi in un dato momento NON significa che non sia accaduto nulla.</p>
    <table class="data-table"><thead><tr><th>Inizio sorveglianza</th><th>Fine</th><th>Durata</th></tr></thead><tbody>$periodRows</tbody></table>

    <p style="font-size:0.85rem;opacity:0.8;"><strong>Limiti:</strong> la Sentinella campiona a intervalli, quindi una sessione piu' breve dell'intervallo puo' non essere stata osservata. Registra l'esistenza, l'origine e la durata delle connessioni, <strong>non il loro contenuto</strong>. Gli orari provengono dall'orologio di questo computer: per una data attestata da terzi occorre la marca temporale del pacchetto prova (vedi DISCLAIMER.md).</p>
</section>
"@
    }

    # === DLL CARICATE DA PERCORSI ANOMALI ===
    $modulesSection = ""
    if ($ModuleFindings) {
        $modRows = ""
        foreach ($m in @($ModuleFindings.SuspiciousModules)) {
            $sigBadge = if ($m.SignatureStatus -eq 'Valid') { "<span class=`"badge badge-medium`">Firmata</span>" } else { "<span class=`"badge badge-critical`">Non firmata</span>" }
            $modRows += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($m.ModuleName))</td><td>$([System.Net.WebUtility]::HtmlEncode($m.ProcessName)) ($($m.ProcessId))</td><td title=`"$([System.Net.WebUtility]::HtmlEncode($m.ModulePath))`">$([System.Net.WebUtility]::HtmlEncode($m.Reason))</td><td>$sigBadge</td><td><span class=`"badge badge-$($m.Risk.ToLower())`">$($m.Risk)</span></td></tr>`n"
        }
        if (-not $modRows) { $modRows = "<tr><td colspan=`"5`" style=`"text-align:center;color:#7eb8e8;`">Nessuna DLL caricata da percorsi anomali.</td></tr>" }
        $inaccessibleNote = if ($ModuleFindings.Inaccessible -gt 0) { " $($ModuleFindings.Inaccessible) processi non ispezionabili (protetti dal sistema o privilegi insufficienti)." } else { "" }
        $modulesSection = @"
<section class="card">
    <h2>&#x1F9EC; DLL caricate da percorsi anomali</h2>
    <p style="font-size:0.85rem;opacity:0.8;">Molti strumenti di monitoraggio non girano come processo autonomo ma si iniettano come DLL dentro programmi legittimi. Qui sono elencate le DLL caricate da cartelle temporanee o pubbliche, dove normalmente non dovrebbero trovarsi. Analizzati $($ModuleFindings.ProcessesAnalyzed) processi.$inaccessibleNote</p>
    <p style="font-size:0.85rem;opacity:0.8;"><strong>Limite:</strong> questo controllo non rileva le tecniche di iniezione avanzate (reflective loading / manual mapping), che non lasciano un modulo elencabile. L'assenza di righe non dimostra l'assenza di iniezione.</p>
    <table class="data-table"><thead><tr><th>DLL</th><th>Processo ospite</th><th>Motivo segnalazione</th><th>Firma</th><th>Rischio</th></tr></thead><tbody>$modRows</tbody></table>
</section>
"@
    }

    # === ANALISI STORICA REGISTRI EVENTI ===
    $eventLogSection = ""
    if ($EventLogFindings) {
        $svcRows = ""
        foreach ($s in @($EventLogFindings.ServiceInstalls)) {
            $riskBadge = if ($s.MatchedTool) { "<span class=`"badge badge-high`">$([System.Net.WebUtility]::HtmlEncode($s.MatchedTool))</span>" } else { "-" }
            $svcRows += "<tr><td>$($s.TimeCreated)</td><td>$([System.Net.WebUtility]::HtmlEncode($s.ServiceName))</td><td title=`"$([System.Net.WebUtility]::HtmlEncode($s.ImagePath))`">$([System.Net.WebUtility]::HtmlEncode($s.ImagePath))</td><td>$riskBadge</td></tr>`n"
        }
        if (-not $svcRows) { $svcRows = "<tr><td colspan=`"4`" style=`"text-align:center;color:#7eb8e8;`">Nessuna installazione di servizio registrata nel periodo analizzato.</td></tr>" }

        $securityNote = if ($EventLogFindings.SecurityLogReadable) {
            "<p style=`"font-size:0.85rem;`">Registro di sicurezza: <strong>leggibile</strong>. Cancellazioni rilevate: $(@($EventLogFindings.SecurityLogCleared).Count) &middot; Accessi remoti (RDP): $(@($EventLogFindings.RemoteLogons).Count)</p>"
        } else {
            "<p style=`"font-size:0.85rem;color:#ffa502;`"><strong>Registro di sicurezza non leggibile</strong> (richiede privilegi di amministratore): cancellazioni del log e accessi remoti RDP <strong>non sono stati verificati</strong>. Per un'analisi completa riesegui come amministratore.</p>"
        }

        $eventLogSection = @"
<section class="card">
    <h2>&#x1F553; Cosa e' successo su questo PC (analisi storica)</h2>
    <p style="font-size:0.85rem;opacity:0.8;">Gli altri controlli fotografano il presente. Questa sezione guarda indietro negli ultimi $($EventLogFindings.DaysAnalyzed) giorni leggendo i registri eventi di Windows: un software di controllo puo' essere stato installato, usato e poi rimosso.</p>
    $securityNote
    <p style="font-size:0.85rem;opacity:0.8;"><strong>Limite:</strong> i registri eventi ruotano e hanno dimensione limitata, quindi eventi piu' vecchi possono essere gia' stati sovrascritti legittimamente. L'installazione di un servizio e' inoltre un'operazione normalissima (driver, aggiornamenti, software aziendale).</p>
    <h3>Servizi installati nel periodo</h3>
    <table class="data-table"><thead><tr><th>Data e ora</th><th>Nome servizio</th><th>Percorso eseguibile</th><th>Corrispondenza nota</th></tr></thead><tbody>$svcRows</tbody></table>
</section>
"@
    }

    # === REGOLE DI RILEVAMENTO CARICATE ===
    $rulesSection = ""
    if ($RulesInfo) {
        $skippedHtml = ""
        foreach ($sk in @($RulesInfo.Skipped)) {
            $skippedHtml += "<li class=`"finding-item`">$([System.Net.WebUtility]::HtmlEncode($sk))</li>`n"
        }
        $skippedBlock = if ($skippedHtml) {
            "<h3>Regole scartate perche' non valide</h3><ul class=`"findings-list`">$skippedHtml</ul><p style=`"font-size:0.85rem;opacity:0.8;`">Una regola scartata non blocca la scansione: viene semplicemente ignorata. Correggi il file indicato e rilancia.</p>"
        } else { "" }
        $sourceText = if ($RulesInfo.UsedFallback) {
            "In uso il <strong>database interno di riserva</strong> (nessuna regola esterna caricata)."
        } else {
            "<strong>$($RulesInfo.Loaded) regole</strong> caricate da $($RulesInfo.SourceCount) file nella cartella <code>core\rules</code>."
        }
        $rulesSection = @"
<section class="card">
    <h2>&#x1F4D0; Regole di rilevamento</h2>
    <p>$sourceText</p>
    <p style="font-size:0.85rem;opacity:0.8;">Le firme di rilevamento non sono scritte nel codice: sono file di dati modificabili da chiunque. Puoi aggiungere le tue regole nella cartella <code>core\rules\custom</code> senza saper programmare e senza modificare il programma. Guida: file <code>RULES.md</code>.</p>
    $skippedBlock
</section>
"@
    }

    # === SPIEGAZIONE AI LOCALE (Ollama, opzionale) ===
    $aiExplanationSection = ""
    if ($OllamaExplanation -and $OllamaExplanation.Text) {
        $aiExplanationSection = @"
<section class="card">
    <h2>&#x1F916; Spiegazione in linguaggio semplice (AI locale)</h2>
    <p style="font-size:0.85rem;opacity:0.8;">Generata in locale con il modello <code>$([System.Net.WebUtility]::HtmlEncode($OllamaExplanation.Model))</code> tramite Ollama (127.0.0.1): nessun dato di questa scansione e' stato inviato a Internet. Testo generato automaticamente: puo' contenere imprecisioni, non sostituisce le sezioni tecniche del report ne' un parere legale.</p>
    <p>$([System.Net.WebUtility]::HtmlEncode($OllamaExplanation.Text))</p>
</section>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="$($cfg.Language)">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="author" content="$($cfg.Author) - $($cfg.AuthorTitle)">
    <meta name="generator" content="DigitalValut Controller $($cfg.Version)">
    <title>$titleEmoji Report Sicurezza - DigitalValut Controller $($cfg.Version)</title>
    $cssContent
</head>
<body>
    <header class="header">
        <div class="logo"><span class="digi">Digital</span><span class="valut">Valut</span></div>
        <p class="tagline">Controller $($cfg.Version) - Strumento di Tutela Privacy Lavoratori PA</p>
        <p class="meta">$($SystemInfo.ComputerName) | $($SystemInfo.ScanDate)</p>
    </header>

    <main class="container">
        <section class="card risk-card">
            <h2>Livello di rischio</h2>
            <div class="risk-score" style="color: $($level.Color)">$($ThreatScore.Score)</div>
            <p class="risk-level" style="color: $($level.Color)">$($level.Icon) $($level.Text)</p>
            <p style="font-size:0.9rem;max-width:62ch;margin:0 auto 0.8rem;">$([System.Net.WebUtility]::HtmlEncode([string]$level.Meaning))</p>
            <p style="font-size:0.82rem;opacity:0.8;max-width:62ch;margin:0 auto 0.8rem;">Il punteggio non misura una violazione: misura quanti indicatori di accesso remoto o di sorveglianza sono stati rilevati e quanto sono gravi. Il calcolo riga per riga e' nella sezione <strong>Come e' stato calcolato il punteggio</strong>.</p>
            <p class="hash-line">Hash verifica dati (SHA-256): <code>$ContentHash</code> | $($ThreatScore.Timestamp)</p>
            <p class="hash-line" style="font-size:0.75rem;opacity:0.8;">L'hash SHA-256 del report e il registro a catena sono in <code>chain_of_custody.jsonl</code> nella stessa cartella. Il meccanismo e' <em>tamper-evident</em>: rende rilevabile un'alterazione accidentale o non esperta del report. Non e' una marcatura temporale certificata da terza parte (RFC 3161) e non impedisce a un soggetto tecnicamente competente di rigenerare l'intera catena: per finalita' probatorie e' necessaria un'acquisizione forense eseguita da un perito qualificato.</p>
        </section>

        $elevationBox

        $alertBox

        $sentinelSection

        $scanDiffSection

        $aiExplanationSection

        $capabilitySection

        <section class="card">
            <h2>&#x1F4DD; COSA DEVI FARE ORA</h2>
            $cosaFareHtml
        </section>

        <section class="card">
            <h2>Riepilogo riscontri</h2>
            <ul class="findings-list">$findingsHtml</ul>
        </section>

        $scoreTableHtml

        $remoteConfigHtml

        $ultraVncLogHtml

        $nonAdminHtml

        <section class="card">
            <h2>&#x1F310; CHI E' COLLEGATO AL TUO PC ORA</h2>
            <table class="data-table"><thead><tr><th>IP Remoto</th><th>Host</th><th>Porta</th><th>Processo</th><th>PID</th><th>Stato</th></tr></thead><tbody>$activeConnHtml</tbody></table>
        </section>

        <section class="card">
            <h2>&#x1F4BB; Informazioni Sistema</h2>
            <div class="info-grid">$infoGrid</div>
        </section>

        <section class="card">
            <h2>&#x1F50C; Porte sospette in ascolto</h2>
            <p style="font-size:0.85rem;opacity:0.85;">Ogni porta e' attribuita al processo che la tiene aperta: e' questo collegamento, e non la porta in se', a rendere il rilievo verificabile. Le porte dei servizi standard di Windows (135, 139, 445) non sono elencate perche' la loro presenza e' normale e non indica controllo remoto.</p>
            <table class="data-table"><thead><tr><th>Porta</th><th>Servizio</th><th>Processo che la detiene</th><th>Rischio</th><th>Descrizione</th></tr></thead><tbody>$portsHtml</tbody></table>
        </section>

        <section class="card">
            <h2>&#x2699;&#xFE0F; Processi rilevati</h2>
            <p style="font-size:0.85rem;opacity:0.8;">La colonna Firma indica se l'eseguibile ha una firma digitale (Authenticode) valida. L'assenza di firma non dimostra da sola malevolenza, ne' la presenza di firma dimostra un uso autorizzato: e' un elemento a supporto, non una prova (vedi DISCLAIMER.md).</p>
            <table class="data-table"><thead><tr><th>Processo</th><th>PID</th><th>Percorso</th><th>Memoria</th><th>Rischio</th><th>Tipo</th><th>Firma</th></tr></thead><tbody>$processHtml</tbody></table>
        </section>

        <section class="card">
            <h2>&#x1F310; Connessioni Esterne Attive</h2>
            <table class="data-table"><thead><tr><th>IP Remoto</th><th>Porta</th><th>Processo</th><th>PID</th></tr></thead><tbody>$extConnHtml</tbody></table>
        </section>

        <section class="card">
            <h2>&#x1F510; Servizi sospetti</h2>
            <table class="data-table"><thead><tr><th>Servizio</th><th>Rischio</th><th>Stato</th></tr></thead><tbody>$servicesHtml</tbody></table>
        </section>

        $surveillanceSection

        $persistenceSection

        $modulesSection

        $eventLogSection

        <section class="card">
            <h2>&#x1F4E6; Software Installato (controllo remoto)</h2>
            <table class="data-table"><thead><tr><th>Nome</th><th>Versione</th><th>Editore</th><th>Rischio</th></tr></thead><tbody>$softwareHtml</tbody></table>
        </section>

        <section class="card">
            <h2>&#x1F680; Programmi Avvio Automatico</h2>
            <table class="data-table"><thead><tr><th>Nome</th><th>Comando</th><th>Posizione</th><th>Nota</th></tr></thead><tbody>$startupHtml</tbody></table>
        </section>

        <section class="card">
            <h2>&#x1F525; Firewall</h2>
            <table class="data-table"><thead><tr><th>Profilo</th><th>Stato</th><th>Traffico In</th><th>Traffico Out</th></tr></thead><tbody>$fwRows</tbody></table>
        </section>

        <section class="card">
            <h2>&#x1F6E1;&#xFE0F; Antivirus</h2>
            <table class="data-table"><thead><tr><th>Nome</th><th>Stato</th><th>Aggiornamenti</th><th>Percorso</th></tr></thead><tbody>$avHtml</tbody></table>
        </section>

        $rulesSection

        $methodologyHtml

        <section class="card template-card">
            <h2>&#x1F4C4; MODELLO RICHIESTA AL DPO (copia e personalizza)</h2>
            $dpoLetterHtml
        </section>

        $legalHtml

        $jsonSection

        $actionButtons

        <footer class="footer-signature">
            <div class="author-badge">
                <strong>$($cfg.Author)</strong><br>
                $($cfg.AuthorTitle)<br>
                $($cfg.Organization)<br>
                $($cfg.Specialty)<br>
                <small>$copyrightHtml</small>
            </div>
        </footer>
    </main>
</body>
</html>
"@

    $outDir = Split-Path -Parent $OutputPath
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.Encoding]::UTF8)
    return $OutputPath
}

Export-ModuleMember -Function Get-DVThreatScore, New-DVReportHTML, Get-DVLegalSectionHTML, `
    Add-DVScoreEvidence, Add-DVModuleScoreEvidence, Test-DVSameSoftware, Test-DVSoftwareMatchesProcess, Get-DVSeverityFromLabel, `
    Get-DVScoreWeights, Get-DVScoreThresholds, Get-DVMethodologyHTML, Get-DVScoreTableHTML, Get-DVRemoteConfigHTML, Get-DVNonAdminGuidanceHTML, Get-DVUltraVncLogHTML
