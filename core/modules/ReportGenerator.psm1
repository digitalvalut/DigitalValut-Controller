# DigitalValut Controller v4.0 - ReportGenerator Module
# Dr. Giuseppe Falsone - CEO DigitalValut - Strumento Tutela Privacy Lavoratori PA

function Get-DVThreatScore {
    param(
        [object]$PortAnalysis,
        [object]$ProcessAnalysis,
        [object]$ServiceAnalysis,
        [object]$SoftwareAnalysis,
        [object]$FirewallStatus,
        [object]$NetworkConnections,
        [hashtable]$PortsDb = @{},
        [object]$SurveillanceCapabilities = $null
    )
    
    $score = 0
    $findings = @()
    
    # Porte (peso elevato)
    $suspiciousPorts = @()
    if ($PortAnalysis -and $PortAnalysis.SuspiciousPorts) { $suspiciousPorts = $PortAnalysis.SuspiciousPorts }
    foreach ($port in $suspiciousPorts) {
        $risk = if ($port.Risk) { $port.Risk } else { "MEDIUM" }
        switch ($risk) {
            "CRITICAL" { $score += 40; $findings += "[CRITICO] Porta $($port.Port) ($($port.Name)) aperta" }
            "HIGH"     { $score += 25; $findings += "[ALTO] Porta $($port.Port) ($($port.Name)) aperta" }
            "MEDIUM"   { $score += 10; $findings += "[MEDIO] Porta $($port.Port) ($($port.Name)) aperta" }
        }
    }
    
    # Processi (peso massimo per spyware)
    $remoteControl = @()
    $spyware = @()
    $employeeMonitor = @()
    if ($ProcessAnalysis) {
        if ($ProcessAnalysis.RemoteControl)   { $remoteControl = $ProcessAnalysis.RemoteControl }
        if ($ProcessAnalysis.Spyware)         { $spyware = $ProcessAnalysis.Spyware }
        if ($ProcessAnalysis.EmployeeMonitor) { $employeeMonitor = $ProcessAnalysis.EmployeeMonitor }
    }
    
    foreach ($proc in $remoteControl) {
        $risk = if ($proc.Risk) { $proc.Risk } else { "HIGH" }
        switch ($risk) {
            "CRITICAL" { $score += 50; $findings += "[CRITICO] Software controllo remoto: $($proc.Name)" }
            "HIGH"     { $score += 30; $findings += "[ALTO] Software controllo remoto: $($proc.Name)" }
        }
    }
    
    foreach ($spy in $spyware) {
        $score += 100
        $findings += "[ALLARME] Potenziale spyware: $($spy.Name)"
    }
    
    foreach ($mon in $employeeMonitor) {
        $score += 60
        $findings += "[ATTENZIONE] Software monitoraggio dipendenti: $($mon.Name)"
    }
    
    # Servizi attivi
    $activeServices = @()
    if ($ServiceAnalysis) { $activeServices = @($ServiceAnalysis) }
    $score += ($activeServices.Count * 30)
    
    # Software installato
    $softwareCount = 0
    if ($SoftwareAnalysis) { $softwareCount = @($SoftwareAnalysis).Count }
    $score += ($softwareCount * 15)
    
    # Firewall disabilitato
    if ($FirewallStatus -and -not $FirewallStatus.AllEnabled) {
        $score += 25
        $findings += "[RISCHIO] Firewall non completamente attivo"
    }
    
    # Connessioni sospette (solo verso porte RAT note)
    $suspiciousConns = @()
    if ($NetworkConnections -and $NetworkConnections.Suspicious) { $suspiciousConns = $NetworkConnections.Suspicious }
    foreach ($conn in $suspiciousConns) {
        $remotePort = if ($conn.RemotePort) { $conn.RemotePort } else { 0 }
        if ($PortsDb -and $PortsDb.ContainsKey($remotePort) -and $PortsDb[$remotePort].Risk -match "CRITICAL|HIGH") {
            $score += 20
            $remoteIP = if ($conn.RemoteAddress) { $conn.RemoteAddress } else { $conn.RemoteIP }
            $findings += "[SOSPETTO] Connessione verso $remoteIP`:$remotePort"
        }
    }
    
    # Sorveglianza audio/video: somma punteggio e findings
    if ($SurveillanceCapabilities -and $SurveillanceCapabilities.OverallAudioVideoRisk) {
        $avScore = $SurveillanceCapabilities.OverallAudioVideoRisk.Score
        if ($avScore -gt 0) {
            $score += $avScore
            if ($SurveillanceCapabilities.SurveillanceFindings) {
                $findings += @($SurveillanceCapabilities.SurveillanceFindings)
            }
        }
    }
    
    # Determina livello
    $level = switch ($score) {
        {$_ -eq 0}    { @{Text="SICURO"; Color="#2ed573"; Icon="&#x2705;"; Class="secure"} }
        {$_ -lt 30}   { @{Text="BASSO"; Color="#7bed9f"; Icon="&#x1F7E2;"; Class="low"} }
        {$_ -lt 60}   { @{Text="MEDIO"; Color="#ffa502"; Icon="&#x1F7E1;"; Class="medium"} }
        {$_ -lt 100}  { @{Text="ALTO"; Color="#ff6348"; Icon="&#x1F7E0;"; Class="high"} }
        default       { @{Text="CRITICO"; Color="#ff4757"; Icon="&#x1F534;"; Class="critical"} }
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    return @{
        Score     = $score
        Level     = $level
        Findings  = $findings
        Timestamp = $timestamp
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
        <p class="law-note"><strong>NOTA:</strong> UltraVNC e software analoghi NON sono &quot;strumenti di lavoro&quot; ma strumenti di CONTROLLO. Richiedono accordo sindacale o autorizzazione INL.</p>
    </article>
    <article class="law-article">
        <h3>GDPR - Art. 5 (Principi)</h3>
        <blockquote>I dati personali sono trattati in modo lecito, corretto e <strong>trasparente</strong> nei confronti dell'interessato.</blockquote>
    </article>
    <article class="law-article">
        <h3>GDPR - Art. 13 (Informazioni da fornire)</h3>
        <blockquote>Il titolare del trattamento fornisce all'interessato, nel momento in cui i dati personali sono ottenuti, le seguenti informazioni: [...] le finalit&agrave; del trattamento [...] i destinatari o le categorie di destinatari dei dati personali.</blockquote>
        <p class="law-note"><strong>TRADUZIONE:</strong> Il datore di lavoro DEVE dirti che ha installato software di controllo, perch&eacute; lo usa e chi pu&ograve; accedere. Se non lo ha fatto, viola il GDPR.</p>
    </article>
    <article class="law-article">
        <h3>CODICE PRIVACY - Art. 171 (Sanzioni penali)</h3>
        <blockquote>La violazione delle disposizioni di cui all'articolo 4 della legge 20 maggio 1970, n. 300 [...] &egrave; punita con le sanzioni di cui all'articolo 38 della medesima legge.</blockquote>
        <p class="law-note"><strong>SANZIONE:</strong> Ammenda da 154 &euro; a 1.549 &euro; o arresto da 15 giorni a 1 anno.</p>
    </article>
    <article class="law-article">
        <h3>PROVVEDIMENTO GARANTE PRIVACY 13/07/2016</h3>
        <p>Il Garante ha chiarito che software come VNC, TeamViewer, ecc. sono strumenti di controllo a distanza e NON rientrano negli &quot;strumenti di lavoro&quot; esclusi dall'Art. 4 comma 2. Richiedono SEMPRE accordo sindacale o autorizzazione INL.</p>
    </article>
    <div class="sanctions-box">
        <h3>&#x1F6A8; SANZIONI PER IL DATORE DI LAVORO</h3>
        <table class="data-table"><tr><td>GDPR - Art. 83</td><td>Fino a <strong>20.000.000 &euro;</strong> o 4% del fatturato</td></tr><tr><td>Codice Privacy - Art. 171</td><td>Ammenda + arresto fino a <strong>1 anno</strong></td></tr><tr><td>Conseguenza processuale</td><td>Dati raccolti <strong>INUTILIZZABILI</strong> in sede disciplinare</td></tr></table>
    </div>
</div>
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
        [string]$ControllerRoot,
        [string]$OutputPath,
        [string]$JsonData = "",
        [string]$ContentHash = "",
        [bool]$IsElevated = $true
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
        $portsHtml += "<tr><td>$($p.Port)</td><td>$($p.Name)</td><td><span class=`"badge badge-$riskClass`">$($p.Risk)</span></td><td>$([System.Net.WebUtility]::HtmlEncode($p.Description))</td></tr>`n"
    }
    if ([string]::IsNullOrEmpty($portsHtml)) { $portsHtml = "<tr><td colspan=`"4`" style=`"text-align:center;color:#7eb8e8;`">Nessuna porta sospetta in ascolto.</td></tr>" }
    
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
        $processHtml += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($procName))$countStr</td><td>$pids</td><td title=`"$([System.Net.WebUtility]::HtmlEncode($path))`">$([System.Net.WebUtility]::HtmlEncode($pathDisplay))</td><td>$mem</td><td><span class=`"badge badge-$riskClass`">$($first.Risk)</span></td><td>$($first.Type)</td></tr>`n"
    }
    if ([string]::IsNullOrEmpty($processHtml)) { $processHtml = "<tr><td colspan=`"6`" style=`"text-align:center;color:#7eb8e8;`">Nessun processo sospetto rilevato.</td></tr>" }
    
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
            $riskClass = if ($r -eq "CRITICO") { "critical" } elseif ($r -eq "ALTO") { "high" } else { "medium" }
            $activeConnHtml += "<tr><td>$($ac.IPRemoto)</td><td>$([System.Net.WebUtility]::HtmlEncode($ac.HostRemoto))</td><td>$($ac.PortaLocale)</td><td>$($ac.Processo)</td><td>$($ac.PID)</td><td><span class=`"badge badge-$riskClass`">$([System.Net.WebUtility]::HtmlEncode($ac.Stato))</span></td></tr>`n"
        }
    }
    
    $capabilityHtml = ""
    if (-not $Capabilities -and $ThreatScore.Score -ge 60) {
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
<div class="step"><div class="step-number">1</div><div class="step-content"><h3>CONSERVA QUESTO REPORT</h3><p>Salva il file HTML e stampalo. E' una <strong>prova documentale</strong> con valore legale (contiene timestamp e hash di verifica).</p></div></div>
<div class="step"><div class="step-number">2</div><div class="step-content"><h3>NON MODIFICARE NULLA SUL PC</h3><p>Non disinstallare software, non cambiare impostazioni. Potrebbe servire per un'eventuale perizia tecnica.</p></div></div>
<div class="step"><div class="step-number">3</div><div class="step-content"><h3>RICHIEDI INFORMAZIONI AL DPO</h3><p>Invia una <strong>richiesta scritta</strong> (PEC o raccomandata) al Data Protection Officer chiedendo: copia dell'informativa, base giuridica, accordo sindacale o autorizzazione INL, elenco soggetti autorizzati.</p></div></div>
<div class="step"><div class="step-number">4</div><div class="step-content"><h3>CONTATTA IL SINDACATO</h3><p>RSU, RSA o sindacato di categoria. L'Art. 4 prevede accordo sindacale PRIMA dell'installazione.</p></div></div>
<div class="step"><div class="step-number">5</div><div class="step-content"><h3>SEGNALA AL GARANTE PRIVACY</h3><p>Se non ottieni risposte, puoi segnalare al <a href=`"https://www.garanteprivacy.it`" target=`"_blank`">Garante per la Protezione dei Dati Personali</a>.</p></div></div>
"@
    
    $reportHash = if ($ContentHash) { $ContentHash.Substring(0, [Math]::Min(16, $ContentHash.Length)) } else { "N/D" }
    $reportDate = $SystemInfo.ScanDate
    $pcName = $SystemInfo.ComputerName
    $dpoLetterHtml = @"
<div class="template-text" id="dpo-request">
<p>Spett.le<br>Data Protection Officer<br>ASP [Provincia]<br>PEC: [indirizzo PEC DPO]</p>
<p><strong>OGGETTO: Richiesta informazioni ex Art. 15 GDPR - Software controllo remoto</strong></p>
<p>Il/La sottoscritto/a [NOME COGNOME], dipendente presso [DIPARTIMENTO], in servizio presso la postazione PC identificata come <strong>$([System.Net.WebUtility]::HtmlEncode($pcName))</strong>,</p>
<p><strong>PREMESSO CHE</strong></p>
<ul>
<li>In data $reportDate ho rilevato la presenza di software di controllo remoto (es. UltraVNC) installato sulla mia postazione;</li>
<li>Tale software consente il controllo remoto completo del PC (schermo, mouse/tastiera, file);</li>
<li>Non ho mai ricevuto informativa specifica sull'installazione e utilizzo di tale strumento;</li>
<li>La mia attivita' comporta il trattamento di dati sanitari (Art. 9 GDPR) e l'accesso a PEC istituzionale;</li>
</ul>
<p><strong>CHIEDE</strong></p>
<ol>
<li>Copia dell'informativa ex Art. 13 GDPR relativa al software di controllo remoto;</li>
<li>Indicazione della base giuridica del trattamento (Art. 6 GDPR);</li>
<li>Copia dell'accordo sindacale ex Art. 4 L. 300/1970 o autorizzazione INL;</li>
<li>Elenco dei soggetti autorizzati all'accesso remoto;</li>
<li>Registro degli accessi remoti effettuati sulla mia postazione;</li>
</ol>
<p>Si allega report tecnico (Hash: <code>$reportHash</code>).</p>
<p>Ai sensi dell'Art. 12 GDPR, si richiede riscontro entro 30 giorni.</p>
<p>Distinti saluti.</p>
<p>[Luogo], [Data]<br>[Firma]</p>
</div>
<button type="button" onclick="var t=document.getElementById('dpo-request');var s=document.createElement('textarea');s.value=t.innerText;document.body.appendChild(s);s.select();document.execCommand('copy');document.body.removeChild(s);alert('Testo copiato negli appunti.');" class="btn btn-primary no-print">&#x1F4CB; Copia Testo</button>
"@
    
    $alertBox = ""
    if ($ThreatScore.Score -ge 60) {
        $alertBox = @"
<div class="alert alert-danger">
    <div class="alert-icon">&#x26A0;&#xFE0F;</div>
    <div class="alert-content">
        <strong>ATTENZIONE!</strong>
        <p>Il CED / gli amministratori di rete possono vedere il tuo schermo, controllare mouse e tastiera, leggere email e PEC, accedere ai dati sanitari. <strong>Questo e' illegale senza informativa preventiva</strong> (Art. 4 Statuto Lavoratori, GDPR Art. 13).</p>
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
    $copyrightHtml = "&copy; 2024-2026 DigitalValut Association. All Rights Reserved."
    
    $capabilitySection = ""
    if ($capabilityHtml) {
        $capabilitySection = @"
<section class="card danger-card">
    <h2>&#x26A0;&#xFE0F; ATTENZIONE: COSA POSSONO FARE GLI AMMINISTRATORI</h2>
    <div class="capability-grid">$capabilityHtml</div>
    <div class="warning-box">
        <strong>&#x1F534; QUESTO E' ILLEGALE SENZA INFORMATIVA</strong>
        <p>Se non hai ricevuto comunicazione scritta sull'installazione di questo software, il datore di lavoro sta violando: Art. 4 Statuto dei Lavoratori (L. 300/1970), Art. 5, 6, 13 GDPR, Art. 114 e 171 Codice Privacy.</p>
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
        $micInUse = if ($sv.Microphone.CurrentlyInUse) { "Sì" } else { "No" }
        $micPerm = if ($sv.Microphone.PermissionEnabled) { "Attivato" } else { "Disattivato" }
        $micProcs = @($sv.Microphone.ActiveProcesses)
        $micProcsHtml = ""
        foreach ($p in $micProcs) {
            $susBadge = if ($p.Suspicious) { " <span class=`"badge badge-critical`">Sospetto</span>" } else { "" }
            $micProcsHtml += "<tr><td>$($p.ProcessName)</td><td>$($p.PID)</td><td>$([System.Net.WebUtility]::HtmlEncode($p.Path))</td><td>$($p.StartTime)</td><td>$susBadge</td></tr>`n"
        }
        if (-not $micProcsHtml) { $micProcsHtml = "<tr><td colspan=`"5`" style=`"text-align:center;color:#7eb8e8;`">Nessun processo con accesso al microfono.</td></tr>" }
        $webcamInUse = if ($sv.Webcam.CurrentlyInUse) { "Sì" } else { "No" }
        $webcamPerm = if ($sv.Webcam.PermissionEnabled) { "Attivato" } else { "Disattivato" }
        $webcamProcs = @($sv.Webcam.ActiveProcesses)
        $webcamProcsHtml = ""
        foreach ($p in $webcamProcs) {
            $susBadge = if ($p.Suspicious) { " <span class=`"badge badge-critical`">Sospetto</span>" } else { "" }
            $webcamProcsHtml += "<tr><td>$($p.ProcessName)</td><td>$($p.PID)</td><td>$susBadge</td></tr>`n"
        }
        if (-not $webcamProcsHtml) { $webcamProcsHtml = "<tr><td colspan=`"3`" style=`"text-align:center;color:#7eb8e8;`">Nessun processo con accesso alla webcam.</td></tr>" }
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
    
    $html = @"
<!DOCTYPE html>
<html lang="$($cfg.Language)">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="author" content="$($cfg.Author) - $($cfg.AuthorTitle)">
    <meta name="generator" content="DigitalValut Controller $($cfg.Version)">
    <title>$titleEmoji Report Sicurezza - DigitalValut Controller v4.0</title>
    $cssContent
</head>
<body>
    <header class="header">
        <div class="logo"><span class="digi">Digital</span><span class="valut">Valut</span></div>
        <p class="tagline">Controller v4.0 - Strumento di Tutela Privacy Lavoratori PA</p>
        <p class="meta">$($SystemInfo.ComputerName) | $($SystemInfo.ScanDate)</p>
    </header>
    
    <main class="container">
        <section class="card risk-card">
            <h2>Livello di rischio</h2>
            <div class="risk-score" style="color: $($level.Color)">$($ThreatScore.Score)</div>
            <p class="risk-level" style="color: $($level.Color)">$($level.Icon) $($level.Text)</p>
            <p class="hash-line">Hash verifica dati (SHA-256): <code>$ContentHash</code> | $($ThreatScore.Timestamp)</p>
            <p class="hash-line" style="font-size:0.75rem;opacity:0.8;">L'hash del file di report definitivo e la catena di custodia sono registrati in <code>chain_of_custody.jsonl</code> nella stessa cartella del report. Usalo per dimostrare che il file non e' stato alterato dopo la generazione.</p>
        </section>
        
        $elevationBox

        $alertBox

        $capabilitySection
        
        <section class="card">
            <h2>&#x1F4DD; COSA DEVI FARE ORA</h2>
            $cosaFareHtml
        </section>
        
        <section class="card">
            <h2>Riepilogo riscontri</h2>
            <ul class="findings-list">$findingsHtml</ul>
        </section>
        
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
            <table class="data-table"><thead><tr><th>Porta</th><th>Servizio</th><th>Rischio</th><th>Descrizione</th></tr></thead><tbody>$portsHtml</tbody></table>
        </section>
        
        <section class="card">
            <h2>&#x2699;&#xFE0F; Processi rilevati</h2>
            <table class="data-table"><thead><tr><th>Processo</th><th>PID</th><th>Percorso</th><th>Memoria</th><th>Rischio</th><th>Tipo</th></tr></thead><tbody>$processHtml</tbody></table>
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

Export-ModuleMember -Function Get-DVThreatScore, New-DVReportHTML, Get-DVLegalSectionHTML
