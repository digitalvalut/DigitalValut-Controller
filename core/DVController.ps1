#Requires -Version 5.1
<#
.SYNOPSIS
    DigitalValut Controller v4.1 - Strumento di Tutela Privacy Lavoratori PA

.DESCRIPTION
    Strumento per la verifica di software di controllo remoto non autorizzato.
    Progettato per dipendenti pubblici (PA) che accedono a dati sensibili (sanita',
    PEC, email). Rileva VNC, TeamViewer, RDP; mostra chi e' collegato e cosa possono
    fare; genera un report tecnico con riferimenti informativi ad Art. 4 Statuto
    Lavoratori e GDPR. Il report NON e' una perizia forense: vedi DISCLAIMER.md.

.AUTHOR
    DigitalValut - www.digitalvalut.it
    Sviluppatore: Dott. Giuseppe Falsone e il team DigitalValut
    DigitalValut Association - Crypto-Forensics & Blockchain Security

.LICENSE
    GNU General Public License v3.0 or later (GPLv3+)
    Copyright (C) 2024-2026 DigitalValut - www.digitalvalut.it
    This program comes with ABSOLUTELY NO WARRANTY. This is free software,
    and you are welcome to redistribute it under the terms of the GPLv3.
    See the LICENSE file for details.

.VERSION
    4.1.1

.LINK
    https://www.digitalvalut.it
#>

param(
    # Scansione rapida: salta i controlli piu' lenti (ricerca file spyware in AppData,
    # programmi di avvio automatico, stato antivirus, persistenza avanzata). Utile per
    # un primo controllo veloce.
    [switch]$QuickScan,

    # Non esegue una scansione: verifica solo l'integrita' del registro di catena di
    # custodia esistente (chain_of_custody.jsonl) e mostra l'esito.
    [switch]$VerifyChain,

    # Disattiva il tentativo di usare un LLM locale (Ollama, su 127.0.0.1) per generare
    # una spiegazione in linguaggio naturale dei risultati. Se Ollama non e' installato
    # il modulo e' comunque no-op: questo switch serve solo a chi lo ha installato ma
    # non vuole usarlo per questa scansione.
    [switch]$DisableAI
)

$ErrorActionPreference = "Continue"

# === CONFIGURAZIONE GLOBALE ===
$Global:DVConfig = @{
    Version         = "4.1.1"
    Author          = "DigitalValut"
    AuthorTitle     = "Sviluppatore: Dott. Giuseppe Falsone e il team DigitalValut"
    Organization    = "DigitalValut Association"
    Specialty       = "Crypto-Forensics & Blockchain Security"
    License         = "Open Source - GNU GPL v3.0 (gratuito per sempre)"
    Website         = "https://www.digitalvalut.it"
    Email           = "info@digitalvalut.com"
    Copyright       = "&copy; 2024-2026 DigitalValut - www.digitalvalut.it. Rilasciato sotto licenza GPLv3."
    Language        = "it"
    AutoOpenReport  = $true
    # Nota: la cartella dei report NON e' configurabile. E' sempre "DigitalValut_Reports"
    # accanto al programma, per garantire un'unica posizione stabile su ogni PC in cui
    # lo strumento viene eseguito (vedi risoluzione di $reportDir piu' sotto).
    ReportPath      = "DigitalValut_Reports"
}

# Carica settings.json se presente
$configPath = Join-Path $PSScriptRoot "config\settings.json"
if (Test-Path $configPath) {
    try {
        $settings = Get-Content $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($settings.Language) { $Global:DVConfig.Language = $settings.Language }
        if ($null -ne $settings.AutoOpenReport) { $Global:DVConfig.AutoOpenReport = $settings.AutoOpenReport }
    } catch { }
}

# Controller root (cartella principale del progetto)
$controllerRoot = (Get-Item $PSScriptRoot).Parent.FullName
$modulesPath = Join-Path $PSScriptRoot "modules"

# Importa moduli
$modules = @(
    "ThreatDatabase",
    "SystemInfo",
    "ProcessScanner",
    "NetworkAnalyzer",
    "SecurityChecker",
    "SurveillanceDetector",
    "AuthenticodeChecker",
    "PersistenceAnalyzer",
    "OllamaAssistant",
    "ReportGenerator",
    "ChainOfCustody"
)
foreach ($mod in $modules) {
    $modPath = Join-Path $modulesPath "$mod.psm1"
    if (Test-Path $modPath) {
        Import-Module $modPath -Force
    } else {
        Write-Host "  [!] Modulo mancante: $mod.psm1 - alcune funzionalita' potrebbero non essere disponibili." -ForegroundColor Yellow
    }
}

# Rilevamento privilegi amministrativi (alcuni controlli sono piu' completi se elevati)
$isElevated = $false
try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
if (-not $isElevated) {
    Write-Host "  [!] Eseguito SENZA privilegi di amministratore: alcuni dati potrebbero essere incompleti." -ForegroundColor Yellow
    Write-Host "      Per una scansione completa: tasto destro sul launcher -> Esegui come amministratore." -ForegroundColor Yellow
}

# Path report: SEMPRE la cartella "DigitalValut_Reports" accanto al programma (portatile,
# unica, indipendente dal PC su cui giri lo strumento). Nessun'altra posizione e' ammessa:
# questo garantisce che report e registro di catena di custodia restino sempre nello stesso
# posto, anche cambiando macchina (utile per USB e per PC diversi assegnati allo stesso utente).
$reportDir = Join-Path $controllerRoot "DigitalValut_Reports"
if (-not (Test-Path $reportDir)) {
    try { New-Item -ItemType Directory -Path $reportDir -Force -ErrorAction Stop | Out-Null } catch { }
}
$canWriteReportDir = $false
try {
    $testFile = Join-Path $reportDir ".write_test"
    [System.IO.File]::WriteAllText($testFile, "test")
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    $canWriteReportDir = $true
} catch { }
if (-not $canWriteReportDir) {
    Write-Host ""
    Write-Host "  [ERRORE] Impossibile scrivere in $reportDir" -ForegroundColor Red
    Write-Host "           Verifica i permessi della cartella e riprova. Nessun report verra' generato" -ForegroundColor Red
    Write-Host "           in un'altra posizione, per garantire che tutti i report restino sempre qui." -ForegroundColor Red
    Write-Host ""
    exit 1
}
$ledgerPath = Get-DVLedgerPath -ReportDir $reportDir

# === MODALITA' VERIFICA CATENA DI CUSTODIA (nessuna scansione) ===
if ($VerifyChain) {
    Write-Host ""
    Write-Host "  [*] Verifica integrita' registro di catena di custodia..." -ForegroundColor Cyan
    $chainResult = Test-DVChainIntegrity -LedgerPath $ledgerPath
    Write-Host ""
    if ($chainResult.Valid) {
        Write-Host "  [OK] $($chainResult.Message)" -ForegroundColor Green
    } else {
        Write-Host "  [ALLARME] $($chainResult.Message)" -ForegroundColor Red
    }
    Write-Host "  Registro: $ledgerPath"
    Write-Host ""
    exit $(if ($chainResult.Valid) { 0 } else { 1 })
}

# === ESECUZIONE SCANSIONE ===
if ($QuickScan) {
    Write-Host "  [*] Modalita' scansione RAPIDA (alcuni controlli lenti saranno saltati)." -ForegroundColor Cyan
}
Write-Host "  [*] Raccolta informazioni sistema..." -ForegroundColor Cyan
$systemInfo = Get-DVSystemInfo

$portDb = Get-RemotePortsDatabase
$processDb = Get-SuspiciousProcessesDatabase

Write-Host "  [*] Analisi porte di rete..." -ForegroundColor Cyan
$portAnalysis = Get-DVOpenPorts -PortsDb $portDb

Write-Host "  [*] Scansione processi..." -ForegroundColor Cyan
$processAnalysis = Get-DVProcessScan -ThreatDb $processDb

Write-Host "  [*] Verifica firma digitale (Authenticode) dei processi rilevati..." -ForegroundColor Cyan
foreach ($category in @('RemoteControl', 'Spyware', 'EmployeeMonitor', 'OtherSuspicious')) {
    if ($processAnalysis[$category] -and @($processAnalysis[$category]).Count -gt 0) {
        $processAnalysis[$category] = Add-DVSignatureInfo -Entries @($processAnalysis[$category])
    }
}

Write-Host "  [*] Verifica servizi sospetti..." -ForegroundColor Cyan
$serviceAnalysis = Get-DVServicesSuspicious -ProcessDb $processDb

Write-Host "  [*] Software installato (controllo remoto/spyware)..." -ForegroundColor Cyan
$softwareAnalysis = Get-DVInstalledSuspiciousSoftware -ThreatDb $processDb

Write-Host "  [*] Stato Firewall..." -ForegroundColor Cyan
$firewallStatus = Get-DVFirewallStatus

Write-Host "  [*] Connessioni di rete..." -ForegroundColor Cyan
$networkConnections = Get-DVNetworkConnections
$externalConnections = Get-DVExternalConnections

Write-Host "  [*] Connessioni remote attive (chi e' collegato)..." -ForegroundColor Cyan
$activeRemoteConnections = Get-DVActiveRemoteConnections -PortsDb $portDb -ProcessDb $processDb

Write-Host "  [*] Capacita' controllo remoto (cosa possono fare)..." -ForegroundColor Cyan
$capabilities = Get-DVRemoteControlCapabilities

$surveillanceCapabilities = $null
$startupPrograms = @()
$antivirusStatus = @()
$persistenceFindings = $null
if (-not $QuickScan) {
    Write-Host "  [*] Rilevamento sorveglianza audio/video (microfono, webcam)..." -ForegroundColor Cyan
    $surveillanceCapabilities = Get-DVSurveillanceCapabilities

    Write-Host "  [*] Programmi avvio automatico..." -ForegroundColor Cyan
    $startupPrograms = Get-DVStartupPrograms

    Write-Host "  [*] Stato Antivirus..." -ForegroundColor Cyan
    $antivirusStatus = Get-DVAntivirusStatus

    Write-Host "  [*] Persistenza avanzata (WMI, AppInit_DLLs, IFEO, task pianificati)..." -ForegroundColor Cyan
    $persistenceFindings = Get-DVPersistenceFindings
} else {
    Write-Host "  [i] Saltati (modalita' rapida): sorveglianza audio/video, avvio automatico, antivirus, persistenza avanzata." -ForegroundColor DarkGray
}

Write-Host "  [*] Calcolo punteggio di rischio..." -ForegroundColor Cyan
$threatScore = Get-DVThreatScore -PortAnalysis $portAnalysis -ProcessAnalysis $processAnalysis `
    -ServiceAnalysis $serviceAnalysis -SoftwareAnalysis $softwareAnalysis `
    -FirewallStatus $firewallStatus -NetworkConnections $networkConnections -PortsDb $portDb `
    -SurveillanceCapabilities $surveillanceCapabilities -PersistenceFindings $persistenceFindings

Write-Host "  [*] Confronto con l'ultima scansione registrata..." -ForegroundColor Cyan
$scanDiff = Compare-DVScanFindings -LedgerPath $ledgerPath -ReportDir $reportDir `
    -CurrentScore $threatScore.Score -CurrentFindings @($threatScore.Findings)
if ($scanDiff) {
    Write-Host "  [i] Scansione precedente: $($scanDiff.PreviousTimestamp) - punteggio $($scanDiff.PreviousScore) ($($scanDiff.PreviousLevel))" -ForegroundColor DarkGray
}

$ollamaExplanation = $null
if (-not $DisableAI) {
    Write-Host "  [*] Verifica presenza di un modello AI locale (Ollama, solo 127.0.0.1)..." -ForegroundColor Cyan
    $ollamaExplanation = Get-DVOllamaExplanation -Findings @($threatScore.Findings) -Score $threatScore.Score -LevelText $threatScore.Level.Text
    if ($ollamaExplanation) {
        Write-Host "  [OK] Spiegazione generata in locale con il modello '$($ollamaExplanation.Model)' (nessun dato inviato a Internet)." -ForegroundColor Green
    } else {
        Write-Host "  [i] Nessun modello AI locale disponibile (normale se Ollama non e' installato): sezione saltata." -ForegroundColor DarkGray
    }
}

$dateStr = Get-Date -Format "yyyy-MM-dd_HH-mm"
$safeComputerName = $systemInfo.ComputerName -replace '[^\w\-]', '_'
$reportFileName = "DV_Report_${safeComputerName}_${dateStr}.html"
$reportFullPath = Join-Path $reportDir $reportFileName

$exportData = @{
    SystemInfo               = $systemInfo
    ThreatScore              = $threatScore
    PortAnalysis             = $portAnalysis
    ProcessCount             = @($processAnalysis.RemoteControl).Count + @($processAnalysis.Spyware).Count + @($processAnalysis.EmployeeMonitor).Count
    GeneratedAt              = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Author                   = $Global:DVConfig.Author
    Version                  = $Global:DVConfig.Version
    ExternalConnections      = $externalConnections
    ActiveRemoteConnections  = $activeRemoteConnections
    Capabilities             = $capabilities
    SurveillanceCapabilities = $surveillanceCapabilities
    StartupPrograms          = $startupPrograms
    AntivirusStatus          = $antivirusStatus
    PersistenceFindings      = $persistenceFindings
    ScanDiff                 = $scanDiff
}
$jsonDataString = $exportData | ConvertTo-Json -Depth 10
$findingsHash = Get-DVContentHash -Content $jsonDataString

Write-Host "  [*] Generazione report HTML..." -ForegroundColor Cyan
try {
    $reportPath = New-DVReportHTML -SystemInfo $systemInfo -ThreatScore $threatScore `
        -PortAnalysis $portAnalysis -ProcessAnalysis $processAnalysis `
        -ServiceAnalysis $serviceAnalysis -SoftwareAnalysis $softwareAnalysis `
        -FirewallStatus $firewallStatus -ExternalConnections $externalConnections `
        -StartupPrograms $startupPrograms -AntivirusStatus $antivirusStatus `
        -SurveillanceCapabilities $surveillanceCapabilities `
        -PersistenceFindings $persistenceFindings -ScanDiff $scanDiff -OllamaExplanation $ollamaExplanation `
        -ControllerRoot $controllerRoot -OutputPath $reportFullPath -JsonData $jsonDataString `
        -ContentHash $findingsHash -IsElevated $isElevated
} catch {
    Write-Host ""
    Write-Host "  [ERRORE] Generazione report fallita: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# Export JSON (opzionale)
$jsonPath = $reportFullPath -replace '\.html$', '.json'
try {
    $exportData | ConvertTo-Json -Depth 10 | Set-Content $jsonPath -Encoding UTF8
} catch { }

Write-Host ""
Write-Host "  [OK] Report salvato: $reportPath" -ForegroundColor Green
Write-Host "  [OK] Punteggio rischio: $($threatScore.Score) - $($threatScore.Level.Text)" -ForegroundColor $(if ($threatScore.Score -gt 59) { "Yellow" } else { "Green" })
Write-Host ""

# === CATENA DI CUSTODIA: hash reali dei file scritti su disco + registro a catena ===
Write-Host "  [*] Registrazione catena di custodia..." -ForegroundColor Cyan
try {
    $reportDir = Split-Path -Parent $reportFullPath
    $ledgerPath = Get-DVLedgerPath -ReportDir $reportDir
    $reportFileHash = Get-DVFileHashSHA256 -Path $reportFullPath
    $jsonFileHash = Get-DVFileHashSHA256 -Path $jsonPath
    Add-DVCustodyRecord -LedgerPath $ledgerPath -ReportFileName (Split-Path -Leaf $reportFullPath) `
        -ReportFileHash $reportFileHash -JsonFileHash $jsonFileHash -SystemInfo $systemInfo `
        -ThreatScore $threatScore.Score -ThreatLevel $threatScore.Level.Text | Out-Null

    $chainCheck = Test-DVChainIntegrity -LedgerPath $ledgerPath
    Write-Host "  [OK] Hash file report (SHA-256): $reportFileHash" -ForegroundColor Green
    Write-Host "  [OK] Registro catena di custodia: $ledgerPath" -ForegroundColor Green
    if ($chainCheck.Valid) {
        Write-Host "  [OK] $($chainCheck.Message)" -ForegroundColor Green
    } else {
        Write-Host "  [ALLARME] $($chainCheck.Message)" -ForegroundColor Red
    }
} catch {
    Write-Host "  [!] Impossibile aggiornare la catena di custodia: $($_.Exception.Message)" -ForegroundColor Yellow
}
Write-Host ""

if ($Global:DVConfig.AutoOpenReport -and $reportPath -and (Test-Path $reportPath)) {
    Start-Process $reportPath
}

exit 0
