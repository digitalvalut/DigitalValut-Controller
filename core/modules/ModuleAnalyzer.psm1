# DigitalValut Controller v4.2 - ModuleAnalyzer Module
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
# RILEVAMENTO DI DLL CARICATE DA PERCORSI ANOMALI
#
# Molti strumenti di monitoraggio e di controllo remoto non girano come processo
# autonomo (facile da vedere in Gestione attivita'), ma si iniettano come DLL
# dentro processi legittimi: il browser, Explorer, un client di posta. Questo
# modulo enumera le DLL caricate dai processi e segnala quelle che si trovano in
# percorsi tipicamente usati per l'iniezione (AppData, Temp, ProgramData,
# cartelle pubbliche) invece che nelle cartelle di sistema o di programma.
#
# LIMITI DICHIARATI (importanti, vedi DISCLAIMER.md):
# - Senza privilegi di amministratore l'elenco dei moduli e' accessibile solo per
#   una parte dei processi: l'assenza di segnalazioni NON significa assenza di
#   iniezione.
# - Il rilevamento e' basato sul PERCORSO, non sul comportamento: software
#   legittimo installato in AppData (Chrome, Teams, Discord, Zoom e molti altri
#   lo fanno di default) genererebbe falsi positivi. Per questo i percorsi di
#   installazione noti sono esclusi (vedi $Global:DVKnownAppDataVendors).
# - Non rileva iniezione "manual mapping" / reflective loading: quelle tecniche
#   non lasciano un modulo elencabile con questo metodo. Un attaccante
#   competente non viene visto da questo controllo.

# Percorsi in cui la presenza di DLL e' di per se' anomala per un processo comune.
$Global:DVSuspiciousModulePaths = @(
    '\appdata\local\temp\',
    '\appdata\roaming\temp\',
    '\windows\temp\',
    '\programdata\temp\',
    '\users\public\',
    '\$recycle.bin\'
)

# Vendor noti che installano legittimamente in AppData: escluderli evita una
# valanga di falsi positivi che renderebbe la sezione inutilizzabile.
$Global:DVKnownAppDataVendors = @(
    '\appdata\local\google\',
    '\appdata\local\microsoft\',
    '\appdata\local\programs\microsoft vs code\',
    '\appdata\local\discord\',
    '\appdata\local\slack\',
    '\appdata\local\zoom\',
    '\appdata\roaming\zoom\',
    '\appdata\local\postman\',
    '\appdata\local\jetbrains\',
    '\appdata\local\spotify\',
    '\appdata\local\whatsapp\',
    '\appdata\local\telegram desktop\',
    '\appdata\local\programs\python\',
    '\appdata\local\yarn\',
    '\appdata\local\npm\'
)

function Test-DVModulePathSuspicious {
    <#
    .SYNOPSIS
        Stabilisce se il percorso di una DLL e' anomalo.
    .OUTPUTS
        Hashtable: Suspicious (bool), Reason (stringa).
    #>
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return @{ Suspicious = $false; Reason = "" }
    }

    $lower = $Path.ToLower()

    # Le esclusioni hanno la precedenza: vendor noti che usano AppData legittimamente
    foreach ($known in $Global:DVKnownAppDataVendors) {
        if ($lower.Contains($known)) { return @{ Suspicious = $false; Reason = "" } }
    }

    foreach ($suspect in $Global:DVSuspiciousModulePaths) {
        if ($lower.Contains($suspect)) {
            return @{ Suspicious = $true; Reason = "DLL caricata da un percorso temporaneo o pubblico ($suspect)" }
        }
    }

    return @{ Suspicious = $false; Reason = "" }
}

function Get-DVSuspiciousModules {
    <#
    .SYNOPSIS
        Enumera le DLL caricate dai processi e restituisce quelle in percorsi
        anomali, arricchite con l'esito della verifica della firma digitale.
    .PARAMETER MaxProcesses
        Limite di processi da analizzare, per non allungare troppo la scansione
        su macchine con centinaia di processi attivi.
    #>
    param([int]$MaxProcesses = 120)

    $findings = @()
    $inaccessible = 0
    $analyzed = 0

    try {
        $processes = @(Get-Process -ErrorAction SilentlyContinue | Select-Object -First $MaxProcesses)
    } catch {
        return @{ Findings = @(); Analyzed = 0; Inaccessible = 0 }
    }

    $signatureCache = @{}

    foreach ($proc in $processes) {
        $modules = $null
        try {
            $modules = $proc.Modules
        } catch {
            # Accesso negato (processo protetto o privilegi insufficienti): atteso, non e' un errore.
            $inaccessible++
            continue
        }
        if (-not $modules) { continue }
        $analyzed++

        foreach ($mod in $modules) {
            $modPath = $null
            try { $modPath = $mod.FileName } catch { continue }
            if ([string]::IsNullOrWhiteSpace($modPath)) { continue }

            $check = Test-DVModulePathSuspicious -Path $modPath
            if (-not $check.Suspicious) { continue }

            # Verifica firma solo sui moduli gia' ritenuti anomali: e' un'operazione
            # costosa e non ha senso eseguirla su migliaia di DLL di sistema.
            $sigStatus = "Unknown"
            $signer = $null
            if ($signatureCache.ContainsKey($modPath)) {
                $sigStatus = $signatureCache[$modPath].Status
                $signer = $signatureCache[$modPath].Signer
            } elseif (Get-Command Get-DVProcessSignature -ErrorAction SilentlyContinue) {
                $sig = Get-DVProcessSignature -Path $modPath
                $sigStatus = $sig.Status
                $signer = $sig.SignerSubject
                $signatureCache[$modPath] = @{ Status = $sigStatus; Signer = $signer }
            }

            $findings += [PSCustomObject]@{
                ProcessName     = $proc.ProcessName
                ProcessId       = $proc.Id
                ModuleName      = (Split-Path -Leaf $modPath)
                ModulePath      = $modPath
                Reason          = $check.Reason
                SignatureStatus = $sigStatus
                SignerSubject   = $signer
                Risk            = if ($sigStatus -eq 'Valid') { "MEDIUM" } else { "HIGH" }
            }
        }
    }

    return @{
        Findings     = $findings
        Analyzed     = $analyzed
        Inaccessible = $inaccessible
    }
}

function Get-DVModuleFindings {
    <#
    .SYNOPSIS
        Esegue l'analisi dei moduli e produce punteggio e riscontri testuali,
        nello stesso formato usato dagli altri moduli per l'integrazione nel
        punteggio di rischio complessivo.
    #>
    param([int]$MaxProcesses = 120)

    $result = Get-DVSuspiciousModules -MaxProcesses $MaxProcesses

    $score = 0
    $textFindings = @()

    foreach ($f in $result.Findings) {
        if ($f.Risk -eq 'HIGH') { $score += 25 } else { $score += 10 }
        $textFindings += "[DLL] $($f.ModuleName) caricata in $($f.ProcessName) da percorso anomalo"
    }

    return @{
        SuspiciousModules = $result.Findings
        ProcessesAnalyzed = $result.Analyzed
        Inaccessible      = $result.Inaccessible
        Score             = $score
        Findings          = $textFindings
    }
}

Export-ModuleMember -Function Test-DVModulePathSuspicious, Get-DVSuspiciousModules, Get-DVModuleFindings
