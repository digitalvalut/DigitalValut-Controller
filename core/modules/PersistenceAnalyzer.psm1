# DigitalValut Controller v4.2 - PersistenceAnalyzer Module
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
# Rileva tecniche di persistenza avanzate, usate sia da malware sia (piu' di
# rado) da software di gestione IT legittimo (es. SCCM usa sottoscrizioni WMI).
# Ogni singolo riscontro va quindi valutato nel contesto: la presenza NON
# dimostra da sola un compromissione. Vedi DISCLAIMER.md.

# Nomi di sottoscrizioni WMI note e legittime (strumenti di gestione IT diffusi),
# per ridurre il rumore di falsi positivi. Elenco non esaustivo.
$Global:DVKnownWmiConsumers = @(
    "SCM Event Log Consumer",
    "BVTConsumer",
    "SCCM*",
    "CCM*",
    "MpsSvc*",
    "Microsoft-Windows-*"
)

function Test-DVKnownWmiConsumer {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    foreach ($pattern in $Global:DVKnownWmiConsumers) {
        if ($Name -like $pattern) { return $true }
    }
    return $false
}

function Get-DVWmiPersistence {
    <#
    .SYNOPSIS
        Elenca le sottoscrizioni WMI permanenti (__EventFilter / __EventConsumer /
        __FilterToConsumerBinding) presenti nel namespace root\subscription.
    .DESCRIPTION
        Le sottoscrizioni WMI permanenti sono una tecnica di persistenza "fileless"
        nota, usata sia da malware sia da strumenti di gestione IT legittimi
        (es. SCCM). Ogni voce non riconosciuta viene segnalata per revisione.
    #>
    $findings = @()
    try {
        $consumers = @()
        $consumers += Get-CimInstance -Namespace "root/subscription" -ClassName "CommandLineEventConsumer" -ErrorAction SilentlyContinue
        $consumers += Get-CimInstance -Namespace "root/subscription" -ClassName "ActiveScriptEventConsumer" -ErrorAction SilentlyContinue

        foreach ($c in $consumers) {
            $known = Test-DVKnownWmiConsumer -Name $c.Name
            $commandOrScript = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif ($c.ScriptText) { $c.ScriptText } else { "" }
            $findings += [PSCustomObject]@{
                Name        = $c.Name
                ConsumerType = $c.CimClass.CimClassName
                Command     = $commandOrScript
                Known       = $known
                Risk        = if ($known) { "LOW" } else { "HIGH" }
            }
        }
    } catch {
        # root\subscription puo' non esistere su alcune installazioni: normale, non un errore.
    }
    return $findings
}

function Get-DVAppInitDlls {
    <#
    .SYNOPSIS
        Verifica la chiave AppInit_DLLs: tecnica di iniezione DLL in ogni processo
        che carica user32.dll, obsoleta ma ancora usata da malware datato.
    #>
    $result = @{ Configured = $false; Dlls = @(); Risk = "NONE" }
    try {
        $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($props -and $props.AppInit_DLLs -and $props.AppInit_DLLs.Trim() -ne "") {
            $loadEnabled = $true
            if ($null -ne $props.LoadAppInit_DLLs) { $loadEnabled = [bool]$props.LoadAppInit_DLLs }
            $result.Configured = $loadEnabled
            $result.Dlls = $props.AppInit_DLLs -split '[,; ]' | Where-Object { $_ }
            if ($loadEnabled) { $result.Risk = "HIGH" }
        }
    } catch { }
    return $result
}

function Get-DVIFEODebuggers {
    <#
    .SYNOPSIS
        Verifica le chiavi "Image File Execution Options": se un eseguibile ha
        un valore "Debugger" impostato, Windows lancia quel debugger al posto
        del programma originale. Tecnica classica di hijacking (es. sethc.exe,
        utilman.exe reindirizzati a cmd.exe come backdoor di accesso).
    #>
    $findings = @()
    $basePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try {
        if (Test-Path $basePath) {
            $subkeys = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue
            foreach ($sk in $subkeys) {
                try {
                    $debugger = (Get-ItemProperty -Path $sk.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
                    if ($debugger) {
                        $findings += [PSCustomObject]@{
                            TargetExecutable = $sk.PSChildName
                            Debugger         = $debugger
                            Risk             = "CRITICAL"
                        }
                    }
                } catch { }
            }
        }
    } catch { }
    return $findings
}

function Get-DVSuspiciousScheduledTasks {
    <#
    .SYNOPSIS
        Elenca i task pianificati con caratteristiche tipiche di persistenza
        sospetta: azioni che referenziano percorsi temporanei/AppData, comandi
        PowerShell con codice codificato in Base64, o interpreti (mshta,
        regsvr32, rundll32) invocati con argomenti da riga di comando.
    #>
    $findings = @()
    $suspiciousPatterns = @(
        '-enc\b', '-encodedcommand', 'FromBase64String', 'mshta\.exe', 'regsvr32\.exe.*http',
        'rundll32\.exe.*javascript', '\\AppData\\Local\\Temp\\', 'IEX\s*\(', 'DownloadString'
    )
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }
        foreach ($t in $tasks) {
            foreach ($action in $t.Actions) {
                $cmdLine = "$($action.Execute) $($action.Arguments)"
                foreach ($pattern in $suspiciousPatterns) {
                    if ($cmdLine -match $pattern) {
                        $findings += [PSCustomObject]@{
                            TaskName = $t.TaskName
                            TaskPath = $t.TaskPath
                            Command  = $cmdLine.Trim()
                            Reason   = "Pattern sospetto: $pattern"
                            Risk     = "HIGH"
                        }
                        break
                    }
                }
            }
        }
    } catch {
        # Get-ScheduledTask non disponibile su alcune edizioni/versioni: nessun errore bloccante.
    }
    return $findings
}

function Get-DVPersistenceFindings {
    <#
    .SYNOPSIS
        Esegue tutti i controlli di persistenza avanzata e restituisce un
        risultato aggregato, nello stesso formato usato dagli altri moduli
        (Score + Findings testuali) per l'integrazione nel punteggio di rischio.
    #>
    $wmi = Get-DVWmiPersistence
    $appInit = Get-DVAppInitDlls
    $ifeo = Get-DVIFEODebuggers
    $tasks = Get-DVSuspiciousScheduledTasks

    $score = 0
    $textFindings = @()

    foreach ($w in ($wmi | Where-Object { -not $_.Known })) {
        $score += 20
        $textFindings += "[PERSISTENZA] Sottoscrizione WMI non riconosciuta: $($w.Name)"
    }
    if ($appInit.Configured) {
        $score += 30
        $textFindings += "[PERSISTENZA] AppInit_DLLs attivo: $($appInit.Dlls -join ', ')"
    }
    foreach ($i in $ifeo) {
        $score += 40
        $textFindings += "[PERSISTENZA] Debugger IFEO su $($i.TargetExecutable): $($i.Debugger)"
    }
    foreach ($t in $tasks) {
        $score += 20
        $textFindings += "[PERSISTENZA] Task pianificato sospetto: $($t.TaskName) - $($t.Reason)"
    }

    return @{
        WmiSubscriptions = $wmi
        AppInitDlls      = $appInit
        IFEODebuggers    = $ifeo
        ScheduledTasks   = $tasks
        Score            = $score
        Findings         = $textFindings
    }
}

Export-ModuleMember -Function Get-DVWmiPersistence, Get-DVAppInitDlls, Get-DVIFEODebuggers, Get-DVSuspiciousScheduledTasks, Get-DVPersistenceFindings, Test-DVKnownWmiConsumer
