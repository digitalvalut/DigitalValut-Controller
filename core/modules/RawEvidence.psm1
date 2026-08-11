# DigitalValut Controller v5.0 - RawEvidence Module
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
# CONSERVAZIONE DEI DATI GREZZI
#
# Il report interpreta: "porta 5900 aperta = VNC = rischio critico". Un perito
# informatico forense, o il consulente tecnico della controparte, non puo' e non
# deve fidarsi di quell'interpretazione: deve poter rifare l'analisi da zero.
#
# Questo modulo salva l'OUTPUT GREZZO dei comandi di sistema, prima di qualsiasi
# elaborazione: elenco connessioni, processi con percorso, servizi, chiavi di
# registro di avvio automatico, task pianificati. Sono gli stessi dati che un
# tecnico raccoglierebbe manualmente, ma acquisiti in un unico momento e
# sigillati con il resto del materiale.
#
# Ogni file e' accompagnato dal comando esatto che lo ha prodotto, cosi' chiunque
# puo' rieseguirlo e confrontare.
#
# LIMITI DICHIARATI (vedi DISCLAIMER.md)
# - Sono dati raccolti DALL'INTERNO del sistema in esame, tramite le API di
#   Windows. Se il sistema fosse compromesso a livello di kernel (rootkit), le
#   stesse API potrebbero restituire dati falsati. Un'acquisizione forense vera
#   si esegue su un sistema spento o con strumenti write-blocker esterni.
# - Non e' una copia forense del disco: e' un'istantanea dello stato in memoria
#   e della configurazione, non un'immagine bit a bit.
# - Senza privilegi amministrativi alcuni dati sono parziali o assenti.

function Invoke-DVRawCapture {
    <#
    .SYNOPSIS
        Esegue un blocco di raccolta e ne salva l'esito grezzo su file,
        annotando il comando usato. Non solleva mai eccezioni.
    #>
    param(
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$CommandDescription,
        [Parameter(Mandatory)][scriptblock]$Capture
    )

    $path = Join-Path $OutputDir $FileName
    $header = @(
        "# DigitalValut Controller - dato grezzo non interpretato",
        "# Comando/origine : $CommandDescription",
        "# Acquisito il    : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) (ora locale)",
        "# Acquisito il    : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC",
        "# Computer        : $env:COMPUTERNAME",
        "# Utente          : $env:USERNAME",
        "# ---------------------------------------------------------------------",
        ""
    )

    $content = ""
    $ok = $true
    try {
        $result = & $Capture
        if ($null -ne $result) {
            $content = ($result | Out-String -Width 500)
        } else {
            $content = "(nessun dato restituito)"
        }
    } catch {
        $ok = $false
        $content = "ERRORE DURANTE LA RACCOLTA: $($_.Exception.Message)`r`n" +
                   "Questo di norma indica privilegi insufficienti o funzionalita' non disponibile su questo sistema."
    }

    try {
        [System.IO.File]::WriteAllText($path, (($header -join "`r`n") + "`r`n" + $content), (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        $ok = $false
    }

    return @{ FileName = $FileName; Path = $path; Success = $ok; Description = $CommandDescription }
}

function Save-DVRawEvidence {
    <#
    .SYNOPSIS
        Raccoglie e salva tutti i dati grezzi di sistema in una cartella dedicata.
    .DESCRIPTION
        Ogni voce e' l'output non elaborato di un comando standard di Windows o
        PowerShell: un tecnico puo' rieseguire lo stesso comando e confrontare.
    .OUTPUTS
        Hashtable: Directory, Files (elenco), Count, Errors.
    #>
    param(
        [Parameter(Mandatory)][string]$ReportDir,
        [string]$SubFolderName = "dati_grezzi"
    )

    $outDir = Join-Path $ReportDir $SubFolderName
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $captures = @()

    $captures += Invoke-DVRawCapture -OutputDir $outDir -FileName "01_connessioni_tcp.txt" `
        -CommandDescription "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess" `
        -Capture { Get-NetTCPConnection -ErrorAction Stop | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Sort-Object State,LocalPort | Format-Table -AutoSize }

    $captures += Invoke-DVRawCapture -OutputDir $outDir -FileName "02_connessioni_netstat.txt" `
        -CommandDescription "netstat -ano (output nativo di Windows, per confronto indipendente)" `
        -Capture { netstat -ano }

    $captures += Invoke-DVRawCapture -OutputDir $outDir -FileName "03_processi.txt" `
        -CommandDescription "Get-Process | Select-Object Id,ProcessName,Path,StartTime,Company,Description" `
        -Capture { Get-Process -ErrorAction Stop | Select-Object Id,ProcessName,Path,StartTime,Company,Description | Sort-Object ProcessName | Format-Table -AutoSize }

    $captures += Invoke-DVRawCapture -OutputDir $outDir -FileName "04_servizi.txt" `
        -CommandDescription "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName" `
        -Capture { Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | Sort-Object Name | Format-Table -AutoSize -Wrap }

    $captures += Invoke-DVRawCapture -OutputDir $outDir -FileName "05_avvio_automatico.txt" `
        -CommandDescription "Chiavi di registro Run/RunOnce (HKLM e HKCU) + cartella Esecuzione automatica" `
        -Capture {
            $out = @()
            foreach ($k in @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
                $out += "=== $k ==="
                if (Test-Path $k) {
                    $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                    if ($props) {
                        $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object { $out += "  $($_.Name) = $($_.Value)" }
                    }
                } else { $out += "  (chiave non presente)" }
                $out += ""
            }
            $out += "=== Cartella Esecuzione automatica ==="
            $sf = [Environment]::GetFolderPath("Startup")
            $out += (Get-ChildItem $sf -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name)" })
            $out
        }

    $captures += Invoke-DVRawCapture -OutputDir $outDir -FileName "06_task_pianificati.txt" `
        -CommandDescription "Get-ScheduledTask (nome, stato e azioni eseguite)" `
        -Capture {
            Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
                $azioni = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " ; "
                [PSCustomObject]@{ TaskPath = $_.TaskPath; TaskName = $_.TaskName; State = $_.State; Azioni = $azioni }
            } | Sort-Object TaskPath, TaskName | Format-Table -AutoSize -Wrap
        }

    $captures += Invoke-DVRawCapture -OutputDir $outDir -FileName "07_software_installato.txt" `
        -CommandDescription "Chiavi di registro Uninstall (elenco software installato)" `
        -Capture {
            Get-ItemProperty @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
            ) -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
                Sort-Object DisplayName | Format-Table -AutoSize -Wrap
        }

    $captures += Invoke-DVRawCapture -OutputDir $outDir -FileName "08_informazioni_sistema.txt" `
        -CommandDescription "Get-CimInstance Win32_OperatingSystem / Win32_ComputerSystem + configurazione IP" `
        -Capture {
            $out = @()
            $out += "=== Sistema operativo ==="
            $out += (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object Caption,Version,BuildNumber,InstallDate,LastBootUpTime,OSArchitecture | Format-List | Out-String)
            $out += "=== Computer ==="
            $out += (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object Name,Domain,Manufacturer,Model,UserName,PartOfDomain | Format-List | Out-String)
            $out += "=== Configurazione IP ==="
            $out += (ipconfig /all | Out-String)
            $out
        }

    $captures += Invoke-DVRawCapture -OutputDir $outDir -FileName "09_utenti_e_sessioni.txt" `
        -CommandDescription "query user / Get-LocalUser / Get-LocalGroupMember Administrators" `
        -Capture {
            $out = @()
            $out += "=== Sessioni attive (query user) ==="
            $out += (cmd /c "query user 2>&1" | Out-String)
            $out += "=== Utenti locali ==="
            $out += (Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,LastLogon,Description | Format-Table -AutoSize | Out-String)
            $out += "=== Membri del gruppo Administrators ==="
            $out += (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object Name,ObjectClass | Format-Table -AutoSize | Out-String)
            $out
        }

    $captures += Invoke-DVRawCapture -OutputDir $outDir -FileName "10_stato_rdp.txt" `
        -CommandDescription "Chiavi di registro Terminal Server (stato Desktop Remoto)" `
        -Capture {
            $out = @()
            $ts = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
            $out += "=== $ts ==="
            $p = Get-ItemProperty -Path $ts -ErrorAction SilentlyContinue
            if ($p) {
                $out += "  fDenyTSConnections = $($p.fDenyTSConnections)   (0 = Desktop Remoto ABILITATO, 1 = disabilitato)"
                $out += "  fSingleSessionPerUser = $($p.fSingleSessionPerUser)"
            } else { $out += "  (chiave non leggibile)" }
            $out
        }

    $errors = @($captures | Where-Object { -not $_.Success })
    return @{
        Directory = $outDir
        Files     = $captures
        Count     = @($captures).Count
        Errors    = $errors
    }
}

Export-ModuleMember -Function Invoke-DVRawCapture, Save-DVRawEvidence
