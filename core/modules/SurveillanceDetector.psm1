# DigitalValut Controller v5.1 - SurveillanceDetector Module
# Modulo rilevamento sorveglianza audio/video
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

$script:SurveillanceWhitelist = @(
    'teams.exe', 'zoom.exe', 'skype.exe', 'discord.exe',
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'slack.exe', 'webex.exe',
    'obs64.exe', 'obs32.exe', 'svchost.exe'
)

$script:VirtualAudioKeywords = @('virtual', 'cable', 'vb-audio', 'voicemeeter', 'stereo mix', 'cable input', 'cable output')
$script:SpywareFileKeywords = @('record', 'audio', 'capture', 'spy', 'monitor')
$script:SurveillanceTimeoutMs = 5000

# Percorso di questo modulo: serve per ricaricarlo in un runspace separato.
$script:SurveillanceModulePath = $PSCommandPath

# Esegue un controllo con timeout e restituisce SEMPRE un esito esplicito
# (OK / TIMEOUT / FALLITO). Cosi' un controllo che non riesce non viene mai
# scambiato per "nessun problema trovato".
#
# NOTA TECNICA (corretto in v5.1): la versione precedente usava Start-Job, che
# avvia un processo separato nel quale le funzioni di questo modulo NON esistono:
# ogni controllo falliva in silenzio e il report mostrava dati vuoti. Qui si usa
# un runspace nello stesso processo che ricarica il modulo; se il caricamento e'
# bloccato (es. policy di esecuzione), si ripiega sull'esecuzione diretta.
function Invoke-DVCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$FunctionName,
        [int]$TimeoutMs = $script:SurveillanceTimeoutMs
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'OK'
    $detail = ''
    $data = @()
    $ps = $null
    try {
        $ps = [powershell]::Create()
        $null = $ps.AddScript({
            param($ModulePath, $Fn)
            Import-Module $ModulePath -Force -DisableNameChecking -ErrorAction Stop
            , @(& $Fn)
        }).AddArgument($script:SurveillanceModulePath).AddArgument($FunctionName)
        $async = $ps.BeginInvoke()
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            try { $ps.Stop() } catch { Write-Verbose "Stop runspace: $($_.Exception.Message)" }
            $status = 'TIMEOUT'
            $detail = "Controllo interrotto dopo $([math]::Round($TimeoutMs / 1000)) s"
        } else {
            $out = $ps.EndInvoke($async)
            if ($ps.HadErrors -and $ps.Streams.Error.Count -gt 0 -and (-not $out -or $out.Count -eq 0)) {
                $status = 'FALLITO'
                $detail = [string]$ps.Streams.Error[0].Exception.Message
            } elseif ($out -and $out.Count -gt 0) {
                $data = @($out[0].BaseObject)
            }
        }
    } catch {
        $status = 'FALLITO'
        $detail = $_.Exception.Message
    } finally {
        if ($ps) { $ps.Dispose() }
    }

    # Ripiego: se il runspace non ha potuto ricaricare il modulo, esecuzione diretta.
    if ($status -eq 'FALLITO' -and $detail -match 'Import-Module|non pu.* essere caricat|cannot be loaded|execution policy|ExecutionPolicy') {
        try {
            $data = @(& $FunctionName)
            $status = 'OK'
            $detail = 'Eseguito direttamente (runspace separato non disponibile)'
        } catch {
            $status = 'FALLITO'
            $detail = $_.Exception.Message
        }
    }
    $sw.Stop()
    return [PSCustomObject]@{
        Name   = $Name
        Status = $status
        Detail = $detail
        Ms     = [int]$sw.ElapsedMilliseconds
        Data   = $data
    }
}

# Converte il nome della sottochiave ConsentStore (percorso con '#' al posto di '\')
# in percorso leggibile.
function ConvertFrom-DVConsentKeyName {
    param([string]$KeyName)
    if (-not $KeyName) { return '' }
    return ($KeyName -replace '#', '\')
}

# True se il percorso e' in una cartella scrivibile dall'utente tipica di software
# non installato in modo ufficiale (Temp, AppData, Public, ProgramData).
function Test-DVUserWritablePath {
    param([string]$Path)
    if (-not $Path) { return $false }
    return ($Path -match '(?i)\\Users\\[^\\]+\\AppData\\(Local\\Temp|Roaming|Local\\Programs)\\|\\Users\\Public\\|\\Windows\\Temp\\|\\ProgramData\\|\\Temp\\')
}

# Interpreta una voce del ConsentStore (microfono/webcam). Funzione pura (testabile):
# LastUsedTimeStart/Stop sono FILETIME; Stop = 0 con Start > 0 significa "in uso adesso".
function ConvertFrom-DVConsentEntry {
    param(
        [Parameter(Mandatory)][string]$Store,
        [Parameter(Mandatory)][string]$KeyName,
        [long]$StartFileTime = 0,
        [long]$StopFileTime = 0,
        [string]$Value = ''
    )
    if ($StartFileTime -le 0) { return $null }
    $path = ConvertFrom-DVConsentKeyName -KeyName $KeyName
    $startDt = [DateTime]::FromFileTime($StartFileTime)
    $inUse = ($StopFileTime -le 0)
    $stopDt = $null
    $durationText = ''
    if (-not $inUse) {
        $stopDt = [DateTime]::FromFileTime($StopFileTime)
        $span = $stopDt - $startDt
        if ($span.TotalSeconds -lt 0) { $span = [TimeSpan]::Zero }
        $durationText = '{0:00}:{1:00}:{2:00}' -f [math]::Floor($span.TotalHours), $span.Minutes, $span.Seconds
    }
    $exe = if ($path -match '\\') { Split-Path -Leaf $path } else { $path }
    # ProcessName/PID/Suspicious: compatibilita' con SentinelMonitor e con il report.
    return [PSCustomObject]@{
        Store         = $Store
        AppName       = $exe
        ProcessName   = [System.IO.Path]::GetFileNameWithoutExtension($exe)
        PID           = $null
        Suspicious    = (-not (Test-DVKnownMediaApp -AppName $exe))
        Path          = $path
        InUseNow      = $inUse
        LastUsedStart = $startDt.ToString('yyyy-MM-dd HH:mm:ss')
        LastUsedStop  = if ($stopDt) { $stopDt.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
        Duration      = $durationText
        Value         = $Value
    }
}

# --- 1. Get-MicrophoneAccess: processi che usano il microfono in tempo reale ---
function Get-MicrophoneAccess {
    $result = @()
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            try {
                if (-not $proc.Modules) { continue }
                $hasAudio = $false
                foreach ($mod in $proc.Modules) {
                    if ($mod.ModuleName -match 'audioses|mmdevapi|AudioSes') { $hasAudio = $true; break }
                }
                if (-not $hasAudio) { continue }
            } catch { continue }
            $name = $proc.ProcessName + '.exe'
            $isWhitelisted = $script:SurveillanceWhitelist -contains $name.ToLower()
            $reason = $null
            if (-not $isWhitelisted) {
                $reason = 'Ha caricato librerie audio (non prova che stia registrando): verificare in "in uso adesso"'
            }
            $procPath = $null; try { $procPath = $proc.Path } catch { Write-Verbose "Path non leggibile: $($proc.Id)" }
            $procStart = $null; try { $procStart = $proc.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch { Write-Verbose "StartTime non leggibile: $($proc.Id)" }
            $result += [PSCustomObject]@{
                ProcessName = $proc.ProcessName
                PID         = $proc.Id
                Path        = $procPath
                StartTime   = $procStart
                Suspicious  = $false
                Informational = (-not $isWhitelisted)
                Reason      = $reason
            }
        }
    } catch { throw }
    return $result
}

# --- 2. Get-WebcamAccess: webcam in uso e virtual camera ---
function Get-WebcamAccess {
    $active = @()
    $virtualCams = @()
    try {
        # Processi che potrebbero usare webcam (moduli video/camera)
        $cameraProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Modules -and ($_.Modules | Where-Object {
                $_.ModuleName -match 'mfplat|msmf|ksproxy|vidcap|avicap'
            })
        }
        foreach ($proc in $cameraProcesses) {
            $name = $proc.ProcessName + '.exe'
            $isWhitelisted = $script:SurveillanceWhitelist -contains $name.ToLower()
            $procPath = $null; try { $procPath = $proc.Path } catch { Write-Verbose "Path non leggibile: $($proc.Id)" }
            $active += [PSCustomObject]@{
                ProcessName = $proc.ProcessName
                PID         = $proc.Id
                Path        = $procPath
                Suspicious  = $false
                Informational = (-not $isWhitelisted)
            }
        }
        # Virtual cameras: driver / software noti
        $pnp = Get-PnpDevice -Class Camera -Status OK -ErrorAction SilentlyContinue
        foreach ($d in $pnp) {
            $fn = ([string]$d.FriendlyName).ToLower()
            if ($fn -match 'obs virtual|manycam|virtual cam|vcam|e2e soft|splitcam|webcamoid|droidcam') {
                $virtualCams += [PSCustomObject]@{
                    DeviceName = $d.FriendlyName
                    Status     = $d.Status
                }
            }
        }
    } catch { throw }
    return @{ ActiveProcesses = $active; VirtualCamerasDetected = $virtualCams }
}

# --- 3. Get-MediaAccessHistory: cronologia microfono/webcam dal registro (ConsentStore) ---
# Include InUseNow: Windows scrive LastUsedTimeStop = 0 finche' il dispositivo e' in uso.
function Get-MediaAccessHistory {
    $micHistory = @()
    $webcamHistory = @()
    $base = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
    $regPaths = @(
        @{ Store = 'microphone'; Path = "$base\microphone\NonPackaged" }
        @{ Store = 'microphone'; Path = "$base\microphone" }
        @{ Store = 'webcam';     Path = "$base\webcam\NonPackaged" }
        @{ Store = 'webcam';     Path = "$base\webcam" }
    )
    foreach ($entry in $regPaths) {
        $items = Get-ChildItem $entry.Path -ErrorAction SilentlyContinue
        foreach ($key in $items) {
            if ($key.PSChildName -eq 'NonPackaged') { continue }
            $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $start = 0; $stop = 0
            if ($null -ne $props.LastUsedTimeStart) { $start = [long]$props.LastUsedTimeStart }
            if ($null -ne $props.LastUsedTimeStop)  { $stop  = [long]$props.LastUsedTimeStop }
            $obj = ConvertFrom-DVConsentEntry -Store $entry.Store -KeyName $key.PSChildName `
                -StartFileTime $start -StopFileTime $stop -Value ([string]$props.Value)
            if (-not $obj) { continue }
            if ($entry.Store -eq 'microphone') { $micHistory += $obj } else { $webcamHistory += $obj }
        }
    }
    return @{ Microphone = $micHistory; Webcam = $webcamHistory }
}

# --- 4. Get-VirtualAudioDevices ---
function Get-VirtualAudioDevices {
    $result = @()
    try {
        $devices = Get-PnpDevice -Class AudioEndpoint -Status OK -ErrorAction SilentlyContinue
        foreach ($d in $devices) {
            $name = ([string]$d.FriendlyName).ToLower()
            $suspicious = $script:VirtualAudioKeywords | Where-Object { $name -match [regex]::Escape($_) }
            if ($suspicious) {
                $reason = 'Dispositivo audio virtuale: puo'' essere software legittimo (streaming, videoconferenza) ma permette anche di reindirizzare l''audio verso programmi di registrazione'
                $result += [PSCustomObject]@{
                    DeviceName = $d.FriendlyName
                    Status     = $d.Status
                    Risk       = 'MEDIO'
                    Reason     = $reason
                }
            }
        }
    } catch { throw }
    return $result
}

# --- 5. Get-AudioSpywareSigns (Get-AudioSpywareIndicators) ---
function Get-AudioSpywareSigns {
    $result = @()
    $appData = [Environment]::GetFolderPath('ApplicationData')
    try {
        # File sospetti in AppData (solo primo livello + figli diretti, per evitare timeout)
        $files = @()
        $files += Get-ChildItem -Path $appData -File -ErrorAction SilentlyContinue |
            Where-Object {
                $fn = $_.Name.ToLower()
                $script:SpywareFileKeywords | Where-Object { $fn -match $_ }
            }
        $topDirs = Get-ChildItem -Path $appData -Directory -ErrorAction SilentlyContinue
        foreach ($dir in $topDirs) {
            $files += Get-ChildItem -Path $dir.FullName -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $fn = $_.Name.ToLower()
                    $script:SpywareFileKeywords | Where-Object { $fn -match $_ }
                }
        }
        foreach ($f in $files) {
            $result += [PSCustomObject]@{
                Type   = 'SuspiciousFile'
                Path   = $f.FullName
                Risk   = 'MEDIO'
                Reason = 'File nella cartella utente il cui NOME richiama registrazione/audio: corrispondenza sul nome, non prova di spyware'
            }
        }
    } catch { throw }
    # audiodg.exe con connessioni esterne (richiede admin / netstat)
    try {
        $audiodg = Get-Process -Name 'audiodg' -ErrorAction SilentlyContinue
        if ($audiodg) {
            $conns = Get-NetTCPConnection -OwningProcess $audiodg.Id -ErrorAction SilentlyContinue |
                Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -notmatch '^127\.' }
            if ($conns -and @($conns).Count -gt 0) {
                $result += [PSCustomObject]@{
                    Type   = 'AudiodgExternalConnections'
                    Path   = 'audiodg.exe'
                    Risk   = 'CRITICO'
                    Reason = 'audiodg.exe con connessioni di rete esterne anomale'
                }
            }
        }
    } catch { Write-Verbose "audiodg: controllo rete non disponibile senza privilegi ($($_.Exception.Message))" }
    return $result
}

# --- 6. Get-PrivacyPermissions: permessi microfono/fotocamera Windows ---
function Get-PrivacyPermissions {
    $micEnabled = $null
    $camEnabled = $null
    $micApps = @()
    $camApps = @()
    try {
        # ConsentStore: valore globale (Windows 10/11)
        $capPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
        $micVal = (Get-ItemProperty -Path "$capPath\microphone" -Name 'Value' -ErrorAction SilentlyContinue).Value
        $camVal = (Get-ItemProperty -Path "$capPath\webcam" -Name 'Value' -ErrorAction SilentlyContinue).Value
        if ($null -ne $micVal) { $micEnabled = ($micVal -eq 'Allow') }
        if ($null -ne $camVal) { $camEnabled = ($camVal -eq 'Allow') }
        # App con permesso (sottochiavi)
        foreach ($store in @('microphone', 'webcam')) {
            $base = "$capPath\$store"
            $apps = @()
            foreach ($sub in @('', '\NonPackaged')) {
                $full = $base + $sub
                $keys = Get-ChildItem $full -ErrorAction SilentlyContinue
                foreach ($k in $keys) {
                    $val = (Get-ItemProperty -LiteralPath $k.PSPath -Name 'Value' -ErrorAction SilentlyContinue).Value
                    if ($val -eq 'Allow') { $apps += $k.PSChildName }
                }
            }
            if ($store -eq 'microphone') { $micApps = $apps } else { $camApps = $apps }
        }
    } catch { throw }
    return @{
        MicrophoneEnabled = $micEnabled
        WebcamEnabled     = $camEnabled
        AppsWithMicPermission  = $micApps
        AppsWithWebcamPermission = $camApps
    }
}

# --- Applicazioni note per microfono/webcam (confronto sul nome del file) ---
function Test-DVKnownMediaApp {
    param([string]$AppName)
    if (-not $AppName) { return $false }
    $n = $AppName.ToLower()
    if ($script:SurveillanceWhitelist -contains $n) { return $true }
    if ($script:SurveillanceWhitelist -contains ($n + '.exe')) { return $true }
    if ($n -match '^microsoft\.|^windows\.') { return $true }
    return $false
}

# --- Punteggio e findings audio/video: funzione PURA (testabile senza Windows) ---
# Ogni segnalazione e' formulata come elemento DA VERIFICARE, non come accusa.
function Measure-DVSurveillance {
    param(
        [object[]]$MicInUse = @(),
        [object[]]$CamInUse = @(),
        [object[]]$VirtualAudio = @(),
        [object[]]$VirtualCams = @(),
        [object[]]$SpywareIndicators = @(),
        [object[]]$MicAppsWithPermission = @(),
        [object[]]$CamAppsWithPermission = @(),
        [object[]]$Checks = @()
    )
    $score = 0
    $canListen = $false; $canWatch = $false; $canRecordWebcam = $false
    $parts = @(); $findings = @()

    foreach ($m in @($MicInUse | Where-Object { $_ -and -not (Test-DVKnownMediaApp $_.AppName) })) {
        $score += 30; $canListen = $true
        $odd = Test-DVUserWritablePath $m.Path
        if ($odd) { $score += 10 }
        $findings += "[ATTENZIONE] Microfono in uso adesso da un'applicazione non presente nell'elenco delle note: $($m.AppName) ($($m.Path))$(if ($odd) { ' - percorso insolito' }). Verificare se e' un programma che hai avviato tu."
        $parts += 'Microfono in uso da applicazione non nota'
    }
    foreach ($c in @($CamInUse | Where-Object { $_ -and -not (Test-DVKnownMediaApp $_.AppName) })) {
        $score += 30; $canWatch = $true
        $odd = Test-DVUserWritablePath $c.Path
        if ($odd) { $score += 10 }
        $findings += "[ATTENZIONE] Webcam in uso adesso da un'applicazione non presente nell'elenco delle note: $($c.AppName) ($($c.Path))$(if ($odd) { ' - percorso insolito' }). Verificare se e' un programma che hai avviato tu."
        $parts += 'Webcam in uso da applicazione non nota'
    }
    if (@($VirtualAudio).Count -gt 0) {
        $score += 10; $canListen = $true
        $parts += 'Dispositivo audio virtuale presente'
        $findings += "[MEDIO] Dispositivo audio virtuale presente ($(@($VirtualAudio | ForEach-Object { $_.DeviceName }) -join ', ')): puo' essere software legittimo; verificare chi lo ha installato."
        if (@($VirtualAudio | Where-Object { ([string]$_.DeviceName).ToLower() -match 'stereo mix' }).Count -gt 0) {
            $score += 10
            $findings += "[MEDIO] Stereo Mix abilitato: l'audio riprodotto dal PC puo' essere registrato."
        }
    }
    if (@($VirtualCams).Count -gt 0) {
        $score += 10; $canRecordWebcam = $true
        $parts += 'Webcam virtuale presente'
        $findings += "[MEDIO] Webcam virtuale presente: puo' essere software legittimo (es. OBS); verificare chi l'ha installata."
    }
    $oddMic = @($MicAppsWithPermission | Where-Object { $_ -and (Test-DVUserWritablePath (ConvertFrom-DVConsentKeyName $_)) })
    if ($oddMic.Count -gt 0) {
        $score += 15; $parts += 'App in cartella insolita con permesso microfono'
        $findings += "[MEDIO] Applicazione in una cartella insolita con permesso microfono: $((($oddMic | ForEach-Object { ConvertFrom-DVConsentKeyName $_ }) | Select-Object -First 3) -join '; ')"
    }
    $oddCam = @($CamAppsWithPermission | Where-Object { $_ -and (Test-DVUserWritablePath (ConvertFrom-DVConsentKeyName $_)) })
    if ($oddCam.Count -gt 0) {
        $score += 15; $parts += 'App in cartella insolita con permesso webcam'
        $findings += "[MEDIO] Applicazione in una cartella insolita con permesso webcam: $((($oddCam | ForEach-Object { ConvertFrom-DVConsentKeyName $_ }) | Select-Object -First 3) -join '; ')"
    }
    foreach ($sp in @($SpywareIndicators | Where-Object { $_ })) {
        if ($sp.Type -eq 'AudiodgExternalConnections') {
            $score += 35; $parts += 'audiodg.exe con connessioni esterne'
            $findings += "[ALTO] audiodg.exe (servizio audio di Windows) ha connessioni di rete esterne: insolito, da approfondire."
        } else {
            $score += 10; $parts += 'File con nome riconducibile a registrazione audio'
            $findings += "[MEDIO] File il cui nome richiama registrazione/audio: $($sp.Path) (corrispondenza sul nome, non prova di spyware)."
        }
    }

    $notOk = @($Checks | Where-Object { $_ -and $_.Status -ne 'OK' })
    foreach ($ck in $notOk) {
        $findings += "[INFO] Controllo '$($ck.Name)' non completato ($($ck.Status)$(if ($ck.Detail) { ': ' + $ck.Detail })): per questa categoria il risultato NON e' affidabile."
    }

    $level = if ($score -ge 80) { 'CRITICO' } elseif ($score -ge 50) { 'ALTO' } elseif ($score -ge 25) { 'MEDIO' } else { 'BASSO' }
    $summary = if ($parts.Count -gt 0) { (($parts | Select-Object -Unique) -join '; ') }
               elseif ($notOk.Count -gt 0) { "Nessun indicatore rilevato, ma $($notOk.Count) controllo/i non completato/i: esito parziale" }
               else { 'Nessun indicatore di sorveglianza audio/video rilevato' }

    return [PSCustomObject]@{
        Score           = $score
        Level           = $level
        CanListenAudio  = $canListen
        CanWatchScreen  = $canWatch
        CanRecordWebcam = $canRecordWebcam
        Summary         = $summary
        Findings        = @($findings)
    }
}

# --- Wrapper: costruisce SurveillanceCapabilities e OverallAudioVideoRisk ---
function Get-DVSurveillanceCapabilities {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $cMic   = Invoke-DVCheck -Name 'Processi con librerie audio'      -FunctionName 'Get-MicrophoneAccess'
    $cCam   = Invoke-DVCheck -Name 'Processi con librerie video'      -FunctionName 'Get-WebcamAccess'
    $cHist  = Invoke-DVCheck -Name 'Cronologia microfono/webcam'      -FunctionName 'Get-MediaAccessHistory' -TimeoutMs 8000
    $cVirt  = Invoke-DVCheck -Name 'Dispositivi audio virtuali'       -FunctionName 'Get-VirtualAudioDevices'
    $cSpy   = Invoke-DVCheck -Name 'Indicatori spyware audio'         -FunctionName 'Get-AudioSpywareSigns' -TimeoutMs 15000
    $cPriv  = Invoke-DVCheck -Name 'Permessi privacy Windows'         -FunctionName 'Get-PrivacyPermissions'
    $checks = @($cMic, $cCam, $cHist, $cVirt, $cSpy, $cPriv)

    $micAccess = @($cMic.Data)
    $webcamData = @{ ActiveProcesses = @(); VirtualCamerasDetected = @() }
    if ($cCam.Status -eq 'OK' -and $cCam.Data.Count -gt 0 -and $cCam.Data[0]) { $webcamData = $cCam.Data[0] }
    $micHistory = @(); $webcamHistory = @()
    if ($cHist.Status -eq 'OK' -and $cHist.Data.Count -gt 0 -and $cHist.Data[0]) {
        $micHistory = @($cHist.Data[0].Microphone)
        $webcamHistory = @($cHist.Data[0].Webcam)
    }
    $virtualAudio = @($cVirt.Data)
    $spywareIndicators = @($cSpy.Data)
    $privacy = @{ MicrophoneEnabled = $null; WebcamEnabled = $null; AppsWithMicPermission = @(); AppsWithWebcamPermission = @() }
    if ($cPriv.Status -eq 'OK' -and $cPriv.Data.Count -gt 0 -and $cPriv.Data[0]) { $privacy = $cPriv.Data[0] }

    $micInUse = @($micHistory | Where-Object { $_ -and $_.InUseNow })
    $camInUse = @($webcamHistory | Where-Object { $_ -and $_.InUseNow })

    $av = Measure-DVSurveillance -MicInUse $micInUse -CamInUse $camInUse `
        -VirtualAudio $virtualAudio -VirtualCams @($webcamData.VirtualCamerasDetected) `
        -SpywareIndicators $spywareIndicators `
        -MicAppsWithPermission @($privacy.AppsWithMicPermission) `
        -CamAppsWithPermission @($privacy.AppsWithWebcamPermission) -Checks $checks

    $overall = [PSCustomObject]@{
        Score           = $av.Score
        Level           = $av.Level
        CanListenAudio  = $av.CanListenAudio
        CanWatchScreen  = $av.CanWatchScreen
        CanRecordWebcam = $av.CanRecordWebcam
        Summary         = $av.Summary
    }

    $recentMic = @($micHistory | ForEach-Object {
        [PSCustomObject]@{ AppName = $_.AppName; LastUsed = $_.LastUsedStart; Duration = $_.Duration; InUseNow = $_.InUseNow }
    })

    $microphoneBlock = [PSCustomObject]@{
        CurrentlyInUse     = ($micInUse.Count -gt 0)
        ActiveProcesses    = $micInUse
        ProcessesWithAudioLibraries = $micAccess
        PermissionEnabled  = $privacy.MicrophoneEnabled
        AppsWithPermission = $privacy.AppsWithMicPermission
        RecentAccess       = $recentMic
    }
    $webcamBlock = [PSCustomObject]@{
        CurrentlyInUse     = ($camInUse.Count -gt 0)
        ActiveProcesses    = $camInUse
        ProcessesWithVideoLibraries = @($webcamData.ActiveProcesses)
        PermissionEnabled  = $privacy.WebcamEnabled
        AppsWithPermission = $privacy.AppsWithWebcamPermission
        VirtualCamerasDetected = $webcamData.VirtualCamerasDetected
    }

    return [PSCustomObject]@{
        Timestamp              = $ts
        Microphone             = $microphoneBlock
        Webcam                 = $webcamBlock
        VirtualAudioDevices    = $virtualAudio
        AudioSpywareIndicators = $spywareIndicators
        OverallAudioVideoRisk  = $overall
        SurveillanceFindings   = @($av.Findings)
        Checks                 = @($checks | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Status = $_.Status; Detail = $_.Detail; Ms = $_.Ms } })
    }
}

Export-ModuleMember -Function Get-MicrophoneAccess, Get-WebcamAccess, Get-MediaAccessHistory,
    Get-VirtualAudioDevices, Get-AudioSpywareSigns, Get-PrivacyPermissions, Get-DVSurveillanceCapabilities,
    Invoke-DVCheck, ConvertFrom-DVConsentKeyName, ConvertFrom-DVConsentEntry, Test-DVUserWritablePath,
    Test-DVKnownMediaApp, Measure-DVSurveillance
