# DigitalValut Controller v4.2 - SurveillanceDetector Module
# Modulo rilevamento sorveglianza audio/video
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

$script:SurveillanceWhitelist = @(
    'teams.exe', 'zoom.exe', 'skype.exe', 'discord.exe',
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'slack.exe', 'webex.exe',
    'obs64.exe', 'obs32.exe', 'svchost.exe'
)

$script:VirtualAudioKeywords = @('virtual', 'cable', 'vb-audio', 'voicemeeter', 'stereo mix', 'cable input', 'cable output')
$script:SpywareFileKeywords = @('record', 'audio', 'capture', 'spy', 'monitor')
$script:SurveillanceTimeoutMs = 5000

function Invoke-WithTimeout {
    param([scriptblock]$ScriptBlock)
    try {
        $job = Start-Job -ScriptBlock $ScriptBlock
        $null = Wait-Job $job -Timeout ($script:SurveillanceTimeoutMs / 1000) -ErrorAction SilentlyContinue
        if ($job.State -eq 'Completed') {
            $result = Receive-Job $job
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            return $result
        }
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    } catch { }
    return $null
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
                $reason = 'Processo non riconosciuto con accesso al microfono'
            }
            $procPath = $null; try { $procPath = $proc.Path } catch { }
            $procStart = $null; try { $procStart = $proc.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch { }
            $result += [PSCustomObject]@{
                ProcessName = $proc.ProcessName
                PID         = $proc.Id
                Path        = $procPath
                StartTime   = $procStart
                Suspicious  = -not $isWhitelisted
                Reason      = $reason
            }
        }
    } catch { }
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
            $procPath = $null; try { $procPath = $proc.Path } catch { }
            $active += [PSCustomObject]@{
                ProcessName = $proc.ProcessName
                PID         = $proc.Id
                Path        = $procPath
                Suspicious  = -not $isWhitelisted
            }
        }
        # Virtual cameras: driver / software noti
        $pnp = Get-PnpDevice -Class Camera -Status OK -ErrorAction SilentlyContinue
        foreach ($d in $pnp) {
            $fn = ($d.FriendlyName -or '').ToLower()
            if ($fn -match 'obs virtual|manycam|virtual cam|vcam|e2e soft|splitcam|webcamoid|droidcam') {
                $virtualCams += [PSCustomObject]@{
                    DeviceName = $d.FriendlyName
                    Status     = $d.Status
                }
            }
        }
    } catch { }
    return @{ ActiveProcesses = $active; VirtualCamerasDetected = $virtualCams }
}

# --- 3. Get-MediaAccessHistory: cronologia microfono/webcam dal registro ---
function Get-MediaAccessHistory {
    $micHistory = @()
    $webcamHistory = @()
    $regPaths = @(
        @{ Store = 'microphone'; Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged" }
        @{ Store = 'microphone'; Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" }
        @{ Store = 'webcam';     Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged" }
        @{ Store = 'webcam';     Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" }
    )
    foreach ($entry in $regPaths) {
        try {
            $items = Get-ChildItem $entry.Path -ErrorAction SilentlyContinue
            foreach ($key in $items) {
                $appName = $key.PSChildName
                $start = (Get-ItemProperty -LiteralPath $key.PSPath -Name 'LastUsedTimeStart' -ErrorAction SilentlyContinue).LastUsedTimeStart
                $stop  = (Get-ItemProperty -LiteralPath $key.PSPath -Name 'LastUsedTimeStop'  -ErrorAction SilentlyContinue).LastUsedTimeStop
                if ($start) {
                    $startDt = [DateTime]::FromFileTime([long]$start)
                    $stopDt = $null
                    $duration = ''
                    if ($stop) {
                        $stopDt = [DateTime]::FromFileTime([long]$stop)
                        $duration = ($stopDt - $startDt).ToString().TrimEnd('\.\d+')
                        if (-not $duration) { $duration = 'N/A' }
                    }
                    $obj = [PSCustomObject]@{
                        AppName       = $appName
                        LastUsedStart = $startDt.ToString('yyyy-MM-dd HH:mm:ss')
                        LastUsedStop  = if ($stopDt) { $stopDt.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                        Duration      = $duration
                    }
                    if ($entry.Store -eq 'microphone') { $micHistory += $obj }
                    else { $webcamHistory += $obj }
                }
            }
        } catch { }
    }
    return @{ Microphone = $micHistory; Webcam = $webcamHistory }
}

# --- 4. Get-VirtualAudioDevices ---
function Get-VirtualAudioDevices {
    $result = @()
    try {
        $devices = Get-PnpDevice -Class AudioEndpoint -Status OK -ErrorAction SilentlyContinue
        foreach ($d in $devices) {
            $name = ($d.FriendlyName -or '').ToLower()
            $suspicious = $script:VirtualAudioKeywords | Where-Object { $name -match [regex]::Escape($_) }
            if ($suspicious) {
                $reason = 'Può redirigere audio a software di registrazione nascosti'
                $result += [PSCustomObject]@{
                    DeviceName = $d.FriendlyName
                    Status     = $d.Status
                    Risk       = 'ALTO'
                    Reason     = $reason
                }
            }
        }
    } catch { }
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
                Risk   = 'CRITICO'
                Reason = 'File sospetto nella cartella utente con nome relativo a registrazione/audio'
            }
        }
    } catch { }
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
    } catch { }
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
    } catch { }
    return @{
        MicrophoneEnabled = $micEnabled
        WebcamEnabled     = $camEnabled
        AppsWithMicPermission  = $micApps
        AppsWithWebcamPermission = $camApps
    }
}

# --- Wrapper: costruisce SurveillanceCapabilities e OverallAudioVideoRisk ---
function Get-DVSurveillanceCapabilities {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $micAccess = @()
    $webcamData = @{ ActiveProcesses = @(); VirtualCamerasDetected = @() }
    $micHistory = @()
    $webcamHistory = @()
    $virtualAudio = @()
    $spywareIndicators = @()
    $privacy = @{ MicrophoneEnabled = $null; WebcamEnabled = $null; AppsWithMicPermission = @(); AppsWithWebcamPermission = @() }

    $micAccess = Invoke-WithTimeout { Get-MicrophoneAccess }
    if (-not $micAccess) { $micAccess = @() }

    $webcamResult = Invoke-WithTimeout { Get-WebcamAccess }
    if ($webcamResult) {
        $webcamData = $webcamResult
    }

    $history = Invoke-WithTimeout { Get-MediaAccessHistory }
    if ($history) {
        $micHistory = $history.Microphone
        $webcamHistory = $history.Webcam
    }

    $virtualAudio = Invoke-WithTimeout { Get-VirtualAudioDevices }
    if (-not $virtualAudio) { $virtualAudio = @() }

    $spywareIndicators = Invoke-WithTimeout { Get-AudioSpywareSigns }
    if (-not $spywareIndicators) { $spywareIndicators = @() }

    $privacy = Invoke-WithTimeout { Get-PrivacyPermissions }
    if (-not $privacy) {
        $privacy = @{ MicrophoneEnabled = $null; WebcamEnabled = $null; AppsWithMicPermission = @(); AppsWithWebcamPermission = @() }
    }

    # Recent access per microfono (per output JSON)
    $recentMic = $micHistory | ForEach-Object {
        [PSCustomObject]@{
            AppName   = $_.AppName
            LastUsed  = $_.LastUsedStart
            Duration  = $_.Duration
        }
    }

    # Calcolo risk score e summary audio/video
    $score = 0
    $canListen = $false
    $canWatch = $false
    $canRecordWebcam = $false
    $summaryParts = @()

    $suspMic = @($micAccess | Where-Object { $_.Suspicious })
    if ($suspMic.Count -gt 0) {
        $score += 30
        $canListen = $true
        $summaryParts += 'Rilevato accesso microfono da processo sconosciuto'
    }
    $suspWebcam = @($webcamData.ActiveProcesses | Where-Object { $_.Suspicious })
    if ($suspWebcam.Count -gt 0) {
        $score += 30
        $canWatch = $true
        $summaryParts += 'Rilevato accesso webcam da processo sconosciuto'
    }
    if ($virtualAudio.Count -gt 0) {
        $score += 20
        $canListen = $true
        $summaryParts += 'Virtual audio cable installato'
    }
    if ($webcamData.VirtualCamerasDetected -and $webcamData.VirtualCamerasDetected.Count -gt 0) {
        $score += 15
        $canRecordWebcam = $true
    }
    # Stereo Mix nei virtual devices
    $stereoMix = $virtualAudio | Where-Object { ($_.DeviceName -or '').ToLower() -match 'stereo mix' }
    if ($stereoMix) { $score += 10 }
    # App sconosciute con permesso
    $knownApps = $script:SurveillanceWhitelist -replace '\.exe$',''
    $unknownMicApps = @($privacy.AppsWithMicPermission | Where-Object {
        $a = $_.ToLower()
        $knownApps -notcontains $a -and ($a -notmatch '^microsoft\.|^windows\.')
    })
    if ($unknownMicApps.Count -gt 0) { $score += 15; $summaryParts += 'App sconosciuta con permesso microfono' }
    $unknownCamApps = @($privacy.AppsWithWebcamPermission | Where-Object {
        $a = $_.ToLower()
        $knownApps -notcontains $a -and ($a -notmatch '^microsoft\.|^windows\.')
    })
    if ($unknownCamApps.Count -gt 0) { $score += 15; $summaryParts += 'App sconosciuta con permesso webcam' }
    if ($spywareIndicators.Count -gt 0) {
        $score += 25
        $summaryParts += 'File o indicatori spyware audio rilevati'
    }
    $audiodgCritical = @($spywareIndicators | Where-Object { $_.Type -eq 'AudiodgExternalConnections' })
    if ($audiodgCritical.Count -gt 0) { $score += 35 }

    $level = if ($score -ge 80) { 'CRITICO' } elseif ($score -ge 50) { 'ALTO' } elseif ($score -ge 25) { 'MEDIO' } else { 'BASSO' }
    $summary = if ($summaryParts.Count -gt 0) { ($summaryParts -join '; ') } else { 'Nessun indicatore di sorveglianza audio/video rilevato' }

    $overall = [PSCustomObject]@{
        Score           = $score
        Level           = $level
        CanListenAudio  = $canListen
        CanWatchScreen  = $canWatch
        CanRecordWebcam = $canRecordWebcam
        Summary         = $summary
    }

    # Findings per report (formato richiesto)
    $survFindings = @()
    foreach ($p in $suspMic) {
        $survFindings += "[CRITICO] Microfono attivo: processo sconosciuto ($($p.ProcessName).exe)"
    }
    foreach ($p in $suspWebcam) {
        $survFindings += "[CRITICO] Webcam attiva: processo sconosciuto ($($p.ProcessName).exe)"
    }
    if ($virtualAudio.Count -gt 0) {
        $survFindings += "[ALTO] Virtual Audio Cable rilevato: possibile intercettazione audio"
    }
    if ($stereoMix) {
        $survFindings += "[MEDIO] Stereo Mix abilitato: audio può essere registrato"
    }
    if ($spywareIndicators.Count -gt 0) {
        foreach ($s in $spywareIndicators) {
            if ($s.Type -eq 'AudiodgExternalConnections') {
                $survFindings += "[CRITICO] audiodg.exe con connessioni esterne: possibile intercettazione"
            } else {
                $survFindings += "[CRITICO] File sospetto rilevato: $($s.Path)"
            }
        }
    }
    if ($webcamData.VirtualCamerasDetected -and $webcamData.VirtualCamerasDetected.Count -gt 0) {
        $survFindings += "[MEDIO] Virtual camera rilevata: possibile registrazione video"
    }

    $microphoneBlock = [PSCustomObject]@{
        CurrentlyInUse     = ($micAccess -and $micAccess.Count -gt 0)
        ActiveProcesses   = $micAccess
        PermissionEnabled = $privacy.MicrophoneEnabled
        AppsWithPermission = $privacy.AppsWithMicPermission
        RecentAccess      = @($recentMic)
    }

    $webcamBlock = [PSCustomObject]@{
        CurrentlyInUse     = ($webcamData.ActiveProcesses -and $webcamData.ActiveProcesses.Count -gt 0)
        ActiveProcesses   = $webcamData.ActiveProcesses
        PermissionEnabled = $privacy.WebcamEnabled
        AppsWithPermission = $privacy.AppsWithWebcamPermission
        VirtualCamerasDetected = $webcamData.VirtualCamerasDetected
    }

    return [PSCustomObject]@{
        Timestamp                 = $ts
        Microphone                = $microphoneBlock
        Webcam                    = $webcamBlock
        VirtualAudioDevices       = $virtualAudio
        AudioSpywareIndicators    = $spywareIndicators
        OverallAudioVideoRisk     = $overall
        SurveillanceFindings     = $survFindings
    }
}

Export-ModuleMember -Function Get-MicrophoneAccess, Get-WebcamAccess, Get-MediaAccessHistory,
    Get-VirtualAudioDevices, Get-AudioSpywareSigns, Get-PrivacyPermissions, Get-DVSurveillanceCapabilities
