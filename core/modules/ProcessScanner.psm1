# DigitalValut Controller v4.0 - ProcessScanner Module
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

function Get-DVProcessScan {
    param([hashtable]$ThreatDb)
    
    $remoteControl = @()
    $spyware = @()
    $employeeMonitor = @()
    $otherSuspicious = @()
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path, WorkingSet64
    } catch {
        return @{
            RemoteControl   = $remoteControl
            Spyware         = $spyware
            EmployeeMonitor = $employeeMonitor
            OtherSuspicious = $otherSuspicious
            Error           = $_.Exception.Message
        }
    }
    
    foreach ($proc in $processes) {
        $nameLower = $proc.ProcessName.ToLower()
        
        foreach ($key in $ThreatDb.Keys) {
            if ($nameLower -like "*$key*") {
                $entry = $ThreatDb[$key].Clone()
                $entry.ProcessName = $proc.ProcessName
                $entry.ProcessId   = $proc.Id
                $entry.Path        = $proc.Path
                $entry.MemoryMB    = if ($proc.WorkingSet64) { [math]::Round($proc.WorkingSet64 / 1MB, 2) } else { $null }
                
                switch ($entry.Type) {
                    "Remote Control"   { $remoteControl += $entry; break }
                    "Commercial RAT"   { $remoteControl += $entry; break }
                    "Remote Admin"     { $remoteControl += $entry; break }
                    "RMM"              { $remoteControl += $entry; break }
                    "Spyware"          { $spyware += $entry; break }
                    "Employee Monitor" { $employeeMonitor += $entry; break }
                    default            { $otherSuspicious += $entry }
                }
                break
            }
        }
    }
    
    return @{
        RemoteControl   = $remoteControl
        Spyware         = $spyware
        EmployeeMonitor = $employeeMonitor
        OtherSuspicious = $otherSuspicious
    }
}

function Get-DVInstalledSuspiciousSoftware {
    param([hashtable]$ThreatDb)
    
    $found = @()
    $searchKeys = $ThreatDb.Keys | Where-Object { $ThreatDb[$_].Alert -eq $true }
    
    try {
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        $installed = Get-ItemProperty $uninstallPaths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName }
    } catch {
        return $found
    }
    
    foreach ($item in $installed) {
        $nameLower = $item.DisplayName.ToLower()
        foreach ($key in $searchKeys) {
            if ($nameLower -like "*$key*") {
                $entry = $ThreatDb[$key].Clone()
                $entry.DisplayName    = $item.DisplayName
                $entry.DisplayVersion = $item.DisplayVersion
                $entry.Publisher      = $item.Publisher
                $entry.InstallDate    = $item.InstallDate
                $entry.InstallLocation = $item.InstallLocation
                $found += $entry
                break
            }
        }
    }
    
    return $found
}

function Get-DVStartupPrograms {
    $startup = @()
    $regPaths = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $keywords = @("vnc", "remote", "teamviewer", "anydesk", "radmin", "ammyy", "logmein", "splashtop", "parsec", "rustdesk", "supremo", "bomgar", "keylog", "spy")
    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            try {
                $props = Get-ItemProperty $path -ErrorAction SilentlyContinue
                if ($props) {
                    $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                        $cmd = $_.Value
                        $suspicious = $false
                        foreach ($kw in $keywords) { if ($cmd -like "*$kw*") { $suspicious = $true; break } }
                        $startup += [PSCustomObject]@{
                            Name       = $_.Name
                            Command    = $cmd
                            Location   = $path -replace "HKCU:\\|HKLM:\\", ""
                            Suspicious = $suspicious
                        }
                    }
                }
            } catch { }
        }
    }
    try {
        $startupFolder = [Environment]::GetFolderPath("Startup")
        Get-ChildItem $startupFolder -ErrorAction SilentlyContinue | ForEach-Object {
            $startup += [PSCustomObject]@{
                Name       = $_.Name
                Command    = $_.FullName
                Location   = "Startup Folder"
                Suspicious = $false
            }
        }
    } catch { }
    return $startup
}

Export-ModuleMember -Function Get-DVProcessScan, Get-DVInstalledSuspiciousSoftware, Get-DVStartupPrograms
