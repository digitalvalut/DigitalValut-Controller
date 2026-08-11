# DigitalValut Controller v5.0 - SecurityChecker Module
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

function Get-DVFirewallStatus {
    $status = @{
        DomainProfile   = $false
        PrivateProfile  = $false
        PublicProfile   = $false
        AllEnabled      = $false
    }

    try {
        $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        foreach ($fwProfile in $fw) {
            switch ($fwProfile.Name) {
                "Domain"  { $status.DomainProfile  = $fwProfile.Enabled }
                "Private" { $status.PrivateProfile = $fwProfile.Enabled }
                "Public"  { $status.PublicProfile  = $fwProfile.Enabled }
            }
        }
        $status.AllEnabled = $status.DomainProfile -and $status.PrivateProfile -and $status.PublicProfile
    } catch {
        $status.AllEnabled = $false
    }

    return $status
}

function Get-DVAntivirusStatus {
    $results = @()
    try {
        $av = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop
        foreach ($a in $av) {
            $stateHex = "{0:X6}" -f $a.productState
            $enabled = $stateHex.Substring(2, 2) -eq "10"
            $upToDate = $stateHex.Substring(4, 2) -eq "00"
            $results += [PSCustomObject]@{
                Name     = $a.displayName
                Enabled  = $enabled
                UpToDate = $upToDate
                Path     = $a.pathToSignedProductExe
            }
        }
    } catch { }
    return $results
}

function Get-DVRemoteControlCapabilities {
    $capabilities = @{
        PuoVedereLOSchermo    = $false
        PuoUsareMouseTastiera = $false
        PuoLeggereFile       = $false
        PuoTrasferireFile    = $false
        PuoRegistrareSchermo = $false
        PuoVedereClipboard   = $false
        Software             = @()
    }
    try {
        $vncProcesses = Get-Process -Name "*vnc*" -ErrorAction SilentlyContinue
        if ($vncProcesses) {
            $capabilities.PuoVedereLOSchermo = $true
            $capabilities.PuoUsareMouseTastiera = $true
            $capabilities.PuoTrasferireFile = $true
            $capabilities.PuoVedereClipboard = $true
            if ($capabilities.Software -notcontains "VNC (UltraVNC/TightVNC)") { $capabilities.Software += "VNC (UltraVNC/TightVNC)" }
        }
        $tvProcesses = Get-Process -Name "*teamviewer*" -ErrorAction SilentlyContinue
        if ($tvProcesses) {
            $capabilities.PuoVedereLOSchermo = $true
            $capabilities.PuoUsareMouseTastiera = $true
            $capabilities.PuoTrasferireFile = $true
            $capabilities.PuoRegistrareSchermo = $true
            if ($capabilities.Software -notcontains "TeamViewer") { $capabilities.Software += "TeamViewer" }
        }
        $anydesk = Get-Process -Name "*anydesk*" -ErrorAction SilentlyContinue
        if ($anydesk) {
            $capabilities.PuoVedereLOSchermo = $true
            $capabilities.PuoUsareMouseTastiera = $true
            if ($capabilities.Software -notcontains "AnyDesk") { $capabilities.Software += "AnyDesk" }
        }
        $rdpStatus = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
        if ($rdpStatus -eq 0) {
            $capabilities.PuoVedereLOSchermo = $true
            $capabilities.PuoUsareMouseTastiera = $true
            $capabilities.PuoLeggereFile = $true
            if ($capabilities.Software -notcontains "Desktop Remoto Windows (RDP)") { $capabilities.Software += "Desktop Remoto Windows (RDP)" }
        }
    } catch { }
    return $capabilities
}

function Get-DVServicesSuspicious {
    param([hashtable]$ProcessDb)

    $found = @()
    $keys = $ProcessDb.Keys | Where-Object { $ProcessDb[$_].Alert -eq $true }

    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq "Running" } |
            Select-Object Name, DisplayName, State
    } catch {
        return $found
    }

    foreach ($svc in $services) {
        $nameLower = ($svc.Name + " " + $svc.DisplayName).ToLower()
        foreach ($key in $keys) {
            if ($nameLower -like "*$key*") {
                $entry = $ProcessDb[$key].Clone()
                $entry.ServiceName    = $svc.Name
                $entry.DisplayName    = $svc.DisplayName
                $entry.Status         = $svc.State
                $found += $entry
                break
            }
        }
    }

    return $found
}

Export-ModuleMember -Function Get-DVFirewallStatus, Get-DVAntivirusStatus, Get-DVRemoteControlCapabilities, Get-DVServicesSuspicious
