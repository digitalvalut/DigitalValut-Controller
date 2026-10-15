# DigitalValut Controller v5.1 - NetworkAnalyzer Module
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

function Resolve-DVPortOwner {
    <#
    .SYNOPSIS
        Risale dal PID che tiene aperta una porta al nome e al percorso dell'eseguibile.
    .DESCRIPTION
        Attribuire una porta in ascolto al processo che la detiene e' cio' che distingue
        un rilievo verificabile ("porta 5900 tenuta aperta da winvnc.exe, PID 4564") da
        una semplice constatazione ("porta 5900 aperta"). Senza privilegi di amministratore
        il percorso dell'eseguibile di processi di altri utenti non e' leggibile: in quel
        caso il campo resta vuoto e va dichiarato, non inventato.
    #>
    param([int]$ProcessId)

    $result = [PSCustomObject]@{
        ProcessId   = $ProcessId
        ProcessName = ''
        Path        = ''
        Resolved    = $false
    }
    if ($ProcessId -le 0) { return $result }

    try {
        $p = Get-Process -Id $ProcessId -ErrorAction Stop
        $result.ProcessName = [string]$p.ProcessName
        $result.Resolved = $true
        try { $result.Path = [string]$p.Path } catch { $result.Path = '' }
    } catch {
        # Il processo puo' essere terminato tra la lettura della porta e questa chiamata,
        # oppure non essere ispezionabile senza privilegi elevati.
        $result.ProcessName = ''
    }
    return $result
}

function Get-DVOpenPorts {
    <#
    .SYNOPSIS
        Elenca le porte in ascolto che corrispondono a una regola di rilevamento.
    .DESCRIPTION
        Fonte tecnica: Get-NetTCPConnection -State Listen.
        Le porte classificate LOW nelle regole (servizi standard di Windows e di dominio,
        es. 135/139/445) sono escluse: segnalarle produce falsi allarmi e indebolisce il
        report. Ogni porta riportata viene attribuita al processo che la detiene.
    #>
    param([hashtable]$PortsDb)

    $suspiciousPorts = @()

    try {
        $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object LocalPort, OwningProcess
    } catch {
        return @{ SuspiciousPorts = $suspiciousPorts; Error = $_.Exception.Message }
    }

    $ownerCache = @{}
    $seenPorts = @{}
    foreach ($conn in @($connections)) {
        $port = [int]$conn.LocalPort   # LocalPort e' UInt16, le chiavi del DB sono Int32
        if (-not $PortsDb.ContainsKey($port)) { continue }
        if ($PortsDb[$port].Risk -eq 'LOW') { continue }
        if ($seenPorts.ContainsKey($port)) { continue }   # stessa porta su IPv4 e IPv6
        $seenPorts[$port] = $true

        $info = $PortsDb[$port].Clone()
        $info.Port = $port

        $ownerPid = 0
        if ($null -ne $conn.OwningProcess) { $ownerPid = [int]$conn.OwningProcess }
        if (-not $ownerCache.ContainsKey($ownerPid)) {
            $ownerCache[$ownerPid] = Resolve-DVPortOwner -ProcessId $ownerPid
        }
        $owner = $ownerCache[$ownerPid]
        $info.OwnerProcessId   = $ownerPid
        $info.OwnerProcessName = $owner.ProcessName
        $info.OwnerPath        = $owner.Path
        $info.OwnerResolved    = $owner.Resolved

        $suspiciousPorts += $info
    }

    return @{ SuspiciousPorts = $suspiciousPorts }
}

function Get-DVNetworkConnections {
    $suspicious = @()
    $conns = $null

    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -notlike "127.*" }

        if ($conns) {
            foreach ($c in $conns) {
                $suspicious += @{
                    LocalAddress  = $c.LocalAddress
                    LocalPort     = $c.LocalPort
                    RemoteAddress = $c.RemoteAddress
                    RemotePort    = $c.RemotePort
                    OwningProcess = $c.OwningProcess
                }
            }
        }
    } catch {
        # Ignore
    }

    return @{ Connections = $conns; Suspicious = $suspicious }
}

function Get-DVExternalConnections {
    $external = @()
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object {
                $_.RemoteAddress -and
                $_.RemoteAddress -ne "127.0.0.1" -and
                $_.RemoteAddress -ne "::1" -and
                $_.RemoteAddress -notlike "192.168.*" -and
                $_.RemoteAddress -notlike "10.*" -and
                $_.RemoteAddress -notlike "172.16.*" -and
                $_.RemoteAddress -notlike "172.17.*" -and
                $_.RemoteAddress -notlike "172.18.*" -and
                $_.RemoteAddress -notlike "169.254.*"
            }
        foreach ($c in $conns) {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            $external += [PSCustomObject]@{
                RemoteIP   = $c.RemoteAddress
                RemotePort = $c.RemotePort
                LocalPort  = $c.LocalPort
                Process    = if ($proc) { $proc.ProcessName } else { "-" }
                PID        = $c.OwningProcess
            }
        }
    } catch { }
    return $external
}

# Traduce il livello di rischio di una regola porta (inglese) in etichetta italiana.
function ConvertTo-DVRiskLabel {
    param([string]$Risk)
    switch ($Risk) {
        'CRITICAL' { return 'CRITICO' }
        'HIGH'     { return 'ALTO' }
        'MEDIUM'   { return 'MEDIO' }
        default    { return 'BASSO' }
    }
}

# Funzione PURA (testabile): decide se e come descrivere una connessione/porta e con
# quale formulazione. Distingue:
#   - servizi Windows standard (RPC/NetBIOS/SMB, rischio LOW): NON sono controllo remoto
#   - porta in ascolto di un software di accesso remoto: "accetta connessioni", da verificare
#   - connessione stabilita: "sessione remota" solo se il processo e' un software remoto noto
#     o la porta e' di accesso remoto; mai l'affermazione assoluta "possono vedere il tuo schermo".
function ConvertTo-DVRemoteConnectionRecord {
    param(
        [Parameter(Mandatory)][ValidateSet('Listen', 'Established')][string]$Kind,
        [int]$LocalPort,
        [object]$PortInfo,
        [bool]$IsRemoteControlProcess = $false,
        [string]$SoftwareName = '-'
    )
    $portRisk = if ($PortInfo -and $PortInfo.Risk) { [string]$PortInfo.Risk } else { '' }
    $isInfrastructure = ($portRisk -eq 'LOW')

    if ($Kind -eq 'Established') {
        if (-not $IsRemoteControlProcess -and ($null -eq $PortInfo -or $isInfrastructure)) { return $null }
        $label = if ($IsRemoteControlProcess) { 'CRITICO' } else { ConvertTo-DVRiskLabel $portRisk }
        return [PSCustomObject]@{
            Stato   = "CONNESSO - sessione su canale di accesso remoto ($SoftwareName): chi e' collegato puo' potenzialmente vedere/usare il PC. Verificare se e' autorizzata."
            Rischio = $label
        }
    }

    # Listen
    if ($isInfrastructure) {
        return [PSCustomObject]@{
            Stato   = "IN ASCOLTO - servizio di rete standard di Windows (normale; non indica controllo remoto)"
            Rischio = 'BASSO'
        }
    }
    return [PSCustomObject]@{
        Stato   = "IN ASCOLTO - accetta connessioni di accesso remoto (verificare se autorizzato; il firewall puo' limitare chi puo' collegarsi)"
        Rischio = (ConvertTo-DVRiskLabel $portRisk)
    }
}

function Get-DVActiveRemoteConnections {
    param(
        [hashtable]$PortsDb,
        [hashtable]$ProcessDb
    )
    $results = @()
    if (-not $PortsDb) { $PortsDb = @{} }
    if (-not $ProcessDb) { $ProcessDb = @{} }
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($conn in $connections) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $isRemoteControl = $false
            $softwareName = if ($process) { $process.ProcessName } else { "-" }
            foreach ($key in $ProcessDb.Keys) {
                if ($process -and $process.ProcessName -like "*$key*") {
                    $isRemoteControl = $true
                    $softwareName = $ProcessDb[$key].Name
                    break
                }
            }
            $portInfo = $null
            if ($PortsDb.ContainsKey([int]$conn.LocalPort)) { $portInfo = $PortsDb[[int]$conn.LocalPort] }
            $rec = ConvertTo-DVRemoteConnectionRecord -Kind Established -LocalPort ([int]$conn.LocalPort) `
                -PortInfo $portInfo -IsRemoteControlProcess $isRemoteControl -SoftwareName $softwareName
            if ($rec) {
                $remoteHost = $conn.RemoteAddress
                try {
                    $dns = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress)
                    $remoteHost = $dns.HostName
                } catch { Write-Verbose "DNS inverso non disponibile per $($conn.RemoteAddress)" }
                $results += [PSCustomObject]@{
                    Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    IPRemoto    = $conn.RemoteAddress
                    HostRemoto  = $remoteHost
                    PortaLocale = $conn.LocalPort
                    PortaRemota = $conn.RemotePort
                    Processo    = $softwareName
                    PID         = $conn.OwningProcess
                    Stato       = $rec.Stato
                    Rischio     = $rec.Rischio
                }
            }
        }
        $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        foreach ($listen in $listening) {
            if ($PortsDb.ContainsKey([int]$listen.LocalPort)) {
                $process = Get-Process -Id $listen.OwningProcess -ErrorAction SilentlyContinue
                $rec = ConvertTo-DVRemoteConnectionRecord -Kind Listen -LocalPort ([int]$listen.LocalPort) `
                    -PortInfo $PortsDb[[int]$listen.LocalPort]
                $results += [PSCustomObject]@{
                    Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    IPRemoto    = "In attesa di connessione"
                    HostRemoto  = "Raggiungibile dalla rete (salvo limiti del firewall)"
                    PortaLocale = $listen.LocalPort
                    PortaRemota = "-"
                    Processo    = if ($process) { $process.ProcessName } else { "-" }
                    PID         = $listen.OwningProcess
                    Stato       = $rec.Stato
                    Rischio     = $rec.Rischio
                }
            }
        }
    } catch { Write-Warning "Analisi connessioni remote non completata: $($_.Exception.Message)" }
    return $results
}

Export-ModuleMember -Function Get-DVOpenPorts, Get-DVNetworkConnections, Get-DVExternalConnections, Get-DVActiveRemoteConnections, ConvertTo-DVRemoteConnectionRecord, ConvertTo-DVRiskLabel, Resolve-DVPortOwner
