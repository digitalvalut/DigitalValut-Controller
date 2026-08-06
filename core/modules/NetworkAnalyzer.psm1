# DigitalValut Controller v4.0 - NetworkAnalyzer Module
# Dr. Giuseppe Falsone - CEO DigitalValut

function Get-DVOpenPorts {
    param([hashtable]$PortsDb)
    
    $suspiciousPorts = @()
    
    try {
        $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object LocalPort -Unique
    } catch {
        return @{ SuspiciousPorts = $suspiciousPorts; Error = $_.Exception.Message }
    }
    
    $listeningPorts = $connections.LocalPort
    foreach ($port in $listeningPorts) {
        if ($PortsDb.ContainsKey($port)) {
            $info = $PortsDb[$port].Clone()
            $info.Port = $port
            $suspiciousPorts += $info
        }
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
            $portInList = $PortsDb.ContainsKey([int]$conn.LocalPort)
            if ($portInList -or $isRemoteControl) {
                $remoteHost = $conn.RemoteAddress
                try {
                    $dns = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress)
                    $remoteHost = $dns.HostName
                } catch { }
                $results += [PSCustomObject]@{
                    Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    IPRemoto    = $conn.RemoteAddress
                    HostRemoto  = $remoteHost
                    PortaLocale = $conn.LocalPort
                    PortaRemota = $conn.RemotePort
                    Processo    = $softwareName
                    PID         = $conn.OwningProcess
                    Stato       = "CONNESSO - POSSONO VEDERE IL TUO SCHERMO"
                    Rischio     = "CRITICO"
                }
            }
        }
        $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        foreach ($listen in $listening) {
            if ($PortsDb.ContainsKey([int]$listen.LocalPort)) {
                $process = Get-Process -Id $listen.OwningProcess -ErrorAction SilentlyContinue
                $results += [PSCustomObject]@{
                    Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    IPRemoto    = "In attesa di connessione"
                    HostRemoto  = "Chiunque nella rete puo' collegarsi"
                    PortaLocale = $listen.LocalPort
                    PortaRemota = "-"
                    Processo    = if ($process) { $process.ProcessName } else { "-" }
                    PID         = $listen.OwningProcess
                    Stato       = "IN ASCOLTO - PRONTO PER CONTROLLO REMOTO"
                    Rischio     = "ALTO"
                }
            }
        }
    } catch { }
    return $results
}

Export-ModuleMember -Function Get-DVOpenPorts, Get-DVNetworkConnections, Get-DVExternalConnections, Get-DVActiveRemoteConnections
