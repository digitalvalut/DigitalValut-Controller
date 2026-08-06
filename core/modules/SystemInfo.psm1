# DigitalValut Controller v3.0 - SystemInfo Module
# Dr. Giuseppe Falsone - CEO DigitalValut

function Get-DVSystemInfo {
    $info = @{
        ComputerName   = $env:COMPUTERNAME
        UserName       = $env:USERNAME
        Domain         = $env:USERDOMAIN
        OSVersion      = ""
        OSBuild        = ""
        Architecture   = $env:PROCESSOR_ARCHITECTURE
        ScanDate       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TimeZone       = [TimeZoneInfo]::Local.DisplayName
        IPAddress      = ""
        LastBoot       = ""
    }
    
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            $info.OSVersion = $os.Caption
            $info.OSBuild   = $os.BuildNumber
            if ($os.LastBootUpTime) { $info.LastBoot = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss") }
        }
    } catch {
        $info.OSVersion = "Unknown"
        $info.OSBuild   = "N/A"
    }
    
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs -and $cs.Domain) { $info.Domain = $cs.Domain }
    } catch { }
    
    try {
        $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "127.*" } |
            Select-Object -First 1
        if ($ip) { $info.IPAddress = $ip.IPAddress }
    } catch { }
    
    return $info
}

Export-ModuleMember -Function Get-DVSystemInfo
