# DigitalValut Controller v5.0 - SystemInfo Module
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

function Get-DVAdminMembership {
    <#
    .SYNOPSIS
        Stabilisce se l'account in uso appartiene al gruppo Amministratori locali.
    .DESCRIPTION
        "Non elevato" NON significa "senza diritti di amministratore": con il Controllo
        account utente (UAC) un amministratore esegue di norma i programmi con un token
        ridotto, nel quale il gruppo Amministratori e' presente ma marcato "solo rifiuto".
        Dichiarare in una richiesta formale di non disporre di privilegi amministrativi,
        quando l'account e' membro del gruppo, sarebbe una affermazione falsa.
        Il SID S-1-5-32-544 compare tra i gruppi del token sia per un amministratore
        con token pieno sia per uno con token ridotto, e non compare per un utente standard.
        Annidamenti (es. Domain Admins nel gruppo locale) sono inclusi nel token.
    .OUTPUTS
        'Si' | 'No' | 'Indeterminato'
    #>
    param([string[]]$GroupSids = $null)
    try {
        if ($null -eq $GroupSids) {
            $GroupSids = @([Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Value })
        }
        if (@($GroupSids).Count -eq 0) { return 'Indeterminato' }
        if (@($GroupSids) -contains 'S-1-5-32-544') { return 'Si' }
        return 'No'
    } catch {
        return 'Indeterminato'
    }
}

Export-ModuleMember -Function Get-DVSystemInfo, Get-DVAdminMembership
