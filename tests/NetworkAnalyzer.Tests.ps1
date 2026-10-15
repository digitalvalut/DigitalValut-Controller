BeforeAll {
    $script:Root = Join-Path $PSScriptRoot '..'
    Import-Module (Join-Path (Join-Path (Join-Path $script:Root 'core') 'modules') 'NetworkAnalyzer.psm1') -Force
}

Describe "ConvertTo-DVRiskLabel" {
    It "traduce i livelli" {
        ConvertTo-DVRiskLabel -Risk 'CRITICAL' | Should -Be 'CRITICO'
        ConvertTo-DVRiskLabel -Risk 'HIGH' | Should -Be 'ALTO'
        ConvertTo-DVRiskLabel -Risk 'MEDIUM' | Should -Be 'MEDIO'
        ConvertTo-DVRiskLabel -Risk 'LOW' | Should -Be 'BASSO'
        ConvertTo-DVRiskLabel -Risk '' | Should -Be 'BASSO'
    }
}

Describe "ConvertTo-DVRemoteConnectionRecord - niente falsi allarmi sui servizi Windows" {
    It "SMB/RPC/NetBIOS in ascolto (rischio LOW) sono 'servizio standard', rischio BASSO" {
        $r = ConvertTo-DVRemoteConnectionRecord -Kind Listen -LocalPort 445 -PortInfo @{ Name = 'SMB'; Risk = 'LOW' }
        $r.Rischio | Should -Be 'BASSO'
        $r.Stato | Should -Match 'standard'
        $r.Stato | Should -Not -Match 'PRONTO PER'
    }

    It "RDP in ascolto (HIGH) e' 'accetta connessioni', da verificare" {
        $r = ConvertTo-DVRemoteConnectionRecord -Kind Listen -LocalPort 3389 -PortInfo @{ Name = 'RDP'; Risk = 'HIGH' }
        $r.Rischio | Should -Be 'ALTO'
        $r.Stato | Should -Match 'verificare'
    }

    It "connessione stabilita su SMB senza software remoto non genera alcuna riga" {
        $r = ConvertTo-DVRemoteConnectionRecord -Kind Established -LocalPort 445 -PortInfo @{ Name = 'SMB'; Risk = 'LOW' }
        $r | Should -BeNullOrEmpty
    }

    It "connessione con processo di controllo remoto noto: CRITICO ma senza affermazioni assolute" {
        $r = ConvertTo-DVRemoteConnectionRecord -Kind Established -LocalPort 5900 -PortInfo @{ Name = 'VNC'; Risk = 'CRITICAL' } -IsRemoteControlProcess $true -SoftwareName 'UltraVNC'
        $r.Rischio | Should -Be 'CRITICO'
        $r.Stato | Should -Match 'potenzialmente'
        $r.Stato | Should -Not -Match 'POSSONO VEDERE IL TUO SCHERMO'
    }

    It "connessione su porta RDP senza processo noto: rischio della porta" {
        $r = ConvertTo-DVRemoteConnectionRecord -Kind Established -LocalPort 3389 -PortInfo @{ Name = 'RDP'; Risk = 'HIGH' }
        $r.Rischio | Should -Be 'ALTO'
    }
}

Describe "Regole porte: servizi Windows standard" {
    It "135, 139 e 445 hanno rischio LOW nel file regole" {
        $rules = Get-Content -Path (Join-Path (Join-Path (Join-Path $script:Root 'core') 'rules') 'network-ports.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($port in 135, 139, 445) {
            $rule = $rules | Where-Object { @($_.match.ports) -contains $port } | Select-Object -First 1
            $rule.risk | Should -Be 'LOW'
        }
    }

    It "VNC (5900) e RDP (3389) restano a rischio alto" {
        $rules = Get-Content -Path (Join-Path (Join-Path (Join-Path $script:Root 'core') 'rules') 'network-ports.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        ($rules | Where-Object { @($_.match.ports) -contains 5900 }).risk | Should -Be 'CRITICAL'
        ($rules | Where-Object { @($_.match.ports) -contains 3389 }).risk | Should -Be 'HIGH'
    }
}

Describe 'Get-DVOpenPorts (UInt16 vs chiavi Int32, porte LOW escluse)' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..\core\modules\NetworkAnalyzer.psm1') -Force
        function global:Get-NetTCPConnection { param($State, $ErrorAction)
            foreach ($p in 135, 3389, 5900) { [pscustomobject]@{ LocalPort = [uint16]$p } } }
    }
    It 'trova le porte di accesso remoto e salta quelle standard Windows' {
        $db = @{ 135 = @{ Risk = 'LOW'; Name = 'RPC' }; 3389 = @{ Risk = 'HIGH'; Name = 'RDP' }; 5900 = @{ Risk = 'CRITICAL'; Name = 'VNC' } }
        $r = Get-DVOpenPorts -PortsDb $db
        (@($r.SuspiciousPorts | ForEach-Object { $_.Port }) -join ',') | Should -Be '3389,5900'
    }
}

Describe 'Get-DVOpenPorts - attribuzione della porta al processo' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..\core\modules\NetworkAnalyzer.psm1') -Force
        function global:Get-NetTCPConnection { param($State, $ErrorAction)
            @(
                [pscustomobject]@{ LocalPort = [uint16]5900; OwningProcess = [uint32]4564 }
                [pscustomobject]@{ LocalPort = [uint16]5900; OwningProcess = [uint32]4564 }  # IPv4 + IPv6
                [pscustomobject]@{ LocalPort = [uint16]3389; OwningProcess = [uint32]1234 }
            )
        }
        function global:Get-Process { param($Id, $ErrorAction)
            if ($Id -eq 4564) { return [pscustomobject]@{ ProcessName = 'winvnc'; Id = 4564; Path = 'C:\Program Files\uvnc bvba\UltraVNC\winvnc.exe' } }
            if ($Id -eq 1234) { return [pscustomobject]@{ ProcessName = 'svchost'; Id = 1234; Path = 'C:\WINDOWS\system32\svchost.exe' } }
            throw 'processo non trovato'
        }
        $script:db = @{
            3389 = @{ Risk = 'HIGH'; Name = 'RDP' }
            5900 = @{ Risk = 'CRITICAL'; Name = 'VNC' }
        }
    }

    It 'associa a ogni porta il processo che la detiene, con PID e percorso' {
        $r = Get-DVOpenPorts -PortsDb $script:db
        $vnc = @($r.SuspiciousPorts | Where-Object { $_.Port -eq 5900 })[0]
        $vnc.OwnerProcessName | Should -Be 'winvnc'
        $vnc.OwnerProcessId | Should -Be 4564
        $vnc.OwnerPath | Should -Match 'winvnc.exe'
        $vnc.OwnerResolved | Should -BeTrue
    }

    It 'non ripete la stessa porta presente su IPv4 e IPv6' {
        $r = Get-DVOpenPorts -PortsDb $script:db
        @($r.SuspiciousPorts | Where-Object { $_.Port -eq 5900 }).Count | Should -Be 1
    }

    It 'un processo non ispezionabile non blocca il rilievo della porta' {
        function global:Get-NetTCPConnection { param($State, $ErrorAction)
            @([pscustomobject]@{ LocalPort = [uint16]5900; OwningProcess = [uint32]9999 })
        }
        $r = Get-DVOpenPorts -PortsDb $script:db
        @($r.SuspiciousPorts).Count | Should -Be 1
        $r.SuspiciousPorts[0].OwnerProcessId | Should -Be 9999
        $r.SuspiciousPorts[0].OwnerResolved | Should -BeFalse
        $r.SuspiciousPorts[0].OwnerProcessName | Should -BeNullOrEmpty
    }
}
