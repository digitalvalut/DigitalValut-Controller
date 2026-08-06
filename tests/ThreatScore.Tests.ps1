BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\ReportGenerator.psm1") -Force
}

Describe "Get-DVThreatScore - livelli di rischio" {
    It "restituisce SICURO con punteggio 0" {
        $result = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $null -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $result.Score | Should -Be 0
        $result.Level.Text | Should -Be "SICURO"
    }

    It "restituisce BASSO tra 1 e 29" {
        $portAnalysis = @{ SuspiciousPorts = @(@{ Port = 22; Name = "SSH"; Risk = "MEDIUM" }) }
        $result = Get-DVThreatScore -PortAnalysis $portAnalysis -ProcessAnalysis $null -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $result.Score | Should -Be 10
        $result.Level.Text | Should -Be "BASSO"
    }

    It "restituisce CRITICO con punteggio 100+" {
        $processAnalysis = @{ RemoteControl = @(); Spyware = @(@{ Name = "Keylogger" }); EmployeeMonitor = @(); OtherSuspicious = @() }
        $result = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $processAnalysis -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $result.Score | Should -BeGreaterOrEqual 100
        $result.Level.Text | Should -Be "CRITICO"
    }

    It "il firewall disattivato aggiunge 25 punti e un finding" {
        $result = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $null -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $false } -NetworkConnections $null
        $result.Score | Should -Be 25
        $result.Findings | Should -Contain "[RISCHIO] Firewall non completamente attivo"
    }
}

Describe "Get-DVThreatScore - integrazione persistenza avanzata" {
    It "somma il punteggio di persistenza al totale" {
        $persistence = @{ Score = 40; Findings = @("[PERSISTENZA] Debugger IFEO su sethc.exe: cmd.exe") }
        $result = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $null -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null `
            -PersistenceFindings $persistence
        $result.Score | Should -Be 40
        $result.Findings | Should -Contain "[PERSISTENZA] Debugger IFEO su sethc.exe: cmd.exe"
    }

    It "ignora PersistenceFindings con Score 0" {
        $persistence = @{ Score = 0; Findings = @() }
        $result = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $null -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null `
            -PersistenceFindings $persistence
        $result.Score | Should -Be 0
    }
}

Describe "Get-DVThreatScore - integrazione firma digitale" {
    It "penalizza un processo di controllo remoto senza firma valida" {
        $processAnalysis = @{
            RemoteControl = @(@{ Name = "FakeVNC"; Risk = "CRITICAL"; ProcessName = "fakevnc"; SignatureStatus = "NotSigned" })
            Spyware = @(); EmployeeMonitor = @(); OtherSuspicious = @()
        }
        $result = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $processAnalysis -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $result.Findings | Where-Object { $_ -match "\[FIRMA\]" } | Should -Not -BeNullOrEmpty
    }

    It "non penalizza un processo con firma valida" {
        $processAnalysis = @{
            RemoteControl = @(@{ Name = "TeamViewer"; Risk = "CRITICAL"; ProcessName = "teamviewer"; SignatureStatus = "Valid" })
            Spyware = @(); EmployeeMonitor = @(); OtherSuspicious = @()
        }
        $result = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $processAnalysis -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $result.Findings | Where-Object { $_ -match "\[FIRMA\]" } | Should -BeNullOrEmpty
    }
}
