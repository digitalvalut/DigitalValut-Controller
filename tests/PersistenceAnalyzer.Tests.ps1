BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\PersistenceAnalyzer.psm1") -Force
}

Describe "Test-DVKnownWmiConsumer" {
    It "riconosce come noti i pattern SCCM/CCM" {
        Test-DVKnownWmiConsumer -Name "SCCM_SoftwareInventory" | Should -BeTrue
        Test-DVKnownWmiConsumer -Name "CCM_RecentlyUsedApps" | Should -BeTrue
    }

    It "riconosce come noto il consumer standard di Windows" {
        Test-DVKnownWmiConsumer -Name "SCM Event Log Consumer" | Should -BeTrue
    }

    It "non riconosce nomi generici o sospetti" {
        Test-DVKnownWmiConsumer -Name "evil_persistence_xyz" | Should -BeFalse
    }

    It "gestisce nomi nulli o vuoti senza errori" {
        Test-DVKnownWmiConsumer -Name "" | Should -BeFalse
        Test-DVKnownWmiConsumer -Name $null | Should -BeFalse
    }
}

Describe "Get-DVPersistenceFindings - aggregazione punteggio" {
    BeforeEach {
        Mock -ModuleName PersistenceAnalyzer Get-DVWmiPersistence { return @() }
        Mock -ModuleName PersistenceAnalyzer Get-DVAppInitDlls { return @{ Configured = $false; Dlls = @(); Risk = "NONE" } }
        Mock -ModuleName PersistenceAnalyzer Get-DVIFEODebuggers { return @() }
        Mock -ModuleName PersistenceAnalyzer Get-DVSuspiciousScheduledTasks { return @() }
    }

    It "restituisce Score 0 e nessun finding quando non c'e' nulla di sospetto" {
        $result = Get-DVPersistenceFindings
        $result.Score | Should -Be 0
        $result.Findings.Count | Should -Be 0
    }

    It "somma correttamente il punteggio per una sottoscrizione WMI non riconosciuta" {
        Mock -ModuleName PersistenceAnalyzer Get-DVWmiPersistence {
            return @([PSCustomObject]@{ Name = "evil_wmi"; ConsumerType = "CommandLineEventConsumer"; Command = "cmd /c evil.exe"; Known = $false; Risk = "HIGH" })
        }
        $result = Get-DVPersistenceFindings
        $result.Score | Should -Be 20
        $result.Findings.Count | Should -Be 1
    }

    It "non conteggia le sottoscrizioni WMI riconosciute come note" {
        Mock -ModuleName PersistenceAnalyzer Get-DVWmiPersistence {
            return @([PSCustomObject]@{ Name = "SCCM_Task"; ConsumerType = "CommandLineEventConsumer"; Command = "sccm.exe"; Known = $true; Risk = "LOW" })
        }
        $result = Get-DVPersistenceFindings
        $result.Score | Should -Be 0
    }

    It "assegna punteggio elevato ad AppInit_DLLs attivo" {
        Mock -ModuleName PersistenceAnalyzer Get-DVAppInitDlls { return @{ Configured = $true; Dlls = @("evil.dll"); Risk = "HIGH" } }
        $result = Get-DVPersistenceFindings
        $result.Score | Should -Be 30
    }

    It "assegna il punteggio piu' alto a un debugger IFEO (hijacking)" {
        Mock -ModuleName PersistenceAnalyzer Get-DVIFEODebuggers {
            return @([PSCustomObject]@{ TargetExecutable = "sethc.exe"; Debugger = "cmd.exe"; Risk = "CRITICAL" })
        }
        $result = Get-DVPersistenceFindings
        $result.Score | Should -Be 40
        $result.Findings[0] | Should -Match "sethc.exe"
    }

    It "somma i punteggi quando sono presenti piu' categorie di riscontri" {
        Mock -ModuleName PersistenceAnalyzer Get-DVAppInitDlls { return @{ Configured = $true; Dlls = @("x.dll"); Risk = "HIGH" } }
        Mock -ModuleName PersistenceAnalyzer Get-DVIFEODebuggers {
            return @([PSCustomObject]@{ TargetExecutable = "utilman.exe"; Debugger = "cmd.exe"; Risk = "CRITICAL" })
        }
        $result = Get-DVPersistenceFindings
        $result.Score | Should -Be 70
        $result.Findings.Count | Should -Be 2
    }
}

Describe "Get-DVPersistenceFindings - esecuzione reale senza mock" {
    It "viene eseguita end-to-end senza sollevare eccezioni" {
        { Get-DVPersistenceFindings } | Should -Not -Throw
    }

    It "restituisce sempre le chiavi attese nella forma corretta" {
        $result = Get-DVPersistenceFindings
        $result.Keys | Should -Contain "Score"
        $result.Keys | Should -Contain "Findings"
        $result.Keys | Should -Contain "WmiSubscriptions"
        $result.Keys | Should -Contain "AppInitDlls"
        $result.Keys | Should -Contain "IFEODebuggers"
        $result.Keys | Should -Contain "ScheduledTasks"
        $result.Score | Should -BeOfType [int]
    }
}
