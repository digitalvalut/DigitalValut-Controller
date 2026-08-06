BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\ChainOfCustody.psm1") -Force
    $script:TestDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dvtest_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null
}

AfterAll {
    if (Test-Path $script:TestDir) { Remove-Item -Path $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe "Get-DVContentHash" {
    It "produce lo stesso hash SHA-256 per lo stesso contenuto" {
        $h1 = Get-DVContentHash -Content "test-content-123"
        $h2 = Get-DVContentHash -Content "test-content-123"
        $h1 | Should -Be $h2
    }

    It "produce hash diversi per contenuti diversi" {
        $h1 = Get-DVContentHash -Content "contenuto-a"
        $h2 = Get-DVContentHash -Content "contenuto-b"
        $h1 | Should -Not -Be $h2
    }

    It "restituisce una stringa esadecimale di 64 caratteri (SHA-256)" {
        $h = Get-DVContentHash -Content "qualsiasi"
        $h | Should -Match '^[0-9a-f]{64}$'
    }
}

Describe "Get-DVLedgerPath" {
    It "compone correttamente il percorso del registro" {
        $path = Get-DVLedgerPath -ReportDir "C:\Reports"
        $path | Should -Be (Join-Path "C:\Reports" "chain_of_custody.jsonl")
    }
}

Describe "Add-DVCustodyRecord e Test-DVChainIntegrity" {
    BeforeEach {
        $script:LedgerPath = Join-Path $script:TestDir ("ledger_" + [guid]::NewGuid().ToString("N") + ".jsonl")
        $script:SysInfo = @{ ComputerName = "TESTPC"; UserName = "tester"; Domain = "WORKGROUP" }
    }

    It "un registro inesistente e' considerato valido (nessun record)" {
        $result = Test-DVChainIntegrity -LedgerPath $script:LedgerPath
        $result.Valid | Should -BeTrue
        $result.TotalEntries | Should -Be 0
    }

    It "una catena con un solo record e' valida" {
        Add-DVCustodyRecord -LedgerPath $script:LedgerPath -ReportFileName "r1.html" -ReportFileHash "abc123" `
            -SystemInfo $script:SysInfo -ThreatScore 10 -ThreatLevel "BASSO" | Out-Null
        $result = Test-DVChainIntegrity -LedgerPath $script:LedgerPath
        $result.Valid | Should -BeTrue
        $result.TotalEntries | Should -Be 1
    }

    It "una catena con piu' record concatenati correttamente e' valida" {
        1..5 | ForEach-Object {
            Add-DVCustodyRecord -LedgerPath $script:LedgerPath -ReportFileName "r$_.html" -ReportFileHash "hash$_" `
                -SystemInfo $script:SysInfo -ThreatScore ($_ * 10) -ThreatLevel "BASSO" | Out-Null
        }
        $result = Test-DVChainIntegrity -LedgerPath $script:LedgerPath
        $result.Valid | Should -BeTrue
        $result.TotalEntries | Should -Be 5
    }

    It "rileva la manomissione di un record esistente (contenuto alterato dopo la scrittura)" {
        Add-DVCustodyRecord -LedgerPath $script:LedgerPath -ReportFileName "r1.html" -ReportFileHash "abc123" `
            -SystemInfo $script:SysInfo -ThreatScore 10 -ThreatLevel "BASSO" | Out-Null
        Add-DVCustodyRecord -LedgerPath $script:LedgerPath -ReportFileName "r2.html" -ReportFileHash "def456" `
            -SystemInfo $script:SysInfo -ThreatScore 20 -ThreatLevel "MEDIO" | Out-Null

        # Manomissione: altero il punteggio nel primo record senza ricalcolare l'hash
        $lines = Get-Content $script:LedgerPath
        $tampered = $lines[0] -replace '"ThreatScore":10', '"ThreatScore":9999'
        $lines[0] = $tampered
        Set-Content -Path $script:LedgerPath -Value $lines -Encoding UTF8

        $result = Test-DVChainIntegrity -LedgerPath $script:LedgerPath
        $result.Valid | Should -BeFalse
    }

    It "rileva la rimozione di un record intermedio" {
        1..3 | ForEach-Object {
            Add-DVCustodyRecord -LedgerPath $script:LedgerPath -ReportFileName "r$_.html" -ReportFileHash "hash$_" `
                -SystemInfo $script:SysInfo -ThreatScore ($_ * 10) -ThreatLevel "BASSO" | Out-Null
        }
        $lines = Get-Content $script:LedgerPath
        $withoutMiddle = @($lines[0], $lines[2])
        Set-Content -Path $script:LedgerPath -Value $withoutMiddle -Encoding UTF8

        $result = Test-DVChainIntegrity -LedgerPath $script:LedgerPath
        $result.Valid | Should -BeFalse
    }
}

Describe "Compare-DVScanFindings" {
    BeforeEach {
        $script:CompareDir = Join-Path $script:TestDir ("cmp_" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $script:CompareDir -Force | Out-Null
        $script:CompareLedger = Join-Path $script:CompareDir "chain_of_custody.jsonl"
        $script:SysInfo = @{ ComputerName = "TESTPC"; UserName = "tester"; Domain = "WORKGROUP" }
    }

    It "restituisce `$null se non esiste alcuna scansione precedente" {
        $result = Compare-DVScanFindings -LedgerPath $script:CompareLedger -ReportDir $script:CompareDir `
            -CurrentScore 50 -CurrentFindings @("finding-1")
        $result | Should -BeNullOrEmpty
    }

    It "individua correttamente nuovi riscontri e riscontri risolti rispetto alla scansione precedente" {
        # Simula la scansione precedente: record nel ledger + file JSON del report
        Add-DVCustodyRecord -LedgerPath $script:CompareLedger -ReportFileName "prev.html" -ReportFileHash "h1" `
            -SystemInfo $script:SysInfo -ThreatScore 40 -ThreatLevel "MEDIO" | Out-Null

        $prevData = @{ ThreatScore = @{ Findings = @("finding-A", "finding-B") } }
        $prevJsonPath = Join-Path $script:CompareDir "prev.json"
        ($prevData | ConvertTo-Json -Depth 5) | Set-Content -Path $prevJsonPath -Encoding UTF8

        $result = Compare-DVScanFindings -LedgerPath $script:CompareLedger -ReportDir $script:CompareDir `
            -CurrentScore 60 -CurrentFindings @("finding-B", "finding-C")

        $result | Should -Not -BeNullOrEmpty
        $result.NewFindings | Should -Contain "finding-C"
        $result.NewFindings | Should -Not -Contain "finding-B"
        $result.ResolvedFindings | Should -Contain "finding-A"
        $result.ScoreDelta | Should -Be 20
        $result.Unchanged | Should -BeFalse
    }

    It "segnala Unchanged quando i findings sono identici" {
        Add-DVCustodyRecord -LedgerPath $script:CompareLedger -ReportFileName "prev.html" -ReportFileHash "h1" `
            -SystemInfo $script:SysInfo -ThreatScore 40 -ThreatLevel "MEDIO" | Out-Null
        $prevData = @{ ThreatScore = @{ Findings = @("finding-A") } }
        (Join-Path $script:CompareDir "prev.json") | ForEach-Object {
            ($prevData | ConvertTo-Json -Depth 5) | Set-Content -Path $_ -Encoding UTF8
        }

        $result = Compare-DVScanFindings -LedgerPath $script:CompareLedger -ReportDir $script:CompareDir `
            -CurrentScore 40 -CurrentFindings @("finding-A")

        $result.Unchanged | Should -BeTrue
    }
}
