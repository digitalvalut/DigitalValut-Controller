BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\AuthenticodeChecker.psm1") -Force
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\ModuleAnalyzer.psm1") -Force
}

Describe "Test-DVModulePathSuspicious" {
    It "non segnala le DLL di sistema" {
        (Test-DVModulePathSuspicious -Path "C:\Windows\System32\kernel32.dll").Suspicious | Should -BeFalse
    }

    It "non segnala le DLL installate in Program Files" {
        (Test-DVModulePathSuspicious -Path "C:\Program Files\Contoso\app.dll").Suspicious | Should -BeFalse
    }

    It "segnala una DLL caricata dalla cartella temporanea dell'utente" {
        $r = Test-DVModulePathSuspicious -Path "C:\Users\tizio\AppData\Local\Temp\strana.dll"
        $r.Suspicious | Should -BeTrue
        $r.Reason | Should -Not -BeNullOrEmpty
    }

    It "segnala una DLL caricata dalla cartella pubblica" {
        (Test-DVModulePathSuspicious -Path "C:\Users\Public\payload.dll").Suspicious | Should -BeTrue
    }

    It "segnala una DLL nel cestino" {
        (Test-DVModulePathSuspicious -Path "C:\`$Recycle.Bin\S-1-5-21\evil.dll").Suspicious | Should -BeTrue
    }

    It "NON segnala i vendor noti che usano legittimamente AppData (evita falsi positivi)" {
        (Test-DVModulePathSuspicious -Path "C:\Users\tizio\AppData\Local\Google\Chrome\Application\chrome_elf.dll").Suspicious | Should -BeFalse
        (Test-DVModulePathSuspicious -Path "C:\Users\tizio\AppData\Local\Microsoft\Teams\lib.dll").Suspicious | Should -BeFalse
        (Test-DVModulePathSuspicious -Path "C:\Users\tizio\AppData\Local\Discord\app-1.0\d3d.dll").Suspicious | Should -BeFalse
    }

    It "l'esclusione dei vendor noti ha la precedenza anche su percorsi temp annidati" {
        # Un vendor noto resta escluso anche se il percorso contiene 'temp' altrove
        (Test-DVModulePathSuspicious -Path "C:\Users\x\AppData\Local\Google\Chrome\Temp\a.dll").Suspicious | Should -BeFalse
    }

    It "gestisce percorsi vuoti o nulli senza errori" {
        { Test-DVModulePathSuspicious -Path "" } | Should -Not -Throw
        (Test-DVModulePathSuspicious -Path "").Suspicious | Should -BeFalse
        (Test-DVModulePathSuspicious -Path $null).Suspicious | Should -BeFalse
    }
}

Describe "Get-DVModuleFindings" {
    It "viene eseguita end-to-end senza sollevare eccezioni" {
        { Get-DVModuleFindings -MaxProcesses 10 } | Should -Not -Throw
    }

    It "restituisce sempre la struttura attesa" {
        $r = Get-DVModuleFindings -MaxProcesses 10
        $r.Keys | Should -Contain "SuspiciousModules"
        $r.Keys | Should -Contain "Score"
        $r.Keys | Should -Contain "Findings"
        $r.Keys | Should -Contain "ProcessesAnalyzed"
        $r.Score | Should -BeOfType [int]
    }

    It "il punteggio non e' mai negativo" {
        (Get-DVModuleFindings -MaxProcesses 10).Score | Should -BeGreaterOrEqual 0
    }
}
