BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\AuthenticodeChecker.psm1") -Force
    # Impostata qui (fase Run), non a livello di script: le variabili definite fuori da
    # BeforeAll/BeforeEach non sono garantite disponibili dentro i blocchi It in Pester 5/6,
    # perche' Discovery e Run sono invocazioni separate del container.
    $script:SystemSignedExe = Join-Path $env:WINDIR "System32\notepad.exe"
}

Describe "Get-DVProcessSignature" {
    It "restituisce Inaccessible per un percorso vuoto" {
        $result = Get-DVProcessSignature -Path ""
        $result.Status | Should -Be "Inaccessible"
    }

    It "restituisce Inaccessible per un percorso inesistente" {
        $result = Get-DVProcessSignature -Path "C:\percorso\che\non\esiste\fake.exe"
        $result.Status | Should -Be "Inaccessible"
    }

    It "riconosce come Valid un eseguibile di sistema firmato Microsoft" {
        # Skip valutato a runtime (non con il parametro -Skip, che gira in fase di
        # discovery quando ne' BeforeAll ne' $env:WINDIR locale sono garantiti disponibili).
        if (-not (Test-Path $script:SystemSignedExe)) {
            Set-ItResult -Skipped -Because "notepad.exe non trovato in questo ambiente"
            return
        }
        $result = Get-DVProcessSignature -Path $script:SystemSignedExe
        $result.Status | Should -Be "Valid"
        $result.IsMicrosoftSigned | Should -BeTrue
        $result.SignerSubject | Should -Match "Microsoft"
    }
}

Describe "Add-DVSignatureInfo" {
    It "arricchisce ogni elemento con SignatureStatus e SignerSubject" {
        $entries = @(
            @{ ProcessName = "notepad"; Path = $script:SystemSignedExe }
            @{ ProcessName = "fantomatico"; Path = "C:\non\esiste.exe" }
        )
        $result = Add-DVSignatureInfo -Entries $entries

        $result[0].SignatureStatus | Should -Not -BeNullOrEmpty
        $result[1].SignatureStatus | Should -Be "Inaccessible"
    }

    It "gestisce correttamente un elenco vuoto senza errori" {
        { Add-DVSignatureInfo -Entries @() } | Should -Not -Throw
    }

    It "usa la cache: non richiama la verifica due volte per lo stesso percorso" {
        $entries = @(
            @{ ProcessName = "a"; Path = $script:SystemSignedExe }
            @{ ProcessName = "b"; Path = $script:SystemSignedExe }
        )
        $result = Add-DVSignatureInfo -Entries $entries
        $result[0].SignatureStatus | Should -Be $result[1].SignatureStatus
    }
}
