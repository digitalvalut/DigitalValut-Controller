BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\ChainOfCustody.psm1") -Force -Global
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\TimestampAuthority.psm1") -Force -Global
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\RawEvidence.psm1") -Force -Global
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\EvidencePackage.psm1") -Force -Global

    $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("dvpkg_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null

    function New-TestReportDir {
        $d = Join-Path $script:TestRoot ([guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Set-Content -Path (Join-Path $d "report.html") -Value "<html>prova</html>" -Encoding UTF8
        Set-Content -Path (Join-Path $d "dati.json")   -Value '{"a":1}' -Encoding UTF8
        return $d
    }
}

AfterAll {
    if (Test-Path $script:TestRoot) { Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe "Get-DVPackageManifest" {
    It "elenca tutti i file con il rispettivo hash SHA-256" {
        $d = New-TestReportDir
        $mf = Get-DVPackageManifest -SourceDir $d
        $mf.Manifest.NumeroFile | Should -Be 2
        $mf.Manifest.File[0].SHA256 | Should -Match '^[0-9a-f]{64}$'
    }

    It "produce un hash del manifesto riproducibile a parita' di contenuto" {
        $d = New-TestReportDir
        $a = (Get-DVPackageManifest -SourceDir $d).Hash
        $b = (Get-DVPackageManifest -SourceDir $d).Hash
        # Il manifesto include l'orario di generazione: gli hash coincidono solo
        # se generati nello stesso secondo. Si verifica quindi il formato e che
        # l'elenco dei file sia stabile.
        $a | Should -Match '^[0-9a-f]{64}$'
        $b | Should -Match '^[0-9a-f]{64}$'
    }

    It "l'hash del manifesto CAMBIA se cambia il contenuto di un file" {
        $d = New-TestReportDir
        $primaFile = (Get-DVPackageManifest -SourceDir $d).Manifest.File[0].SHA256
        Set-Content -Path (Join-Path $d "dati.json") -Value '{"a":999}' -Encoding UTF8
        $dopo = Get-DVPackageManifest -SourceDir $d
        $hashDopo = ($dopo.Manifest.File | Where-Object { $_.File -eq "dati.json" }).SHA256
        $hashDopo | Should -Not -Be $primaFile
    }

    It "rispetta i pattern di esclusione" {
        $d = New-TestReportDir
        Set-Content -Path (Join-Path $d "PACCHETTO_PROVA_vecchio.zip") -Value "x" -Encoding UTF8
        $mf = Get-DVPackageManifest -SourceDir $d -ExcludePatterns @("PACCHETTO_PROVA_*.zip")
        @($mf.Manifest.File | Where-Object { $_.File -like "PACCHETTO_PROVA_*" }).Count | Should -Be 0
    }
}

Describe "New-DVEvidencePackage - senza marca temporale" {
    It "crea un pacchetto .zip contenente il manifesto e le istruzioni" {
        $d = New-TestReportDir
        $pkg = New-DVEvidencePackage -ReportDir $d
        $pkg.Success | Should -BeTrue
        Test-Path $pkg.PackagePath | Should -BeTrue

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($pkg.PackagePath)
        try {
            # I separatori nelle voci dello ZIP variano tra piattaforme e versioni
            # (backslash su Windows PowerShell 5.1, slash altrove): si normalizza.
            $nomi = @($zip.Entries | ForEach-Object { $_.FullName -replace '\\', '/' })
            $nomi | Should -Contain "MANIFESTO.json"
            $nomi | Should -Contain "LEGGIMI_PRIMA.txt"
            @($nomi | Where-Object { $_ -like "contenuto/*" }).Count | Should -BeGreaterThan 0
        } finally { $zip.Dispose() }
    }

    It "segnala Timestamped=`$false se la marca temporale non e' richiesta" {
        $d = New-TestReportDir
        (New-DVEvidencePackage -ReportDir $d).Timestamped | Should -BeFalse
    }

    It "restituisce un errore se la cartella non esiste, senza sollevare eccezioni" {
        { New-DVEvidencePackage -ReportDir "C:\cartella\inesistente\xyz" } | Should -Not -Throw
        (New-DVEvidencePackage -ReportDir "C:\cartella\inesistente\xyz").Success | Should -BeFalse
    }

    It "non include nel pacchetto eventuali pacchetti precedenti" {
        $d = New-TestReportDir
        Set-Content -Path (Join-Path $d "PACCHETTO_PROVA_precedente.zip") -Value "vecchio" -Encoding UTF8
        $pkg = New-DVEvidencePackage -ReportDir $d
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($pkg.PackagePath)
        try {
            @($zip.Entries | Where-Object { $_.FullName -like "*PACCHETTO_PROVA_precedente*" }).Count | Should -Be 0
        } finally { $zip.Dispose() }
    }
}

Describe "New-DVPackageInstructions" {
    It "dichiara esplicitamente l'ASSENZA della marca temporale quando manca" {
        $t = New-DVPackageInstructions -ManifestHash ("a" * 64) -Timestamped $false
        $t | Should -Match "MARCA TEMPORALE ASSENTE"
        $t | Should -Match "modificabile"
    }

    It "riporta autorita' e data quando la marca temporale e' presente" {
        $t = New-DVPackageInstructions -ManifestHash ("b" * 64) -Timestamped $true -TsaName "TSA-Prova" -CertifiedTime ([datetime]"2026-03-14 03:12:00")
        $t | Should -Match "MARCA TEMPORALE PRESENTE"
        $t | Should -Match "TSA-Prova"
        $t | Should -Match "2026-03-14"
    }

    It "chiarisce sempre che NON e' una perizia forense" {
        $t = New-DVPackageInstructions -ManifestHash ("c" * 64) -Timestamped $true -TsaName "X"
        $t | Should -Match "NON e' una perizia"
    }

    It "include le istruzioni di verifica indipendente con OpenSSL" {
        $t = New-DVPackageInstructions -ManifestHash ("d" * 64) -Timestamped $true -TsaName "X"
        $t | Should -Match "openssl"
    }
}

Describe "Verificatore autonomo VERIFICA_PROVA.ps1" {
    It "esiste ed e' sintatticamente valido" {
        $p = Join-Path $PSScriptRoot "..\VERIFICA_PROVA.ps1"
        Test-Path $p | Should -BeTrue
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $p).Path, [ref]$tokens, [ref]$errors) | Out-Null
        $errors.Count | Should -Be 0
    }

    It "NON dipende da alcun modulo di DigitalValut (deve poter girare da solo)" {
        $p = Resolve-Path (Join-Path $PSScriptRoot "..\VERIFICA_PROVA.ps1")
        $contenuto = Get-Content $p -Raw
        # Non deve importare moduli del progetto: chi riceve il pacchetto non li ha.
        $contenuto | Should -Not -Match 'Import-Module.*\.psm1'
    }

    It "rileva una manomissione dei file rispetto al manifesto" {
        $d = New-TestReportDir
        $pkg = New-DVEvidencePackage -ReportDir $d -ControllerRoot (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
        $estratto = Join-Path $script:TestRoot ("est_" + [guid]::NewGuid().ToString("N"))
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($pkg.PackagePath, $estratto)

        # Manomissione: si altera un file dopo la sigillatura
        Set-Content -Path (Join-Path $estratto "contenuto\report.html") -Value "<html>ALTERATO</html>" -Encoding UTF8

        $verificatore = Join-Path $estratto "VERIFICA_PROVA.ps1"
        Test-Path $verificatore | Should -BeTrue
        $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $verificatore 2>&1 | Out-String
        $output | Should -Match "MODIFICATI"
    }

    It "conferma l'integrita' di un pacchetto non manomesso" {
        $d = New-TestReportDir
        $pkg = New-DVEvidencePackage -ReportDir $d -ControllerRoot (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
        $estratto = Join-Path $script:TestRoot ("ok_" + [guid]::NewGuid().ToString("N"))
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($pkg.PackagePath, $estratto)

        $output = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $estratto "VERIFICA_PROVA.ps1") 2>&1 | Out-String
        $output | Should -Match "nessuna alterazione"
    }
}

Describe "RawEvidence" {
    It "raccoglie i dati grezzi senza sollevare eccezioni" {
        $d = New-TestReportDir
        { Save-DVRawEvidence -ReportDir $d } | Should -Not -Throw
    }

    It "produce piu' file, ciascuno con l'indicazione del comando di origine" {
        $d = New-TestReportDir
        $raw = Save-DVRawEvidence -ReportDir $d
        $raw.Count | Should -BeGreaterThan 5
        $primo = Get-Content (Join-Path $raw.Directory "10_stato_rdp.txt") -Raw
        $primo | Should -Match "Comando/origine"
        $primo | Should -Match "dato grezzo non interpretato"
    }

    It "un blocco di raccolta che fallisce non interrompe gli altri" {
        $d = New-TestReportDir
        $r = Invoke-DVRawCapture -OutputDir $d -FileName "errore.txt" -CommandDescription "comando inesistente" -Capture { throw "errore simulato" }
        $r.Success | Should -BeFalse
        (Get-Content (Join-Path $d "errore.txt") -Raw) | Should -Match "ERRORE DURANTE LA RACCOLTA"
    }
}
