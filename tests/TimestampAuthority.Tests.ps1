BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\TimestampAuthority.psm1") -Force
}

Describe "Codifica DER" {
    It "codifica correttamente le lunghezze brevi (forma corta)" {
        (ConvertTo-DVDerLength -Length 5)[0]  | Should -Be 5
        (ConvertTo-DVDerLength -Length 127)[0] | Should -Be 127
    }

    It "codifica correttamente le lunghezze lunghe (forma estesa)" {
        $r = ConvertTo-DVDerLength -Length 300
        $r[0] | Should -Be 0x82      # forma lunga, 2 byte di lunghezza
        $r[1] | Should -Be 1
        $r[2] | Should -Be 44        # 300 = 0x012C
    }

    It "costruisce una struttura TLV con tag e lunghezza corretti" {
        $tlv = New-DVDerTlv -Tag 0x04 -Content ([byte[]]@(1,2,3))
        $tlv[0] | Should -Be 0x04
        $tlv[1] | Should -Be 3
        $tlv.Length | Should -Be 5
    }

    It "rilegge correttamente una struttura appena costruita" {
        $tlv = New-DVDerTlv -Tag 0x30 -Content ([byte[]]@(0xAA, 0xBB))
        $parsed = Read-DVDerTlv -Bytes $tlv -Position 0
        $parsed.Tag | Should -Be 0x30
        $parsed.Length | Should -Be 2
        $parsed.TotalEnd | Should -Be 4
    }

    It "restituisce `$null su dati DER troncati invece di sollevare eccezioni" {
        Read-DVDerTlv -Bytes ([byte[]]@(0x30)) -Position 0 | Should -BeNullOrEmpty
        Read-DVDerTlv -Bytes ([byte[]]@()) -Position 0 | Should -BeNullOrEmpty
    }
}

Describe "New-DVTimestampRequest" {
    It "produce una richiesta con struttura RFC 3161 valida" {
        $hash = New-Object byte[] 32
        $built = New-DVTimestampRequest -Sha256Hash $hash
        $built.Request[0] | Should -Be 0x30            # SEQUENCE
        $built.Nonce.Length | Should -Be 8
        $built.Request.Length | Should -BeGreaterThan 50
    }

    It "include l'OID di SHA-256 nella richiesta" {
        $hash = New-Object byte[] 32
        $built = New-DVTimestampRequest -Sha256Hash $hash
        $hex = ($built.Request | ForEach-Object { $_.ToString('x2') }) -join ''
        # OID 2.16.840.1.101.3.4.2.1 (sha256)
        $hex | Should -Match '608648016503040201'
    }

    It "genera un nonce sempre positivo (primo byte < 0x80)" {
        $hash = New-Object byte[] 32
        1..20 | ForEach-Object {
            (New-DVTimestampRequest -Sha256Hash $hash).Nonce[0] | Should -BeLessThan 0x80
        }
    }

    It "genera nonce differenti a ogni chiamata (protezione da replay)" {
        $hash = New-Object byte[] 32
        $a = ((New-DVTimestampRequest -Sha256Hash $hash).Nonce | ForEach-Object { $_.ToString('x2') }) -join ''
        $b = ((New-DVTimestampRequest -Sha256Hash $hash).Nonce | ForEach-Object { $_.ToString('x2') }) -join ''
        $a | Should -Not -Be $b
    }

    It "rifiuta un hash che non sia SHA-256 da 32 byte" {
        { New-DVTimestampRequest -Sha256Hash (New-Object byte[] 20) } | Should -Throw
    }
}

Describe "Request-DVTimestamp - robustezza" {
    It "non solleva eccezioni quando l'autorita' non e' raggiungibile" {
        $hash = New-Object byte[] 32
        { Request-DVTimestamp -Sha256Hash $hash -CustomUrl "http://127.0.0.1:1/tsa-inesistente" -TimeoutSec 2 } | Should -Not -Throw
    }

    It "restituisce Success=`$false e un messaggio d'errore se tutte le TSA falliscono" {
        # Si sostituisce l'elenco delle autorita' con una sola non raggiungibile,
        # per non dipendere dalla connessione reale durante i test.
        InModuleScope TimestampAuthority {
            $Global:DVTimestampAuthorities = @(
                @{ Name = "TSA-di-prova-irraggiungibile"; Url = "http://127.0.0.1:1/nope"; Qualified = $false }
            )
        }
        $hash = New-Object byte[] 32
        $r = Request-DVTimestamp -Sha256Hash $hash -TimeoutSec 2
        $r.Success | Should -BeFalse
        $r.Error | Should -Not -BeNullOrEmpty
    }
}

Describe "Test-DVTimestampToken - robustezza" {
    It "non solleva eccezioni su un token non valido" {
        { Test-DVTimestampToken -Token ([byte[]]@(1,2,3,4,5)) } | Should -Not -Throw
    }

    It "segnala come non valido un token malformato" {
        $r = Test-DVTimestampToken -Token ([byte[]]@(0x30,0x03,0x02,0x01,0x00))
        $r.Valid | Should -BeFalse
    }

    It "restituisce sempre la struttura attesa" {
        $r = Test-DVTimestampToken -Token ([byte[]]@(1,2,3))
        $r.Keys | Should -Contain "Valid"
        $r.Keys | Should -Contain "SignatureValid"
        $r.Keys | Should -Contain "CertifiedTime"
    }
}

Describe "Get-DVFileSha256Bytes" {
    It "calcola un hash SHA-256 di 32 byte" {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dvts_" + [guid]::NewGuid().ToString("N") + ".txt")
        Set-Content -Path $tmp -Value "contenuto di prova" -Encoding UTF8
        try {
            $h = Get-DVFileSha256Bytes -Path $tmp
            $h.Length | Should -Be 32
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}
