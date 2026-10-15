BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\core\modules\UltraVncLogAnalyzer.psm1') -Force
    $script:dir = Join-Path ([IO.Path]::GetTempPath()) ('dv-vnclog-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $script:dir | Out-Null
}

Describe 'ConvertFrom-DVVncLogLine - formati verificati' {
    It 'riconosce "accepted connection from" (sorgente UltraVNC, vncsockconnect.cpp)' {
        $r = ConvertFrom-DVVncLogLine -Line '2026-10-08 09:12:44 - vncsockconnect.cpp : accepted connection from 10.30.1.5'
        $r.Kind | Should -Be 'Connessione accettata'
        $r.Address | Should -Be '10.30.1.5'
        $r.IsLocal | Should -BeFalse
    }
    It 'riconosce le tre righe di mslogon.log descritte dall''autore' {
        (ConvertFrom-DVVncLogLine -Line 'Connection received from 10.30.1.9').Kind | Should -Be 'Connessione ricevuta'
        (ConvertFrom-DVVncLogLine -Line 'Invalid attempt from client 10.30.1.9').Kind | Should -Be 'Tentativo di accesso non valido'
        (ConvertFrom-DVVncLogLine -Line 'Client 10.30.1.9 disconnected').Kind | Should -Be 'Disconnessione'
    }
    It 'una riga qualunque non e'' un evento' {
        ConvertFrom-DVVncLogLine -Line 'vncdesktop.cpp : screen updated' | Should -BeNullOrEmpty
        ConvertFrom-DVVncLogLine -Line '' | Should -BeNullOrEmpty
    }
    It 'distingue la connessione dal PC stesso (loopback) da quella remota' {
        (ConvertFrom-DVVncLogLine -Line 'Connection received from 127.0.0.1').IsLocal | Should -BeTrue
        (ConvertFrom-DVVncLogLine -Line 'Connection received from 10.30.1.5').IsLocal | Should -BeFalse
    }
    It 'toglie la porta dall''indirizzo IPv4' {
        (ConvertFrom-DVVncLogLine -Line 'accepted connection from 10.30.1.5:51234').Address | Should -Be '10.30.1.5'
    }
    It 'riduce un IPv4 incapsulato in IPv6' {
        (ConvertFrom-DVVncLogLine -Line 'accepted connection from ::ffff:10.30.1.5').Address | Should -Be '10.30.1.5'
    }
}

Describe 'Tutela dei terzi - nomi utente mai conservati' {
    It 'il nome utente presente nella riga non compare nell''evento estratto' {
        $line = '2026-10-08 09:12:44 accepted connection from 10.30.1.5 user ASPCL\mario.rossi logon ok'
        $r = ConvertFrom-DVVncLogLine -Line $line
        ($r | ConvertTo-Json -Depth 4) | Should -Not -Match 'mario'
        ($r | ConvertTo-Json -Depth 4) | Should -Not -Match 'rossi'
    }
}

Describe 'ConvertFrom-DVLogTimestamp - mai una data inventata' {
    It 'anno per primo: interpretata' {
        $t = ConvertFrom-DVLogTimestamp -Line '2026-10-08 09:12:44 testo'
        $t.Time | Should -Be ([datetime]'2026-10-08 09:12:44')
        $t.Ambiguous | Should -BeFalse
    }
    It 'giorno maggiore di 12 nel primo campo: dd/MM/yyyy' {
        (ConvertFrom-DVLogTimestamp -Line '23/10/2026 09:12:44 x').Time.Month | Should -Be 10
    }
    It 'giorno maggiore di 12 nel secondo campo: MM/dd/yyyy' {
        $t = ConvertFrom-DVLogTimestamp -Line '10/23/2026 09:12:44 x'
        $t.Time.Day | Should -Be 23
        $t.Time.Month | Should -Be 10
    }
    It 'data ambigua (05/06/2026): NON interpretata, ma il testo originale e'' conservato' {
        $t = ConvertFrom-DVLogTimestamp -Line '05/06/2026 09:12:44 x'
        $t.Time | Should -BeNullOrEmpty
        $t.Ambiguous | Should -BeTrue
        $t.Text | Should -Match '05/06/2026'
    }
    It 'riga senza data: nessuna data' {
        (ConvertFrom-DVLogTimestamp -Line 'accepted connection from 10.1.1.1').Text | Should -Be ''
    }
}

Describe 'Get-DVUltraVncLogFindings - lettura in sola lettura' {
    It 'file non presente: lo dichiara, non e'' un errore' {
        $r = Get-DVUltraVncLogFindings -ExtraPaths @((Join-Path $script:dir 'assente.log')) -SkipEventLog
        $f = @($r.Files | Where-Object { $_.Path -like '*assente.log' })[0]
        $f.Exists | Should -BeFalse
        $r.RemoteConnectionCount | Should -Be 0
    }

    It 'conta le connessioni remote, esclude il loopback e riporta l''impronta' {
        $p = Join-Path $script:dir 'winvnc.log'
        @(
            '2026-10-06 08:00:01 accepted connection from 10.30.1.5'
            '2026-10-06 08:00:02 accepted connection from 127.0.0.1'
            '2026-10-08 09:12:44 accepted connection from 10.30.1.5'
            '2026-10-09 10:00:00 accepted connection from 10.30.1.77'
            'vncdesktop.cpp : rumore'
        ) | Set-Content -LiteralPath $p -Encoding ASCII
        $r = Get-DVUltraVncLogFindings -ExtraPaths @($p) -SkipEventLog
        $r.RemoteConnectionCount | Should -Be 3
        $r.DistinctRemoteAddresses.Count | Should -Be 2
        $r.FirstSeenText | Should -Be '2026-10-06 08:00:01'
        $r.LastSeenText | Should -Be '2026-10-09 10:00:00'
        $f = @($r.Files | Where-Object { $_.Path -eq $p })[0]
        $f.Sha256 | Should -Match '^[0-9a-f]{64}$'
        $f.Truncated | Should -BeFalse
    }

    It 'la stessa connessione in due file non viene contata due volte (massimo, non somma)' {
        $a = Join-Path $script:dir 'a-winvnc.log'
        $b = Join-Path $script:dir 'b-mslogon.log'
        '2026-10-08 09:12:44 accepted connection from 10.30.1.5' | Set-Content -LiteralPath $a -Encoding ASCII
        '2026-10-08 09:12:44 Connection received from 10.30.1.5' | Set-Content -LiteralPath $b -Encoding ASCII
        $r = Get-DVUltraVncLogFindings -ExtraPaths @($a, $b) -SkipEventLog
        $r.RemoteConnectionCount | Should -Be 1
    }

    It 'i tentativi di accesso non validi sono contati a parte' {
        $p = Join-Path $script:dir 'mslogon-fail.log'
        @('Invalid attempt from client 10.30.1.9', 'Invalid attempt from client 10.30.1.9') | Set-Content -LiteralPath $p -Encoding ASCII
        $r = Get-DVUltraVncLogFindings -ExtraPaths @($p) -SkipEventLog
        $r.FailedAttemptCount | Should -Be 2
        $r.RemoteConnectionCount | Should -Be 0
    }

    It 'un file senza righe riconosciute e'' letto ma non prova l''assenza di accessi' {
        $p = Join-Path $script:dir 'vuoto.log'
        @('riga qualunque', 'altro rumore') | Set-Content -LiteralPath $p -Encoding ASCII
        $r = Get-DVUltraVncLogFindings -ExtraPaths @($p) -SkipEventLog
        @($r.Files | Where-Object { $_.Path -eq $p })[0].Readable | Should -BeTrue
        $r.RemoteConnectionCount | Should -Be 0
        $r.AnyFileRead | Should -BeTrue
    }

    It 'un file grande e'' letto solo in coda e lo dichiara' {
        $p = Join-Path $script:dir 'grande.log'
        $lines = 1..3000 | ForEach-Object { "2026-10-01 00:00:00 rumore di riempimento numero $_ xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
        $lines += '2026-10-09 10:00:00 accepted connection from 10.30.1.88'
        $lines | Set-Content -LiteralPath $p -Encoding ASCII
        $r = Get-DVUltraVncLogFindings -ExtraPaths @($p) -SkipEventLog -MaxBytes 20000
        $f = @($r.Files | Where-Object { $_.Path -eq $p })[0]
        $f.Truncated | Should -BeTrue
        $f.BytesRead | Should -BeLessOrEqual 20000
        $r.RemoteConnectionCount | Should -Be 1
    }

    It 'il file non viene modificato dalla lettura' {
        $p = Join-Path $script:dir 'intatto.log'
        '2026-10-09 10:00:00 accepted connection from 10.30.1.88' | Set-Content -LiteralPath $p -Encoding ASCII
        $before = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
        $null = Get-DVUltraVncLogFindings -ExtraPaths @($p) -SkipEventLog
        (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash | Should -Be $before
    }

    It 'si legge anche un file tenuto aperto in scrittura da un altro processo' {
        $p = Join-Path $script:dir 'inuso.log'
        $w = New-Object System.IO.FileStream($p, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try {
            $bytes = [Text.Encoding]::ASCII.GetBytes("2026-10-09 10:00:00 accepted connection from 10.30.1.88`r`n")
            $w.Write($bytes, 0, $bytes.Length); $w.Flush()
            $r = Get-DVUltraVncLogFindings -ExtraPaths @($p) -SkipEventLog
            @($r.Files | Where-Object { $_.Path -eq $p })[0].Readable | Should -BeTrue
            $r.RemoteConnectionCount | Should -Be 1
        } finally { $w.Dispose() }
    }

    It 'una data ambigua non genera prima/ultima data inventate' {
        $p = Join-Path $script:dir 'ambiguo.log'
        '05/06/2026 09:12:44 accepted connection from 10.30.1.5' | Set-Content -LiteralPath $p -Encoding ASCII
        $r = Get-DVUltraVncLogFindings -ExtraPaths @($p) -SkipEventLog
        $r.RemoteConnectionCount | Should -Be 1
        $r.FirstSeenText | Should -Be ''
    }
}

Describe 'Sessioni: una connessione genera piu'' righe' {
    It 'tre righe "Connection received" e una disconnessione sono UNA sessione' {
        $f = Join-Path $script:dir 'mslogon-sess.log'
        $lines = @(
            '2025-04-16 12:08:00 Connection received from 10.75.49.11',
            '2025-04-16 12:08:51 Connection received from 10.75.49.11',
            '2025-04-16 12:08:00 Connection received from 10.75.49.11',
            '2025-04-16 12:14:00 Client 10.75.49.11 disconnected',
            '2025-04-16 13:06:00 Connection received from 10.75.49.11',
            '2025-04-16 13:06:45 Connection received from 10.75.49.11',
            '2025-04-16 13:10:00 Client 10.75.49.11 disconnected',
            '2025-04-16 13:16:00 Connection received from 10.38.39.44'
        )
        Set-Content -LiteralPath $f -Value $lines -Encoding Default
        $r = Get-DVUltraVncLogFindings -ExtraPaths @($f) -SkipEventLog
        $r.RemoteConnectionCount | Should -Be 6
        $r.RemoteSessionCount | Should -Be 3
    }
    It 'lo stesso file raggiunto con maiuscole diverse non e'' letto due volte' {
        $p = Get-DVUltraVncLogCandidatePaths -ExtraPaths @('C:\X\Log.log', 'c:\x\LOG.log')
        @($p | Where-Object { $_ -ieq 'C:\X\Log.log' }).Count | Should -Be 1
    }
}
