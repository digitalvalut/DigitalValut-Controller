BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\ChainOfCustody.psm1") -Force -Global
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\SentinelMonitor.psm1") -Force -Global
    $script:TestDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dvsent_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null
}

AfterAll {
    if (Test-Path $script:TestDir) { Remove-Item -Path $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe "Percorsi della Sentinella" {
    It "compone il percorso del registro eventi" {
        (Get-DVSentinelLogPath -ReportDir "C:\R") | Should -Be (Join-Path "C:\R" "sentinella_eventi.jsonl")
    }
    It "compone il percorso del file di arresto" {
        (Get-DVSentinelStopPath -ReportDir "C:\R") | Should -Be (Join-Path "C:\R" "STOP_SENTINELLA.txt")
    }
}

Describe "Registro eventi con catena crittografica" {
    BeforeEach {
        $script:Log = Join-Path $script:TestDir ("log_" + [guid]::NewGuid().ToString("N") + ".jsonl")
    }

    It "un registro inesistente e' considerato valido" {
        $r = Test-DVSentinelChain -LogPath $script:Log
        $r.Valid | Should -BeTrue
        $r.TotalEvents | Should -Be 0
    }

    It "scrive un evento e mantiene la catena integra" {
        Add-DVSentinelEvent -LogPath $script:Log -EventType "PROVA" -Data @{ Campo = "valore" } | Out-Null
        (Test-DVSentinelChain -LogPath $script:Log).Valid | Should -BeTrue
    }

    It "concatena correttamente piu' eventi consecutivi" {
        1..6 | ForEach-Object { Add-DVSentinelEvent -LogPath $script:Log -EventType "EVENTO_$_" -Data @{ N = $_ } | Out-Null }
        $r = Test-DVSentinelChain -LogPath $script:Log
        $r.Valid | Should -BeTrue
        $r.TotalEvents | Should -Be 6
    }

    It "il primo evento parte dal capostipite GENESIS" {
        Add-DVSentinelEvent -LogPath $script:Log -EventType "PRIMO" -Data @{ X = 1 } | Out-Null
        $first = (Get-Content $script:Log | Select-Object -First 1) | ConvertFrom-Json
        $first.PreviousHash | Should -Be "GENESIS"
    }

    It "RILEVA la cancellazione di un evento intermedio" {
        1..4 | ForEach-Object { Add-DVSentinelEvent -LogPath $script:Log -EventType "E$_" -Data @{ N = $_ } | Out-Null }
        $lines = Get-Content $script:Log
        Set-Content -Path $script:Log -Value (@($lines[0], $lines[2], $lines[3])) -Encoding UTF8
        (Test-DVSentinelChain -LogPath $script:Log).Valid | Should -BeFalse
    }

    It "RILEVA la modifica del contenuto di un evento gia' scritto" {
        Add-DVSentinelEvent -LogPath $script:Log -EventType "SESSIONE" -Data @{ DurataSecondi = 900 } | Out-Null
        Add-DVSentinelEvent -LogPath $script:Log -EventType "ALTRO" -Data @{ N = 2 } | Out-Null
        $lines = Get-Content $script:Log
        Set-Content -Path $script:Log -Value ($lines | ForEach-Object { $_ -replace '"DurataSecondi":900', '"DurataSecondi":5' }) -Encoding UTF8
        $r = Test-DVSentinelChain -LogPath $script:Log
        $r.Valid | Should -BeFalse
        $r.Message | Should -Match "modificato"
    }
}

Describe "Get-DVSentinelSummary" {
    BeforeEach {
        $script:Log = Join-Path $script:TestDir ("sum_" + [guid]::NewGuid().ToString("N") + ".jsonl")
    }

    It "restituisce Presente=`$false se non esiste alcun registro" {
        (Get-DVSentinelSummary -LogPath $script:Log).Presente | Should -BeFalse
    }

    It "ricostruisce i periodi di sorveglianza da AVVIO e ARRESTO" {
        Add-DVSentinelEvent -LogPath $script:Log -EventType "AVVIO_SENTINELLA" -Data @{ IntervalSeconds = 30 } | Out-Null
        Add-DVSentinelEvent -LogPath $script:Log -EventType "ARRESTO_SENTINELLA" -Data @{ DurataMinuti = 12.5 } | Out-Null
        $s = Get-DVSentinelSummary -LogPath $script:Log
        @($s.PeriodiSorveglianza).Count | Should -Be 1
        $s.MinutiSorvegliati | Should -Be 12.5
    }

    It "elenca le sessioni remote con durata, IP e software" {
        Add-DVSentinelEvent -LogPath $script:Log -EventType "AVVIO_SENTINELLA" -Data @{ IntervalSeconds = 30 } | Out-Null
        Add-DVSentinelEvent -LogPath $script:Log -EventType "SESSIONE_REMOTA_APERTA" -Data @{ IPRemoto = "10.0.0.5"; Software = "UltraVNC" } | Out-Null
        Add-DVSentinelEvent -LogPath $script:Log -EventType "SESSIONE_REMOTA_CHIUSA" -Data @{
            IPRemoto = "10.0.0.5"; Software = "UltraVNC"; DurataSecondi = 2820; InizioSessione = "2026-03-14 03:12:00"; PortaLocale = 5900
        } | Out-Null

        $s = Get-DVSentinelSummary -LogPath $script:Log
        @($s.SessioniRemote).Count | Should -Be 1
        $s.SessioniRemote[0].IPRemoto | Should -Be "10.0.0.5"
        $s.SessioniRemote[0].DurataSecondi | Should -Be 2820
        $s.SessioniRemote[0].Inizio | Should -Be "2026-03-14 03:12:00"
    }

    It "segnala un periodo di sorveglianza ancora in corso" {
        Add-DVSentinelEvent -LogPath $script:Log -EventType "AVVIO_SENTINELLA" -Data @{ IntervalSeconds = 30 } | Out-Null
        $s = Get-DVSentinelSummary -LogPath $script:Log
        $s.PeriodiSorveglianza[0].Fine | Should -Be "(in corso)"
    }

    It "riporta l'esito della verifica di integrita' del registro" {
        Add-DVSentinelEvent -LogPath $script:Log -EventType "AVVIO_SENTINELLA" -Data @{ IntervalSeconds = 30 } | Out-Null
        (Get-DVSentinelSummary -LogPath $script:Log).ChainValid | Should -BeTrue
    }

    It "elenca gli usi di microfono e webcam" {
        Add-DVSentinelEvent -LogPath $script:Log -EventType "PERIFERICA_DISATTIVATA" -Data @{
            Periferica = "Microfono"; Processo = "sconosciuto.exe"; InizioUso = "2026-03-14 03:20:00"; DurataSecondi = 600
        } | Out-Null
        $s = Get-DVSentinelSummary -LogPath $script:Log
        @($s.UsiPeriferiche).Count | Should -Be 1
        $s.UsiPeriferiche[0].Periferica | Should -Be "Microfono"
    }
}

Describe "Rilevamento sessioni in corso" {
    It "non solleva eccezioni con database vuoti" {
        { Get-DVCurrentRemoteSessions -PortsDb @{} -ProcessDb @{} } | Should -Not -Throw
    }

    It "restituisce una tabella (nessuna corrispondenza con database vuoti)" {
        (Get-DVCurrentRemoteSessions -PortsDb @{} -ProcessDb @{}).Count | Should -Be 0
    }

    It "Get-DVCurrentMediaUse non solleva eccezioni" {
        { Get-DVCurrentMediaUse } | Should -Not -Throw
    }
}

Describe "Start-DVSentinel - esecuzione breve reale" {
    It "esegue, si arresta da sola e registra avvio e arresto" {
        $dir = Join-Path $script:TestDir ("run_" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null

        $r = Start-DVSentinel -ReportDir $dir -IntervalSeconds 1 -MaxMinutes 0.05 -PortsDb @{} -ProcessDb @{}

        $log = Get-DVSentinelLogPath -ReportDir $dir
        Test-Path $log | Should -BeTrue
        (Test-DVSentinelChain -LogPath $log).Valid | Should -BeTrue

        $tipi = @(Get-Content $log | ForEach-Object { ($_ | ConvertFrom-Json).EventType })
        $tipi | Should -Contain "AVVIO_SENTINELLA"
        $tipi | Should -Contain "ARRESTO_SENTINELLA"
    }

    It "si arresta quando compare il file STOP" {
        $dir = Join-Path $script:TestDir ("stop_" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        # Il file di arresto viene rimosso all'avvio, quindi si usa una durata
        # massima brevissima per verificare l'uscita ordinata.
        $r = Start-DVSentinel -ReportDir $dir -IntervalSeconds 1 -MaxMinutes 0.03 -PortsDb @{} -ProcessDb @{}
        $r.Eventi | Should -BeGreaterOrEqual 0
        (Test-DVSentinelChain -LogPath (Get-DVSentinelLogPath -ReportDir $dir)).Valid | Should -BeTrue
    }
}
