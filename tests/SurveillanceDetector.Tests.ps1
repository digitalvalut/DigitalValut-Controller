BeforeAll {
    $script:ModulePath = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'core') 'modules'
    $script:ModuleFile = Join-Path $script:ModulePath 'SurveillanceDetector.psm1'
    Import-Module $script:ModuleFile -Force
}

Describe "Regressioni v5.1 (bug trovati nella v5.0)" {
    It "non usa piu' ( x -or '' ).ToLower(): in PowerShell -or restituisce un booleano, non una stringa" {
        $code = (Get-Content -Path $script:ModuleFile | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match "-or\s*''\s*\)\s*\.\s*ToLower"
    }

    It "non usa piu' Start-Job: nel job le funzioni del modulo non esistono e ogni controllo falliva in silenzio" {
        $code = (Get-Content -Path $script:ModuleFile | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match 'Start-Job'
    }
}

Describe "Invoke-DVCheck - esito esplicito per ogni controllo" {
    It "restituisce FALLITO (non 'pulito') quando la funzione non esiste" {
        $r = Invoke-DVCheck -Name 'prova' -FunctionName 'Get-FunzioneInesistente-DV'
        $r.Status | Should -Be 'FALLITO'
        $r.Detail | Should -Not -BeNullOrEmpty
    }

    It "restituisce OK per una funzione esistente" {
        $r = Invoke-DVCheck -Name 'prova' -FunctionName 'ConvertFrom-DVConsentKeyName'
        $r.Status | Should -Be 'OK'
    }
}

Describe "Percorsi e applicazioni note" {
    It "ConvertFrom-DVConsentKeyName converte '#' in '\'" {
        ConvertFrom-DVConsentKeyName -KeyName 'C:#Windows#System32#svchost.exe' | Should -Be 'C:\Windows\System32\svchost.exe'
    }

    It "Test-DVUserWritablePath riconosce Temp, AppData Roaming e Public" {
        Test-DVUserWritablePath -Path 'C:\Users\x\AppData\Local\Temp\a.exe' | Should -BeTrue
        Test-DVUserWritablePath -Path 'C:\Users\x\AppData\Roaming\Foo\a.exe' | Should -BeTrue
        Test-DVUserWritablePath -Path 'C:\Users\Public\a.exe' | Should -BeTrue
    }

    It "Test-DVUserWritablePath non segnala Program Files e System32" {
        Test-DVUserWritablePath -Path 'C:\Program Files\Contoso\a.exe' | Should -BeFalse
        Test-DVUserWritablePath -Path 'C:\Windows\System32\svchost.exe' | Should -BeFalse
        Test-DVUserWritablePath -Path '' | Should -BeFalse
    }

    It "Test-DVKnownMediaApp riconosce le applicazioni note e i pacchetti Microsoft" {
        Test-DVKnownMediaApp -AppName 'Teams.exe' | Should -BeTrue
        Test-DVKnownMediaApp -AppName 'microsoft.windows.camera' | Should -BeTrue
        Test-DVKnownMediaApp -AppName 'rec.exe' | Should -BeFalse
        Test-DVKnownMediaApp -AppName '' | Should -BeFalse
    }
}

Describe "ConvertFrom-DVConsentEntry - lettura del registro ConsentStore" {
    BeforeAll {
        $script:t0 = ([datetime]'2026-10-13T09:00:00').ToFileTime()
        $script:t1 = ([datetime]'2026-10-13T09:01:30').ToFileTime()
    }

    It "con LastUsedTimeStop = 0 il dispositivo risulta IN USO adesso" {
        $e = ConvertFrom-DVConsentEntry -Store 'microphone' -KeyName 'C:#Users#x#AppData#Local#Temp#rec.exe' -StartFileTime $script:t0 -StopFileTime 0
        $e.InUseNow | Should -BeTrue
        $e.AppName | Should -Be 'rec.exe'
        $e.ProcessName | Should -Be 'rec'
        $e.Suspicious | Should -BeTrue
    }

    It "con Stop valorizzato calcola la durata e non e' in uso" {
        $e = ConvertFrom-DVConsentEntry -Store 'webcam' -KeyName 'C:#Windows#System32#svchost.exe' -StartFileTime $script:t0 -StopFileTime $script:t1
        $e.InUseNow | Should -BeFalse
        $e.Duration | Should -Be '00:01:30'
        $e.Suspicious | Should -BeFalse
    }

    It "senza LastUsedTimeStart restituisce null (mai usato)" {
        $e = ConvertFrom-DVConsentEntry -Store 'microphone' -KeyName 'qualcosa' -StartFileTime 0 -StopFileTime 0
        $e | Should -BeNullOrEmpty
    }
}

Describe "Measure-DVSurveillance - punteggio e formulazione" {
    BeforeAll {
        $script:t0 = ([datetime]'2026-10-13T09:00:00').ToFileTime()
    }

    It "senza dati: punteggio 0, livello BASSO, nessun finding" {
        $r = Measure-DVSurveillance
        $r.Score | Should -Be 0
        $r.Level | Should -Be 'BASSO'
        $r.Findings.Count | Should -Be 0
        $r.Summary | Should -Match 'Nessun indicatore'
    }

    It "applicazione nota (Teams) che usa il microfono non genera segnalazioni" {
        $m = ConvertFrom-DVConsentEntry -Store 'microphone' -KeyName 'C:#Program Files#Teams#Teams.exe' -StartFileTime $script:t0
        (Measure-DVSurveillance -MicInUse @($m)).Score | Should -Be 0
    }

    It "applicazione sconosciuta con microfono in uso: +30 e formulazione 'da verificare', non accusatoria" {
        $m = ConvertFrom-DVConsentEntry -Store 'microphone' -KeyName 'C:#Program Files#Foo#foo.exe' -StartFileTime $script:t0
        $r = Measure-DVSurveillance -MicInUse @($m)
        $r.Score | Should -Be 30
        $r.Findings[0] | Should -Match 'Verificare'
        $r.Findings[0] | Should -Not -Match 'CRITICO'
    }

    It "percorso insolito (Temp) aggiunge 10 punti" {
        $m = ConvertFrom-DVConsentEntry -Store 'webcam' -KeyName 'C:#Users#x#AppData#Local#Temp#rec.exe' -StartFileTime $script:t0
        (Measure-DVSurveillance -CamInUse @($m)).Score | Should -Be 40
    }

    It "dispositivo audio virtuale: +10; con Stereo Mix +20 totali" {
        $v = [PSCustomObject]@{ DeviceName = 'CABLE Output (VB-Audio)' }
        (Measure-DVSurveillance -VirtualAudio @($v)).Score | Should -Be 10
        $s = [PSCustomObject]@{ DeviceName = 'Stereo Mix (Realtek)' }
        (Measure-DVSurveillance -VirtualAudio @($s)).Score | Should -Be 20
    }

    It "un controllo non completato non da' punteggio ma segnala che l'esito e' parziale" {
        $ck = [PSCustomObject]@{ Name = 'Permessi privacy Windows'; Status = 'FALLITO'; Detail = 'accesso negato' }
        $r = Measure-DVSurveillance -Checks @($ck)
        $r.Score | Should -Be 0
        $r.Summary | Should -Match 'parziale'
        $r.Findings[0] | Should -Match 'NON e'' affidabile'
    }

    It "audiodg con connessioni esterne pesa 35" {
        $a = [PSCustomObject]@{ Type = 'AudiodgExternalConnections'; Path = 'audiodg.exe' }
        (Measure-DVSurveillance -SpywareIndicators @($a)).Score | Should -Be 35
    }
}
