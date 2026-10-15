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

    It "restituisce BASSO tra 1 e 24" {
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

Describe "DV-SCORE-2 - un fatto non si conta due volte" {
    BeforeAll {
        $script:rcUltra = @{
            RemoteControl = @(
                [PSCustomObject]@{ Name = 'WinVNC'; ProcessName = 'winvnc'; ProcessId = 4564; Risk = 'CRITICAL'; RuleId = 'DV-PROC-0007'; SignatureStatus = 'Unknown'; Path = 'C:\Program Files\uvnc bvba\UltraVNC\winvnc.exe' }
                [PSCustomObject]@{ Name = 'WinVNC'; ProcessName = 'winvnc'; ProcessId = 13944; Risk = 'CRITICAL'; RuleId = 'DV-PROC-0007'; SignatureStatus = 'Unknown'; Path = 'C:\Program Files\uvnc bvba\UltraVNC\winvnc.exe' }
            )
            Spyware = @(); EmployeeMonitor = @(); OtherSuspicious = @()
        }
        $script:portVnc = @{ SuspiciousPorts = @(
            @{ Port = 5900; Name = 'VNC'; Risk = 'CRITICAL'; RuleId = 'DV-PORT-0012'; OwnerProcessName = 'winvnc'; OwnerProcessId = 4564; OwnerPath = 'C:\Program Files\uvnc bvba\UltraVNC\winvnc.exe' }
        )}
        $script:swUltra = @( [PSCustomObject]@{ Name = 'UltraVnc'; Version = '1.1.9.6'; Publisher = 'uvnc bvba'; Risk = 'CRITICAL' } )
    }

    It "due processi dello stesso software producono un solo rilievo" {
        $r = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $script:rcUltra -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        @($r.Evidence | Where-Object { $_.Category -eq 'Processi' }).Count | Should -Be 1
        $r.Score | Should -Be 30
    }

    It "la porta del software gia' rilevato vale solo l'esposizione in rete, non un nuovo fatto" {
        $r = Get-DVThreatScore -PortAnalysis $script:portVnc -ProcessAnalysis $script:rcUltra -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $portRow = @($r.Evidence | Where-Object { $_.Category -eq 'Porte' })[0]
        $portRow.Points | Should -Be 10
        $portRow.State | Should -Match 'Conferma di R-01'
        $r.Score | Should -Be 40
    }

    It "una porta di un software diverso e' un fatto distinto e pesa per intero" {
        $portRdp = @{ SuspiciousPorts = @(
            @{ Port = 3389; Name = 'RDP'; Risk = 'HIGH'; RuleId = 'DV-PORT-0009'; OwnerProcessName = 'svchost'; OwnerProcessId = 1234 }
        )}
        $r = Get-DVThreatScore -PortAnalysis $portRdp -ProcessAnalysis $script:rcUltra -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $portRow = @($r.Evidence | Where-Object { $_.Category -eq 'Porte' })[0]
        $portRow.Points | Should -Be 20
        $portRow.State | Should -Be 'In ascolto'
    }

    It "il software installato corrispondente a un processo non aggiunge punti (correlazione per percorso)" {
        $r = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $script:rcUltra -ServiceAnalysis @() `
            -SoftwareAnalysis $script:swUltra -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $swRow = @($r.Evidence | Where-Object { $_.Category -eq 'Software installato' })[0]
        $swRow.Points | Should -Be 0
        $swRow.State | Should -Be 'Conferma di un rilievo precedente'
        $r.Score | Should -Be 30
    }

    It "senza percorso leggibile la correlazione resta indeterminata e non attribuisce punti" {
        $rcNoPath = @{
            RemoteControl = @([PSCustomObject]@{ Name = 'WinVNC'; ProcessName = 'winvnc'; Risk = 'CRITICAL'; SignatureStatus = 'Unknown'; Path = '' })
            Spyware = @(); EmployeeMonitor = @(); OtherSuspicious = @()
        }
        $r = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $rcNoPath -ServiceAnalysis @() `
            -SoftwareAnalysis $script:swUltra -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $swRow = @($r.Evidence | Where-Object { $_.Category -eq 'Software installato' })[0]
        $swRow.Points | Should -Be 0
        $swRow.State | Should -Match 'non verificabile'
    }

    It "un software installato senza alcun processo corrispondente pesa 10" {
        $r = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $null -ServiceAnalysis @() `
            -SoftwareAnalysis $script:swUltra -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $r.Score | Should -Be 10
    }
}

Describe "DV-SCORE-2 - sessione attiva e tracciabilita'" {
    It "una sessione di accesso remoto in corso porta il livello a CRITICO" {
        $rc = @{
            RemoteControl = @([PSCustomObject]@{ Name = 'WinVNC'; ProcessName = 'winvnc'; Risk = 'CRITICAL'; SignatureStatus = 'Unknown'; Path = 'C:\x\winvnc.exe' })
            Spyware = @(); EmployeeMonitor = @(); OtherSuspicious = @()
        }
        $att = @(
            [PSCustomObject]@{ Stato = 'CONNESSO - sessione su canale di accesso remoto (WinVNC)'; IPRemoto = '10.30.1.5'; PortaLocale = 5900; Processo = 'WinVNC'; PID = 4564 }
            [PSCustomObject]@{ Stato = 'IN ASCOLTO - accetta connessioni'; IPRemoto = 'In attesa di connessione'; PortaLocale = 5900; Processo = 'WinVNC'; PID = 4564 }
        )
        $r = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $rc -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null `
            -ActiveRemoteConnections $att
        @($r.Evidence | Where-Object { $_.Category -eq 'Sessioni attive' }).Count | Should -Be 1
        $r.Score | Should -Be 70
        $r.Level.Text | Should -Be 'ALTO'
    }

    It "la somma dei punti delle evidenze e' esattamente il punteggio totale" {
        $rc = @{
            RemoteControl = @([PSCustomObject]@{ Name = 'WinVNC'; ProcessName = 'winvnc'; Risk = 'CRITICAL'; SignatureStatus = 'NotSigned'; Path = 'C:\x\winvnc.exe' })
            Spyware = @(); EmployeeMonitor = @(); OtherSuspicious = @()
        }
        $ports = @{ SuspiciousPorts = @(
            @{ Port = 3389; Name = 'RDP'; Risk = 'HIGH'; OwnerProcessName = 'svchost'; OwnerProcessId = 9 }
            @{ Port = 5900; Name = 'VNC'; Risk = 'CRITICAL'; OwnerProcessName = 'winvnc'; OwnerProcessId = 4564 }
        )}
        $r = Get-DVThreatScore -PortAnalysis $ports -ProcessAnalysis $rc -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $false } -NetworkConnections $null `
            -PersistenceFindings @{ Score = 20; Findings = @('[PERSISTENZA] Task sospetto') }
        $sum = 0
        foreach ($e in $r.Evidence) { $sum += [int]$e.Points }
        $sum | Should -Be $r.Score
    }

    It "ogni evidenza che attribuisce punti dichiara la fonte tecnica del dato" {
        $rc = @{
            RemoteControl = @([PSCustomObject]@{ Name = 'WinVNC'; ProcessName = 'winvnc'; Risk = 'CRITICAL'; SignatureStatus = 'Unknown'; Path = 'C:\x\winvnc.exe' })
            Spyware = @(); EmployeeMonitor = @(); OtherSuspicious = @()
        }
        $r = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $rc -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $false } -NetworkConnections $null
        foreach ($e in @($r.Evidence | Where-Object { [int]$_.Points -gt 0 })) {
            $e.Source | Should -Not -BeNullOrEmpty
            $e.Note | Should -Not -BeNullOrEmpty
            $e.Id | Should -Match '^R-\d\d$'
        }
    }

    It "il punteggio di un modulo e' attribuito a una sola riga, senza duplicare il totale" {
        $av = @{
            OverallAudioVideoRisk = @{ Score = 35 }
            SurveillanceFindings  = @('[CRITICO] audiodg con connessioni esterne', '[ALTO] microfono in uso')
        }
        $r = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $null -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null `
            -SurveillanceCapabilities $av
        $r.Score | Should -Be 35
        @($r.Evidence | Where-Object { $_.Category -eq 'Sorveglianza audio/video' }).Count | Should -Be 2
    }

    It "espone il modello di calcolo usato" {
        $r = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $null -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $r.Model | Should -Be 'DV-SCORE-2'
    }
}

Describe "Test-DVSameSoftware - correlazione conservativa" {
    It "riconosce lo stesso programma con o senza estensione" {
        Test-DVSameSoftware -A 'winvnc.exe' -B 'WinVNC' | Should -BeTrue
    }
    It "non correla programmi diversi" {
        Test-DVSameSoftware -A 'svchost' -B 'winvnc' | Should -BeFalse
    }
    It "non correla su valori vuoti" {
        Test-DVSameSoftware -A '' -B 'winvnc' | Should -BeFalse
    }
    It "non correla su sigle troppo corte (evita falsi accostamenti)" {
        Test-DVSameSoftware -A 'vn' -B 'winvnc' | Should -BeFalse
    }
}

Describe "Get-DVMethodologyHTML - dichiarazione del perimetro" {
    It "senza privilegi elevati marca i controlli che richiedono amministratore" {
        $h = Get-DVMethodologyHTML -IsElevated $false -Version '5.1.2'
        $h | Should -Match 'PARZIALE'
        $h | Should -Match 'utente standard'
    }
    It "con privilegi elevati non dichiara controlli parziali" {
        $h = Get-DVMethodologyHTML -IsElevated $true -Version '5.1.2'
        $h | Should -Not -Match 'PARZIALE'
    }
    It "elenca sempre il registro eventi di sicurezza, anche quando non eseguibile" {
        $h = Get-DVMethodologyHTML -IsElevated $false -Version '5.1.2'
        $h | Should -Match 'Registro eventi Sicurezza'
    }
}

Describe "Get-DVScoreTableHTML - verificabilita' del conto" {
    It "riporta il totale e la riga di ogni evidenza" {
        $rc = @{
            RemoteControl = @([PSCustomObject]@{ Name = 'WinVNC'; ProcessName = 'winvnc'; Risk = 'CRITICAL'; SignatureStatus = 'Unknown'; Path = 'C:\x\winvnc.exe' })
            Spyware = @(); EmployeeMonitor = @(); OtherSuspicious = @()
        }
        $r = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $rc -ServiceAnalysis @() `
            -SoftwareAnalysis @() -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null
        $h = Get-DVScoreTableHTML -ThreatScore $r
        $h | Should -Match 'PUNTEGGIO TOTALE'
        $h | Should -Match 'R-01'
        $h | Should -Match 'Pesi e soglie'
    }
}

Describe "Get-DVMethodologyHTML - esattezza dei dati dichiarati" {
    It "riporta il numero di regole caricate, non il numero di chiavi della struttura" {
        # $RulesInfo e' una hashtable: .Count restituirebbe 4 (le chiavi) invece di 75.
        $rules = @{ Loaded = 75; SourceCount = 7; Skipped = @(); UsedFallback = $false }
        $h = Get-DVMethodologyHTML -IsElevated $true -RulesInfo $rules -Version '5.1.3'
        $h | Should -Match '75 regole caricate da 7 file'
    }
    It "dichiara il database di riserva quando nessuna regola esterna e' stata caricata" {
        $rules = @{ Loaded = 0; SourceCount = 0; Skipped = @(); UsedFallback = $true }
        $h = Get-DVMethodologyHTML -IsElevated $true -RulesInfo $rules -Version '5.1.3'
        $h | Should -Match 'database interno di riserva'
    }
    It "riporta la versione dello strumento" {
        $h = Get-DVMethodologyHTML -IsElevated $true -Version '5.1.3'
        $h | Should -Match 'DigitalValut Controller 5\.1\.3'
    }
}

Describe 'Get-DVAdminMembership - appartenenza al gruppo Amministratori' {
    BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\core\modules\SystemInfo.psm1') -Force }
    It 'utente standard: nessun SID Amministratori nel token' {
        Get-DVAdminMembership -GroupSids @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-4') | Should -Be 'No'
    }
    It 'amministratore (anche con token ridotto da UAC): SID presente' {
        Get-DVAdminMembership -GroupSids @('S-1-1-0', 'S-1-5-32-544', 'S-1-5-32-545') | Should -Be 'Si'
    }
    It 'token illeggibile o vuoto: indeterminato, mai "No"' {
        Get-DVAdminMembership -GroupSids @() | Should -Be 'Indeterminato'
    }
}

Describe 'Registro locale dello strumento (accessi passati)' {
    BeforeAll {
        function New-FakeLog { param([int]$Count, [string[]]$Addrs = @('10.30.1.5'))
            [PSCustomObject]@{ RemoteConnectionCount = $Count; RemoteSessionCount = $Count; FailedAttemptCount = 0; DistinctRemoteAddresses = $Addrs
                FirstSeenText = '2026-10-01 09:00:00'; LastSeenText = '2026-10-08 18:30:00'; AnyFileRead = $true; AnyFileFound = $true
                Files = @([PSCustomObject]@{ Path = 'C:\x\winvnc.log'; Exists = $true; Readable = $true; Sha256 = ('a' * 64); SizeBytes = 100; Truncated = $false; Error = ''; ConnectionLines = $Count; LastWrite = $null })
                Events = @(1..$Count | ForEach-Object { [PSCustomObject]@{ Time = $null; TimeText = '2026-10-01 09:00:00'; Kind = 'Connessione accettata'; Address = '10.30.1.5'; IsLocal = $false; Source = 'C:\x\winvnc.log' } }); EventLog = $null }
        }
    }
    It 'connessioni passate: +10 punti e la somma delle evidenze resta uguale al totale' {
        $r = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $null -ServiceAnalysis @() -SoftwareAnalysis @() `
            -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null -UltraVncLog (New-FakeLog -Count 3)
        $r.Score | Should -Be 10
        $sum = 0; foreach ($e in $r.Evidence) { $sum += [int]$e.Points }
        $sum | Should -Be $r.Score
    }
    It 'nessuna connessione riconosciuta: 0 punti' {
        $r = Get-DVThreatScore -PortAnalysis $null -ProcessAnalysis $null -ServiceAnalysis @() -SoftwareAnalysis @() `
            -FirewallStatus @{ AllEnabled = $true } -NetworkConnections $null -UltraVncLog (New-FakeLog -Count 0 -Addrs @())
        $r.Score | Should -Be 0
    }
    It 'la sezione HTML indica che un registro senza connessioni non prova l''assenza' {
        $h = Get-DVUltraVncLogHTML -UltraVncLog (New-FakeLog -Count 0 -Addrs @())
        $h | Should -Match 'non prova'
    }
    It 'la sezione HTML riporta indirizzi e hash, nessun altro contenuto' {
        $h = Get-DVUltraVncLogHTML -UltraVncLog (New-FakeLog -Count 2)
        $h | Should -Match '10\.30\.1\.5'
        $h | Should -Match ('a' * 64)
    }
    It 'senza dati di registro la sezione e'' vuota' {
        (Get-DVUltraVncLogHTML -UltraVncLog $null) | Should -Be ''
    }
}
