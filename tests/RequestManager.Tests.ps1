BeforeAll {
    $script:Root = Join-Path $PSScriptRoot '..'
    $script:ModuleFile = Join-Path (Join-Path (Join-Path $script:Root 'core') 'modules') 'RequestManager.psm1'
    $script:ScriptFile = Join-Path (Join-Path $script:Root 'core') 'Richieste.ps1'
    Import-Module $script:ModuleFile -Force
}

Describe "Invarianti di progetto: nessun invio in rete" {
    It "il modulo non contiene chiamate di rete o di posta" {
        $src = Get-Content -Path $script:ModuleFile -Raw
        $src | Should -Not -Match 'Invoke-WebRequest|Invoke-RestMethod|Send-MailMessage|System\.Net\.Http|WebClient|Net\.Sockets|Start-BitsTransfer'
    }

    It "lo script interattivo non contiene chiamate di rete o di posta" {
        $src = Get-Content -Path $script:ScriptFile -Raw
        $src | Should -Not -Match 'Invoke-WebRequest|Invoke-RestMethod|Send-MailMessage|System\.Net\.Http|WebClient|Net\.Sockets|Start-BitsTransfer'
    }
}

Describe "Get-DVResponseDeadline" {
    It "un mese di calendario, non 30 giorni (31 gennaio -> 28 febbraio)" {
        (Get-DVResponseDeadline -ReceivedDate ([datetime]'2026-01-31') -Months 1).ToString('yyyy-MM-dd') | Should -Be '2026-02-28'
    }

    It "un mese da 1 settembre -> 1 ottobre" {
        (Get-DVResponseDeadline -ReceivedDate ([datetime]'2026-09-01') -Months 1).ToString('yyyy-MM-dd') | Should -Be '2026-10-01'
    }

    It "10 giorni per il sollecito" {
        (Get-DVResponseDeadline -ReceivedDate ([datetime]'2026-10-01') -Days 10).ToString('yyyy-MM-dd') | Should -Be '2026-10-11'
    }

    It "nessun termine se mesi e giorni sono zero" {
        Get-DVResponseDeadline -ReceivedDate ([datetime]'2026-10-01') | Should -BeNullOrEmpty
    }
}

Describe "ConvertTo-DVNeutralFinding" {
    It "toglie l'etichetta di gravita'" {
        ConvertTo-DVNeutralFinding -Finding '[CRITICO] Software controllo remoto: WinVNC' | Should -Be 'Software controllo remoto: WinVNC'
    }

    It "gestisce stringhe vuote e null" {
        ConvertTo-DVNeutralFinding -Finding '' | Should -Be ''
        ConvertTo-DVNeutralFinding -Finding $null | Should -Be ''
    }
}

Describe "Modelli di richiesta" {
    BeforeAll {
        $script:scan = [PSCustomObject]@{
            ComputerName = 'PC-PROVA'; ScanDate = '2026-10-13 09:16:52'; ReportHash = 'abc123'
            ReportFileName = 'DV_Report_PC-PROVA.html'; Findings = @('Software controllo remoto: WinVNC')
        }
    }

    It "Expand-DVTemplate lascia un segnaposto visibile quando manca un dato" {
        Expand-DVTemplate -Template 'Ciao {{NOME}}' -Data @{} | Should -Be 'Ciao [DA COMPILARE: NOME]'
        Expand-DVTemplate -Template 'Ciao {{NOME}}' -Data @{ NOME = 'Anna' } | Should -Be 'Ciao Anna'
    }

    It "ogni tipo di richiesta si compone senza lasciare segnaposto {{ }} non risolti" {
        foreach ($t in 'DPO-ISTANZA', 'DPO-SOLLECITO', 'RSU', 'INL', 'GARANTE-RECLAMO') {
            $txt = New-DVRequestText -Type $t -Scan $script:scan -Today ([datetime]'2026-10-13')
            $txt | Should -Not -Match '\{\{'
        }
    }

    It "i tipi che riportano le rilevazioni le includono nel testo" {
        foreach ($t in 'DPO-ISTANZA', 'RSU', 'INL', 'GARANTE-RECLAMO') {
            (New-DVRequestText -Type $t -Scan $script:scan) | Should -Match 'WinVNC'
        }
    }

    It "l'istanza al DPO cita gli artt. 12, 13, 15 GDPR, l'art. 4 L. 300/1970 e calcola la scadenza a un mese" {
        $txt = New-DVRequestText -Type 'DPO-ISTANZA' -Scan $script:scan -Today ([datetime]'2026-10-13')
        $txt | Should -Match 'artt\. 12, 13 e 15'
        $txt | Should -Match 'art\. 4'
        $txt | Should -Match '13/11/2026'
    }

    It "i modelli dichiarano di non costituire accusa di illecito e che il report non e' una perizia" {
        foreach ($t in 'DPO-ISTANZA', 'DPO-SOLLECITO', 'RSU', 'INL') {
            (New-DVRequestText -Type $t -Scan $script:scan) | Should -Match 'non costituisce accusa'
        }
        (New-DVRequestText -Type 'DPO-ISTANZA' -Scan $script:scan) | Should -Match 'non costituisce perizia'
    }

    It "il testo generato segnala i punti ancora da completare" {
        $txt = New-DVRequestText -Type 'DPO-ISTANZA' -Scan $script:scan
        (Get-DVRequestOpenPoints -Text $txt) | Should -BeGreaterThan 0
    }

    It "il reclamo al Garante cita l'art. 77 GDPR" {
        (New-DVRequestText -Type 'GARANTE-RECLAMO' -Scan $script:scan) | Should -Match 'art\. 77'
    }
}

Describe "Registro delle richieste (catena di hash)" {
    BeforeEach {
        $script:ledger = Join-Path $TestDrive ("richieste_{0}.jsonl" -f ([guid]::NewGuid().ToString('N')))
    }

    It "senza registro: valido e vuoto" {
        (Test-DVRequestChain -LedgerPath $script:ledger).Valid | Should -BeTrue
    }

    It "INVIATA di una istanza DPO calcola la scadenza a un mese" {
        $ev = Add-DVRequestEvent -LedgerPath $script:ledger -Id 'RQ-1' -Event INVIATA -Type 'DPO-ISTANZA' -EventDate ([datetime]'2026-09-01')
        $ev.Deadline | Should -Be '2026-10-01'
    }

    It "INVIATA di un sollecito calcola 10 giorni; RSU non ha scadenza" {
        (Add-DVRequestEvent -LedgerPath $script:ledger -Id 'RQ-2' -Event INVIATA -Type 'DPO-SOLLECITO' -EventDate ([datetime]'2026-10-01')).Deadline | Should -Be '2026-10-11'
        (Add-DVRequestEvent -LedgerPath $script:ledger -Id 'RQ-3' -Event INVIATA -Type 'RSU' -EventDate ([datetime]'2026-10-01')).Deadline | Should -Be ''
    }

    It "catena integra dopo piu' eventi" {
        Add-DVRequestEvent -LedgerPath $script:ledger -Id 'RQ-1' -Event PREPARATA -Type 'DPO-ISTANZA' | Out-Null
        Add-DVRequestEvent -LedgerPath $script:ledger -Id 'RQ-1' -Event INVIATA -Type 'DPO-ISTANZA' -Reference 'ricevuta-1' | Out-Null
        $r = Test-DVRequestChain -LedgerPath $script:ledger
        $r.Valid | Should -BeTrue
        $r.TotalEntries | Should -Be 2
    }

    It "rileva la modifica di un record" {
        Add-DVRequestEvent -LedgerPath $script:ledger -Id 'RQ-1' -Event INVIATA -Type 'DPO-ISTANZA' -Reference 'ricevuta-1' | Out-Null
        Add-DVRequestEvent -LedgerPath $script:ledger -Id 'RQ-1' -Event NOTA -Type 'DPO-ISTANZA' -Note 'x' | Out-Null
        $content = Get-Content -Path $script:ledger -Raw
        Set-Content -Path $script:ledger -Value ($content -replace 'ricevuta-1', 'ricevuta-9') -Encoding UTF8
        (Test-DVRequestChain -LedgerPath $script:ledger).Valid | Should -BeFalse
    }

    It "rileva la rimozione di un record" {
        Add-DVRequestEvent -LedgerPath $script:ledger -Id 'RQ-1' -Event PREPARATA -Type 'DPO-ISTANZA' | Out-Null
        Add-DVRequestEvent -LedgerPath $script:ledger -Id 'RQ-1' -Event INVIATA -Type 'DPO-ISTANZA' | Out-Null
        Add-DVRequestEvent -LedgerPath $script:ledger -Id 'RQ-1' -Event NOTA -Type 'DPO-ISTANZA' | Out-Null
        $lines = @(Get-Content -Path $script:ledger)
        Set-Content -Path $script:ledger -Value @($lines[0], $lines[2]) -Encoding UTF8
        (Test-DVRequestChain -LedgerPath $script:ledger).Valid | Should -BeFalse
    }
}

Describe "Get-DVRequestSummary - stato e passo successivo" {
    BeforeAll {
        $script:newEv = { param($Id, $Event, $Type, $Deadline = '', $Recipient = '')
            [PSCustomObject]@{ Id = $Id; Event = $Event; Type = $Type; Deadline = $Deadline; Recipient = $Recipient } }
        $script:today = [datetime]'2026-10-13'
    }

    It "solo preparata" {
        $s = @(Get-DVRequestSummary -Events @(& $script:newEv 'A' 'PREPARATA' 'DPO-ISTANZA') -Today $script:today)
        $s[0].Stato | Should -Be 'PREPARATA'
    }

    It "inviata con scadenza futura: giorni residui" {
        $s = @(Get-DVRequestSummary -Events @((& $script:newEv 'A' 'PREPARATA' 'DPO-ISTANZA'), (& $script:newEv 'A' 'INVIATA' 'DPO-ISTANZA' '2026-10-20')) -Today $script:today)
        $s[0].Stato | Should -Be 'INVIATA'
        $s[0].GiorniResidui | Should -Be 7
    }

    It "istanza scaduta: suggerisce il sollecito" {
        $s = @(Get-DVRequestSummary -Events @((& $script:newEv 'A' 'INVIATA' 'DPO-ISTANZA' '2026-10-01')) -Today $script:today)
        $s[0].Stato | Should -Be 'SCADUTA'
        $s[0].ProssimoPasso | Should -Match 'DPO-SOLLECITO'
    }

    It "sollecito scaduto: suggerisce il reclamo al Garante" {
        $s = @(Get-DVRequestSummary -Events @((& $script:newEv 'B' 'INVIATA' 'DPO-SOLLECITO' '2026-10-05')) -Today $script:today)
        $s[0].ProssimoPasso | Should -Match 'GARANTE-RECLAMO'
    }

    It "con risposta ricevuta non risulta scaduta; chiusa prevale" {
        $r = @(Get-DVRequestSummary -Events @((& $script:newEv 'A' 'INVIATA' 'DPO-ISTANZA' '2026-10-01'), (& $script:newEv 'A' 'RISPOSTA_RICEVUTA' 'DPO-ISTANZA')) -Today $script:today)
        $r[0].Stato | Should -Be 'RISPOSTA_RICEVUTA'
        $c = @(Get-DVRequestSummary -Events @((& $script:newEv 'A' 'INVIATA' 'DPO-ISTANZA' '2026-10-01'), (& $script:newEv 'A' 'CHIUSA' 'DPO-ISTANZA')) -Today $script:today)
        $c[0].Stato | Should -Be 'CHIUSA'
    }

    It "senza eventi: nessuna riga" {
        @(Get-DVRequestSummary -Events @() -Today $script:today).Count | Should -Be 0
    }
}

Describe "Get-DVLatestScanSummary" {
    It "senza report restituisce null" {
        Get-DVLatestScanSummary -ReportDir (Join-Path $TestDrive 'non-esiste') | Should -BeNullOrEmpty
    }

    It "ricava dati neutri, senza duplicati e senza porte Windows standard" {
        $dir = Join-Path $TestDrive 'rep'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $json = @'
{"SystemInfo":{"ComputerName":"PC-X","ScanDate":"2026-10-13 09:16:52"},
 "ThreatScore":{"Findings":["[CRITICO] Software controllo remoto: WinVNC","[CRITICO] Software controllo remoto: WinVNC"]},
 "ActiveRemoteConnections":[
   {"PortaLocale":5900,"Processo":"winvnc","Stato":"IN ASCOLTO - accetta connessioni","Rischio":"CRITICO"},
   {"PortaLocale":445,"Processo":"System","Stato":"IN ASCOLTO - x","Rischio":"ALTO"},
   {"PortaLocale":135,"Processo":"svchost","Stato":"IN ASCOLTO - x","Rischio":"BASSO"}]}
'@
        Set-Content -Path (Join-Path $dir 'DV_Report_PC-X_2026-10-13_09-16.json') -Value $json -Encoding UTF8
        Set-Content -Path (Join-Path $dir 'DV_Report_PC-X_2026-10-13_09-16.html') -Value '<html></html>' -Encoding UTF8
        $s = Get-DVLatestScanSummary -ReportDir $dir
        $s.ComputerName | Should -Be 'PC-X'
        $s.ReportHash | Should -Match '^[0-9a-f]{64}$'
        @($s.Findings | Where-Object { $_ -match '^Software controllo remoto' }).Count | Should -Be 1
        ($s.Findings -join '|') | Should -Match '5900'
        ($s.Findings -join '|') | Should -Not -Match '445'
        ($s.Findings -join '|') | Should -Not -Match '135'
    }
}

Describe 'Dichiarazione sui privilegi: si afferma solo cio'' che e'' accertato' {
    BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\core\modules\RequestManager.psm1') -Force }
    It 'utente non elevato ma membro del gruppo Amministratori: la lettera NON afferma di non avere privilegi' {
        $scan = [PSCustomObject]@{ ReportFileName='r.html'; ReportHash='abc'; ComputerName='PC'; ScanDate='2026-10-13'; Findings=@(); IsElevated=$false; AdminGroupMember='Si'; ConsentOutcome=''; ConsentReason='' }
        $t = New-DVRequestText -Type 'DPO-ISTANZA' -Data @{} -Scan $scan -Today ([datetime]'2026-10-13')
        $t | Should -Not -Match 'non disponendo di privilegi amministrativi sulla postazione assegnatami, non ho'
        $t | Should -Match 'DA COMPLETARE SOLO SE VERO'
    }
    It 'utente senza privilegi accertati (nessun SID Amministratori): la dichiarazione compare' {
        $scan = [PSCustomObject]@{ ReportFileName='r.html'; ReportHash='abc'; ComputerName='PC'; ScanDate='2026-10-13'; Findings=@(); IsElevated=$false; AdminGroupMember='No'; ConsentOutcome=''; ConsentReason='' }
        $t = New-DVRequestText -Type 'DPO-ISTANZA' -Data @{} -Scan $scan -Today ([datetime]'2026-10-13')
        $t | Should -Match 'non disponendo di privilegi amministrativi'
    }
    It 'con appartenenza indeterminata la dichiarazione non compare' {
        $scan = [PSCustomObject]@{ ReportFileName='r.html'; ReportHash='abc'; ComputerName='PC'; ScanDate='2026-10-13'; Findings=@(); IsElevated=$false; AdminGroupMember='Indeterminato'; ConsentOutcome=''; ConsentReason='' }
        $t = New-DVRequestText -Type 'DPO-ISTANZA' -Data @{} -Scan $scan -Today ([datetime]'2026-10-13')
        $t | Should -Match 'DA COMPLETARE SOLO SE VERO'
    }
}

Describe 'Registro dello strumento nella lettera' {
    BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\core\modules\RequestManager.psm1') -Force }
    It 'con connessioni nel registro la lettera le riporta; senza, la riga e'' assente' {
        $dir = Join-Path $TestDrive 'replog'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $json = '{"SystemInfo":{"ComputerName":"PC-X","ScanDate":"2026-10-13 09:16:52"},"ThreatScore":{"Findings":[]},"UltraVncLog":{"RemoteConnectionCount":12,"RemoteSessionCount":4,"DistinctRemoteAddresses":["10.30.1.5","10.30.1.9"],"FirstSeenText":"2026-10-01 09:00:00","LastSeenText":"2026-10-08 18:30:00"}}'
        Set-Content -Path (Join-Path $dir 'DV_Report_PC-X_2026-10-13_09-16.json') -Value $json -Encoding UTF8
        Set-Content -Path (Join-Path $dir 'DV_Report_PC-X_2026-10-13_09-16.html') -Value '<html></html>' -Encoding UTF8
        $s = Get-DVLatestScanSummary -ReportDir $dir
        $t = New-DVRequestText -Type 'DPO-ISTANZA' -Data @{} -Scan $s
        $t | Should -Match '4 sessioni da 2 indirizzi'
        $t | Should -Match '10\.30\.1\.5'
        $t | Should -Not -Match '\{\{REGISTRO_STRUMENTO\}\}'
        $t0 = New-DVRequestText -Type 'DPO-ISTANZA' -Data @{} -Scan $null
        $t0 | Should -Not -Match 'registro locale dello strumento'
    }
}
