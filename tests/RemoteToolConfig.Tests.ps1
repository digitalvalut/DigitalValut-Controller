BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\RemoteToolConfig.psm1") -Force
    $script:iniDir = Join-Path ([IO.Path]::GetTempPath()) ("dv-ini-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $script:iniDir | Out-Null

    $script:defaultIni = Join-Path $script:iniDir 'default.ini'
    @'
[admin]
QuerySetting=2
QueryAccept=0
QueryTimeout=10
DisableTrayIcon=0
FileTransferEnabled=1
BlankMonitorEnabled=1
MSLogonRequired=0
DebugLevel=0
AuthHosts=
[poll]
TurboMode=1
'@ | Set-Content -LiteralPath $script:defaultIni -Encoding ASCII

    $script:silentIni = Join-Path $script:iniDir 'silenzioso.ini'
    @'
[admin]
QuerySetting=1
QueryAccept=1
DisableTrayIcon=1
AllowProperties=0
FileTransferEnabled=1
service_commandline=-autoreconnect -connect 10.30.1.50
'@ | Set-Content -LiteralPath $script:silentIni -Encoding ASCII

    $script:consentIni = Join-Path $script:iniDir 'consenso.ini'
    @'
[admin]
QuerySetting=3
QueryAccept=0
DisableTrayIcon=0
'@ | Set-Content -LiteralPath $script:consentIni -Encoding ASCII

    $script:loopbackIni = Join-Path $script:iniDir 'loopback.ini'
    @'
[admin]
QuerySetting=1
LoopbackOnly=1
'@ | Set-Content -LiteralPath $script:loopbackIni -Encoding ASCII
}

Describe 'ConvertFrom-DVIniFile' {
    It 'separa le sezioni e conserva i valori come scritti' {
        $ini = ConvertFrom-DVIniFile -Path $script:defaultIni
        $ini['admin']['QuerySetting'] | Should -Be '2'
        $ini['poll']['TurboMode'] | Should -Be '1'
    }
    It 'ignora righe di commento e malformate senza interrompere la lettura' {
        $p = Join-Path $script:iniDir 'sporco.ini'
        @'
; commento
[admin]
riga senza uguale
QuerySetting=4
# altro commento
'@ | Set-Content -LiteralPath $p -Encoding ASCII
        $ini = ConvertFrom-DVIniFile -Path $p
        $ini['admin']['QuerySetting'] | Should -Be '4'
    }
}

Describe 'Get-DVUltraVncConsentAssessment - conclusione prudente' {
    It "con QuerySetting 0 o 1 dichiara che il consenso non e' previsto" {
        $r = Get-DVUltraVncConsentAssessment -Settings @{ QuerySetting = '1' }
        $r.Outcome | Should -Be 'Non previsto'
        $r.Points | Should -Be 15
    }
    It "con QuerySetting 2 e AuthHosts vuoto non afferma cio' che non puo' dimostrare" {
        $r = Get-DVUltraVncConsentAssessment -Settings @{ QuerySetting = '2'; AuthHosts = '' }
        $r.Outcome | Should -Be 'Non determinabile'
        $r.Points | Should -Be 0
    }
    It "con QuerySetting 2 e un indirizzo marcato ? riconosce il consenso parziale" {
        $r = Get-DVUltraVncConsentAssessment -Settings @{ QuerySetting = '2'; AuthHosts = '?192.168.1' }
        $r.Outcome | Should -Be 'Previsto solo per alcuni indirizzi'
    }
    It "con QuerySetting 2 e soli indirizzi ammessi dichiara il consenso non previsto" {
        $r = Get-DVUltraVncConsentAssessment -Settings @{ QuerySetting = '2'; AuthHosts = '+192.168.1' }
        $r.Outcome | Should -Be 'Non previsto'
        $r.Points | Should -Be 15
    }
    It 'con QuerySetting 3 riconosce il consenso previsto' {
        $r = Get-DVUltraVncConsentAssessment -Settings @{ QuerySetting = '3' }
        $r.Outcome | Should -Be 'Previsto'
        $r.Points | Should -Be 0
    }
    It 'con sole connessioni locali la domanda non si pone' {
        $r = Get-DVUltraVncConsentAssessment -Settings @{ QuerySetting = '1'; LoopbackOnly = '1' }
        $r.Outcome | Should -Be 'Non applicabile'
        $r.Points | Should -Be 0
    }
    It 'in assenza di impostazioni usa il valore predefinito documentato (2)' {
        $r = Get-DVUltraVncConsentAssessment -Settings @{}
        $r.Outcome | Should -Be 'Non determinabile'
    }
}

Describe 'Get-DVUltraVncConfigReport - una configurazione predefinita non viene penalizzata' {
    It 'non attribuisce punti a un UltraVNC con impostazioni predefinite' {
        $r = Get-DVUltraVncConfigReport -ConfigPath $script:defaultIni
        $r.Found | Should -BeTrue
        $r.Score | Should -Be 0
    }
    It 'riporta comunque le caratteristiche invasive, senza punteggio' {
        $r = Get-DVUltraVncConfigReport -ConfigPath $script:defaultIni
        $ft = @($r.Interpreted | Where-Object { $_.Key -eq 'FileTransferEnabled' })[0]
        $ft.Reading | Should -Match 'prelevare file'
        $ft.Points | Should -Be 0
    }
    It 'distingue i valori letti dal file da quelli predefiniti non presenti' {
        $r = Get-DVUltraVncConfigReport -ConfigPath $script:consentIni
        @($r.Interpreted | Where-Object { $_.Key -eq 'QuerySetting' })[0].IsDefault | Should -BeFalse
        @($r.Interpreted | Where-Object { $_.Key -eq 'FileTransferEnabled' })[0].IsDefault | Should -BeTrue
    }
}

Describe 'Get-DVUltraVncConfigReport - configurazione che occulta l accesso' {
    It 'penalizza assenza di consenso, icona nascosta e connessione inversa' {
        $r = Get-DVUltraVncConfigReport -ConfigPath $script:silentIni
        $r.Score | Should -Be 55
        $r.Consent.Outcome | Should -Be 'Non previsto'
        $r.ReverseConnection | Should -Match '-connect 10.30.1.50'
    }
    It 'non conta due volte lo stesso fatto: QueryAccept e ininfluente se il dialogo non compare' {
        $r = Get-DVUltraVncConfigReport -ConfigPath $script:silentIni
        $qa = @($r.Interpreted | Where-Object { $_.Key -eq 'QueryAccept' })[0]
        $qa.Points | Should -Be 0
        $qa.Reading | Should -Match 'Ininfluente'
    }
    It 'ogni riga interpretata dichiara la funzione documentata dell impostazione' {
        $r = Get-DVUltraVncConfigReport -ConfigPath $script:silentIni
        foreach ($i in @($r.Interpreted)) { $i.Governs | Should -Not -BeNullOrEmpty }
    }
    It 'la somma dei punti delle righe corrisponde al punteggio del modulo' {
        $r = Get-DVUltraVncConfigReport -ConfigPath $script:silentIni
        $sum = 0
        foreach ($i in @($r.Interpreted)) { $sum += [int]$i.Points }
        $sum | Should -Be $r.Score
    }
    It 'con sole connessioni locali non attribuisce il peso del consenso' {
        $r = Get-DVUltraVncConfigReport -ConfigPath $script:loopbackIni
        $r.Consent.Outcome | Should -Be 'Non applicabile'
    }
}

Describe 'Get-DVUltraVncConfigReport - robustezza' {
    It 'un file inesistente non genera eccezioni e dichiara Found = false' {
        $r = Get-DVUltraVncConfigReport -ConfigPath (Join-Path $script:iniDir 'non-esiste.ini')
        $r.Found | Should -BeFalse
        $r.Score | Should -Be 0
    }
    It 'Get-DVRemoteToolConfigFindings restituisce sempre la struttura attesa' {
        $r = Get-DVRemoteToolConfigFindings -UltraVncConfigPath $script:defaultIni
        $r.Keys | Should -Contain 'UltraVNC'
        $r.Keys | Should -Contain 'OtherTools'
        $r.Keys | Should -Contain 'Score'
        $r.Keys | Should -Contain 'Findings'
    }
}

Describe 'Catalogo delle impostazioni' {
    It 'ogni voce del catalogo dichiara la chiave e la funzione documentata' {
        foreach ($e in Get-DVUltraVncSettingCatalog) {
            $e.Key | Should -Not -BeNullOrEmpty
            $e.Governs | Should -Not -BeNullOrEmpty
        }
    }
    It 'solo le impostazioni di occultamento o assenza di consenso hanno peso' {
        $weighted = @()
        foreach ($e in Get-DVUltraVncSettingCatalog) {
            foreach ($k in @($e.Readings.Keys)) {
                if ([int]$e.Readings[$k].Points -gt 0) { $weighted += $e.Key }
            }
        }
        @($weighted | Select-Object -Unique) | Should -Contain 'QuerySetting'
        @($weighted | Select-Object -Unique) | Should -Contain 'DisableTrayIcon'
        @($weighted | Select-Object -Unique) | Should -Not -Contain 'FileTransferEnabled'
    }
}

Describe 'Credenziali: mai nel report' {
    BeforeAll {
        # Valore che imita una password UltraVNC cifrata (esadecimale): non deve mai uscire.
        $script:secretHex = 'DEADBEEF0123456789ABCDEF'
        $script:secretIni = Join-Path $script:iniDir 'secret.ini'
        @"
[ultravnc]
passwd=$($script:secretHex)
passwd2=CAFEBABE9876543210FEDCBA
[admin]
QuerySetting=2
QueryAccept=0
MSLogonRequired=0
"@ | Set-Content -LiteralPath $script:secretIni -Encoding ASCII
    }

    It 'riconosce come credenziale i nomi tipici' {
        foreach ($n in 'passwd', 'passwd2', 'Password', 'ViewOnlyPassword', 'ControlPassword', 'Pwd', 'api_key', 'auth_token', 'secret') {
            Test-DVSecretSettingName -Name $n | Should -BeTrue
        }
    }

    It 'non scambia impostazioni ordinarie per credenziali' {
        foreach ($n in 'QuerySetting', 'QueryAccept', 'DisableTrayIcon', 'PortNumber', 'MSLogonRequired', 'FileTransferEnabled') {
            Test-DVSecretSettingName -Name $n | Should -BeFalse
        }
    }

    It 'oscura il valore di una credenziale ma dichiara che e'' valorizzata' {
        $v = Protect-DVSettingValue -Name 'passwd' -Value 'DEADBEEF'
        $v | Should -Not -Match 'DEADBEEF'
        $v | Should -Match 'valorizzato'
    }

    It 'dichiara una credenziale vuota come tale' {
        (Protect-DVSettingValue -Name 'passwd' -Value '') | Should -Match 'vuoto'
    }

    It 'lascia invariati i valori delle impostazioni ordinarie' {
        Protect-DVSettingValue -Name 'QuerySetting' -Value '2' | Should -Be '2'
    }

    It 'la password UltraVNC non compare in Settings' {
        $r = Get-DVUltraVncConfigReport -ConfigPath $script:secretIni
        $r.Settings['passwd'] | Should -Not -Match $script:secretHex
        $r.Settings['passwd2'] | Should -Not -Match 'CAFEBABE'
    }

    It 'la password UltraVNC non compare nel JSON esportato nel report' {
        $r = Get-DVUltraVncConfigReport -ConfigPath $script:secretIni
        $json = $r | ConvertTo-Json -Depth 8
        $json | Should -Not -Match $script:secretHex
        $json | Should -Not -Match 'CAFEBABE'
    }

    It 'le impostazioni ordinarie restano interpretate dopo l''oscuramento' {
        $r = Get-DVUltraVncConfigReport -ConfigPath $script:secretIni
        $r.Settings['QuerySetting'] | Should -Be '2'
        $r.Found | Should -BeTrue
    }
}
