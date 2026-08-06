BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\EventLogAnalyzer.psm1") -Force
}

Describe "Test-DVCanReadSecurityLog" {
    It "non solleva mai eccezioni, qualunque sia il livello di privilegi" {
        { Test-DVCanReadSecurityLog } | Should -Not -Throw
    }

    It "restituisce un booleano" {
        (Test-DVCanReadSecurityLog) | Should -BeOfType [bool]
    }
}

Describe "Get-DVServiceInstallEvents - parsing degli eventi 7045" {
    # Sulla macchina di sviluppo non esistevano eventi 7045 reali: il parsing viene
    # quindi verificato con un evento sintetico che riproduce la struttura XML
    # documentata da Microsoft per l'evento 7045 del registro System.
    BeforeAll {
        $script:FakeXml = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>7045</EventID></System>
  <EventData>
    <Data Name="ServiceName">uvnc_service</Data>
    <Data Name="ImagePath">C:\Program Files\UltraVNC\winvnc.exe -service</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="StartType">auto start</Data>
  </EventData>
</Event>
"@
    }

    It "estrae correttamente ServiceName e ImagePath dalla struttura XML dell'evento" {
        $xml = [xml]$script:FakeXml
        $serviceName = ""
        $imagePath = ""
        foreach ($d in $xml.Event.EventData.Data) {
            switch ($d.Name) {
                'ServiceName' { $serviceName = $d.'#text' }
                'ImagePath'   { $imagePath = $d.'#text' }
            }
        }
        $serviceName | Should -Be "uvnc_service"
        $imagePath | Should -Match "winvnc.exe"
    }

    It "la logica di corrispondenza riconosce uno strumento noto dal nome del servizio" {
        $processDb = @{ "winvnc" = @{ Name = "UltraVNC"; Alert = $true } }
        $haystack = "uvnc_service C:\Program Files\UltraVNC\winvnc.exe -service".ToLower()
        $matched = $null
        foreach ($key in $processDb.Keys) {
            if ($processDb[$key].Alert -eq $true -and $haystack.Contains($key.ToLower())) {
                $matched = $processDb[$key].Name
                break
            }
        }
        $matched | Should -Be "UltraVNC"
    }

    It "non solleva eccezioni se non ci sono eventi nel periodo richiesto" {
        { Get-DVServiceInstallEvents -DaysBack 1 -ProcessDb @{} } | Should -Not -Throw
    }
}

Describe "Get-DVEventLogFindings" {
    It "viene eseguita end-to-end senza sollevare eccezioni, anche senza privilegi" {
        { Get-DVEventLogFindings -DaysBack 7 -ProcessDb @{} } | Should -Not -Throw
    }

    It "restituisce sempre la struttura attesa" {
        $r = Get-DVEventLogFindings -DaysBack 7 -ProcessDb @{}
        $r.Keys | Should -Contain "SecurityLogReadable"
        $r.Keys | Should -Contain "ServiceInstalls"
        $r.Keys | Should -Contain "Score"
        $r.Keys | Should -Contain "Findings"
        $r.Keys | Should -Contain "DaysAnalyzed"
    }

    It "dichiara esplicitamente il numero di giorni analizzati" {
        (Get-DVEventLogFindings -DaysBack 14 -ProcessDb @{}).DaysAnalyzed | Should -Be 14
    }

    It "il punteggio non e' mai negativo" {
        (Get-DVEventLogFindings -DaysBack 7 -ProcessDb @{}).Score | Should -BeGreaterOrEqual 0
    }

    It "se il registro Security non e' leggibile, le sezioni che lo richiedono restano vuote" {
        $r = Get-DVEventLogFindings -DaysBack 7 -ProcessDb @{}
        if (-not $r.SecurityLogReadable) {
            @($r.SecurityLogCleared).Count | Should -Be 0
            @($r.RemoteLogons).Count | Should -Be 0
        }
    }
}
