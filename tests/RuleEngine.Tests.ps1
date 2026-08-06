BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\RuleEngine.psm1") -Force
    $script:TestDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dvrules_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

    function New-TestRuleFile {
        param([string]$Name, [string]$Content)
        $path = Join-Path $script:TestDir $Name
        [System.IO.File]::WriteAllText($path, $Content, (New-Object System.Text.UTF8Encoding($false)))
        return $path
    }
}

AfterAll {
    if (Test-Path $script:TestDir) { Remove-Item -Path $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe "Test-DVRuleValid" {
    It "accetta una regola process completa e corretta" {
        $rule = [PSCustomObject]@{
            id = "T-1"; name = "Test"; type = "process"; risk = "HIGH"
            match = [PSCustomObject]@{ nameContains = @("qualcosa") }
        }
        (Test-DVRuleValid -Rule $rule).Valid | Should -BeTrue
    }

    It "accetta una regola port con elenco di porte" {
        $rule = [PSCustomObject]@{
            id = "T-2"; name = "Porta"; type = "port"; risk = "CRITICAL"
            match = [PSCustomObject]@{ ports = @(5900, 5901) }
        }
        (Test-DVRuleValid -Rule $rule).Valid | Should -BeTrue
    }

    It "scarta una regola nulla" {
        (Test-DVRuleValid -Rule $null).Valid | Should -BeFalse
    }

    It "scarta una regola senza il campo obbligatorio risk" {
        $rule = [PSCustomObject]@{
            id = "T-3"; name = "Test"; type = "process"
            match = [PSCustomObject]@{ nameContains = @("x") }
        }
        $result = Test-DVRuleValid -Rule $rule
        $result.Valid | Should -BeFalse
        $result.Reason | Should -Match "risk"
    }

    It "scarta un type non ammesso" {
        $rule = [PSCustomObject]@{
            id = "T-4"; name = "Test"; type = "inventato"; risk = "HIGH"
            match = [PSCustomObject]@{ nameContains = @("x") }
        }
        $result = Test-DVRuleValid -Rule $rule
        $result.Valid | Should -BeFalse
        $result.Reason | Should -Match "type non valido"
    }

    It "scarta un livello di rischio non ammesso" {
        $rule = [PSCustomObject]@{
            id = "T-5"; name = "Test"; type = "process"; risk = "ALTISSIMO"
            match = [PSCustomObject]@{ nameContains = @("x") }
        }
        (Test-DVRuleValid -Rule $rule).Valid | Should -BeFalse
    }

    It "scarta una regola senza alcun criterio di match" {
        $rule = [PSCustomObject]@{
            id = "T-6"; name = "Test"; type = "process"; risk = "HIGH"
            match = [PSCustomObject]@{ }
        }
        (Test-DVRuleValid -Rule $rule).Valid | Should -BeFalse
    }

    It "scarta una regola port senza porte" {
        $rule = [PSCustomObject]@{
            id = "T-7"; name = "Test"; type = "port"; risk = "HIGH"
            match = [PSCustomObject]@{ nameContains = @("x") }
        }
        (Test-DVRuleValid -Rule $rule).Valid | Should -BeFalse
    }
}

Describe "Import-DVRules" {
    It "restituisce zero regole se la cartella non esiste, senza sollevare eccezioni" {
        { Import-DVRules -RulesPath "C:\cartella\che\non\esiste" } | Should -Not -Throw
        $r = Import-DVRules -RulesPath "C:\cartella\che\non\esiste"
        @($r.Rules).Count | Should -Be 0
    }

    It "carica una regola singola da un file JSON" {
        New-TestRuleFile -Name "singola.json" -Content '{"id":"S-1","name":"Singola","type":"process","risk":"HIGH","match":{"nameContains":["abc"]}}' | Out-Null
        $r = Import-DVRules -RulesPath $script:TestDir
        @($r.Rules | Where-Object { $_.id -eq 'S-1' }).Count | Should -Be 1
        Remove-Item (Join-Path $script:TestDir "singola.json") -Force
    }

    It "carica piu' regole da un file contenente un array" {
        New-TestRuleFile -Name "multi.json" -Content '[{"id":"M-1","name":"A","type":"process","risk":"HIGH","match":{"nameContains":["a"]}},{"id":"M-2","name":"B","type":"process","risk":"LOW","match":{"nameContains":["b"]}}]' | Out-Null
        $r = Import-DVRules -RulesPath $script:TestDir
        @($r.Rules | Where-Object { $_.id -like 'M-*' }).Count | Should -Be 2
        Remove-Item (Join-Path $script:TestDir "multi.json") -Force
    }

    It "ignora un file con JSON non valido senza bloccare il caricamento delle altre regole" {
        New-TestRuleFile -Name "rotta.json" -Content '{ questo non e json' | Out-Null
        New-TestRuleFile -Name "buona.json" -Content '{"id":"B-1","name":"Buona","type":"process","risk":"HIGH","match":{"nameContains":["ok"]}}' | Out-Null

        $r = Import-DVRules -RulesPath $script:TestDir
        @($r.Rules | Where-Object { $_.id -eq 'B-1' }).Count | Should -Be 1
        ($r.Skipped -join ' ') | Should -Match "rotta.json"

        Remove-Item (Join-Path $script:TestDir "rotta.json") -Force
        Remove-Item (Join-Path $script:TestDir "buona.json") -Force
    }

    It "riporta il motivo dello scarto per una regola incompleta" {
        New-TestRuleFile -Name "incompleta.json" -Content '{"id":"I-1","name":"Incompleta","type":"process","match":{"nameContains":["x"]}}' | Out-Null
        $r = Import-DVRules -RulesPath $script:TestDir
        ($r.Skipped -join ' ') | Should -Match "risk"
        Remove-Item (Join-Path $script:TestDir "incompleta.json") -Force
    }

    It "traccia il file di provenienza di ogni regola caricata" {
        New-TestRuleFile -Name "origine.json" -Content '{"id":"O-1","name":"Origine","type":"process","risk":"HIGH","match":{"nameContains":["z"]}}' | Out-Null
        $r = Import-DVRules -RulesPath $script:TestDir
        $rule = $r.Rules | Where-Object { $_.id -eq 'O-1' }
        $rule.SourceFile | Should -Be "origine.json"
        Remove-Item (Join-Path $script:TestDir "origine.json") -Force
    }

    It "legge anche le regole nelle sottocartelle (es. custom)" {
        $sub = Join-Path $script:TestDir "custom"
        New-Item -ItemType Directory -Path $sub -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $sub "utente.json"), '{"id":"U-1","name":"Utente","type":"process","risk":"MEDIUM","match":{"nameContains":["mio"]}}', (New-Object System.Text.UTF8Encoding($false)))
        $r = Import-DVRules -RulesPath $script:TestDir
        @($r.Rules | Where-Object { $_.id -eq 'U-1' }).Count | Should -Be 1
        Remove-Item $sub -Recurse -Force
    }
}

Describe "Test-DVRuleMatch" {
    BeforeAll {
        $script:Rule = [PSCustomObject]@{
            id = "R-1"; name = "Test"; type = "process"; risk = "HIGH"
            match = [PSCustomObject]@{
                nameContains = @("vnc")
                excludeIfPathContains = @("\program files\aziendale\")
            }
        }
    }

    It "trova una corrispondenza indipendentemente da maiuscole e minuscole" {
        Test-DVRuleMatch -Rule $script:Rule -Name "WinVNC.exe" | Should -BeTrue
        Test-DVRuleMatch -Rule $script:Rule -Name "ULTRAVNC" | Should -BeTrue
    }

    It "non trova corrispondenza su un nome estraneo" {
        Test-DVRuleMatch -Rule $script:Rule -Name "chrome.exe" | Should -BeFalse
    }

    It "l'esclusione per percorso ha la precedenza sul match del nome" {
        Test-DVRuleMatch -Rule $script:Rule -Name "winvnc.exe" -Path "C:\Program Files\Aziendale\winvnc.exe" | Should -BeFalse
    }

    It "gestisce nome e percorso vuoti senza errori" {
        { Test-DVRuleMatch -Rule $script:Rule -Name "" -Path "" } | Should -Not -Throw
    }
}

Describe "Test-DVPortRuleMatch" {
    It "riconosce una porta presente nell'elenco" {
        $rule = [PSCustomObject]@{ match = [PSCustomObject]@{ ports = @(5900, 5901) } }
        Test-DVPortRuleMatch -Rule $rule -Port 5900 | Should -BeTrue
    }

    It "non riconosce una porta assente" {
        $rule = [PSCustomObject]@{ match = [PSCustomObject]@{ ports = @(5900) } }
        Test-DVPortRuleMatch -Rule $rule -Port 443 | Should -BeFalse
    }
}

Describe "Conversione ai database usati dai moduli esistenti" {
    It "ConvertTo-DVPortDatabase produce una hashtable indicizzata per numero di porta" {
        $rules = @(
            [PSCustomObject]@{ id="P-1"; name="VNC"; type="port"; risk="CRITICAL"; category="Remote"; description="desc"; match=[PSCustomObject]@{ ports=@(5900,5901) } }
        )
        $db = ConvertTo-DVPortDatabase -Rules $rules
        $db.Count | Should -Be 2
        $db[5900].Name | Should -Be "VNC"
        $db[5900].Risk | Should -Be "CRITICAL"
    }

    It "ConvertTo-DVProcessDatabase produce una hashtable indicizzata per pattern del nome" {
        $rules = @(
            [PSCustomObject]@{ id="Q-1"; name="TeamViewer"; type="process"; risk="CRITICAL"; category="Remote Control"; alert=$true; match=[PSCustomObject]@{ nameContains=@("teamviewer") } }
        )
        $db = ConvertTo-DVProcessDatabase -Rules $rules -Types @('process')
        $db['teamviewer'].Name | Should -Be "TeamViewer"
        $db['teamviewer'].Alert | Should -BeTrue
    }

    It "gestisce un elenco di regole vuoto senza errori" {
        { ConvertTo-DVPortDatabase -Rules @() } | Should -Not -Throw
        (ConvertTo-DVPortDatabase -Rules @()).Count | Should -Be 0
    }
}

Describe "Regole ufficiali del progetto" {
    It "tutte le regole in core/rules sono valide (nessuno scarto)" {
        $officialPath = Join-Path $PSScriptRoot "..\core\rules"
        $r = Import-DVRules -RulesPath $officialPath
        $r.Skipped | Should -BeNullOrEmpty
    }

    It "le regole ufficiali producono un database di porte e processi non vuoto" {
        $officialPath = Join-Path $PSScriptRoot "..\core\rules"
        $r = Import-DVRules -RulesPath $officialPath
        (ConvertTo-DVPortDatabase -Rules $r.Rules).Count | Should -BeGreaterThan 0
        (ConvertTo-DVProcessDatabase -Rules $r.Rules -Types @('process')).Count | Should -BeGreaterThan 0
    }

    It "non ci sono id di regola duplicati" {
        $officialPath = Join-Path $PSScriptRoot "..\core\rules"
        $r = Import-DVRules -RulesPath $officialPath
        $ids = @($r.Rules | ForEach-Object { $_.id })
        $unique = @($ids | Select-Object -Unique)
        $ids.Count | Should -Be $unique.Count
    }
}
