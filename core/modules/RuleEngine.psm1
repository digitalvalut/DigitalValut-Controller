# DigitalValut Controller v5.0 - RuleEngine Module
# Copyright (C) 2024-2026 DigitalValut - www.digitalvalut.it
# Sviluppatore: Dott. Giuseppe Falsone e il team DigitalValut
#
# Questo file e' parte di DigitalValut Controller.
# Software libero: puoi ridistribuirlo e/o modificarlo secondo i termini della
# GNU General Public License v3.0 o (a tua scelta) qualsiasi versione successiva,
# come pubblicata dalla Free Software Foundation.
# Distribuito SENZA ALCUNA GARANZIA; senza neppure la garanzia implicita di
# COMMERCIABILITA' o IDONEITA' PER UNO SCOPO PARTICOLARE. Vedi la GNU GPL v3.
# Copia della licenza nel file LICENSE. Avvertenze e limiti: DISCLAIMER.md
#
# MOTORE DI REGOLE ESTERNE
#
# Le firme di rilevamento non sono piu' scritte dentro il codice PowerShell:
# vivono in file .json nella cartella "core\rules". Chiunque puo' aggiungere
# una propria regola creando un nuovo file in quella cartella (o in
# "core\rules\custom"), SENZA modificare il codice, senza saper programmare in
# PowerShell e senza dover contattare o coinvolgere l'autore del progetto.
#
# PRINCIPI DI ROBUSTEZZA (deliberati):
# - Un file di regole malformato NON blocca mai la scansione: viene ignorato e
#   segnalato. Una regola scritta male da un terzo non puo' rompere lo strumento
#   a chi lo usa.
# - Le regole sono SOLO dati dichiarativi: non contengono codice eseguibile,
#   quindi un file di regole scaricato da terzi non puo' eseguire comandi sul PC.
#   E' una scelta di sicurezza precisa, non una limitazione tecnica.
# - Se la cartella regole manca o e' vuota, lo strumento continua a funzionare
#   con il database interno di riserva (nessuna regressione).
#
# Vedi RULES.md per il formato e per esempi copia-incolla.

$Global:DVRuleSchemaVersion = 1

function Get-DVRulesPath {
    <#
    .SYNOPSIS
        Restituisce il percorso della cartella delle regole (core\rules).
    #>
    param([string]$ModuleRoot = $PSScriptRoot)
    return (Join-Path (Split-Path -Parent $ModuleRoot) "rules")
}

function Test-DVRuleValid {
    <#
    .SYNOPSIS
        Verifica che un oggetto regola abbia i campi minimi obbligatori e valori ammessi.
    .OUTPUTS
        Hashtable con Valid (bool) e Reason (stringa) in caso di scarto.
    #>
    param([Parameter(Mandatory)][AllowNull()]$Rule)

    if ($null -eq $Rule) { return @{ Valid = $false; Reason = "regola nulla" } }

    foreach ($field in @('id', 'name', 'type', 'risk')) {
        if (-not $Rule.PSObject.Properties.Name -contains $field) {
            return @{ Valid = $false; Reason = "campo obbligatorio mancante: $field" }
        }
        if ([string]::IsNullOrWhiteSpace([string]$Rule.$field)) {
            return @{ Valid = $false; Reason = "campo obbligatorio vuoto: $field" }
        }
    }

    $validTypes = @('process', 'port', 'service', 'software', 'module')
    if ($Rule.type -notin $validTypes) {
        return @{ Valid = $false; Reason = "type non valido '$($Rule.type)' (ammessi: $($validTypes -join ', '))" }
    }

    $validRisks = @('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    if ($Rule.risk -notin $validRisks) {
        return @{ Valid = $false; Reason = "risk non valido '$($Rule.risk)' (ammessi: $($validRisks -join ', '))" }
    }

    if (-not $Rule.match) {
        return @{ Valid = $false; Reason = "sezione 'match' mancante" }
    }

    # Le regole di tipo 'port' devono indicare almeno una porta numerica
    if ($Rule.type -eq 'port') {
        if (-not $Rule.match.ports -or @($Rule.match.ports).Count -eq 0) {
            return @{ Valid = $false; Reason = "regola di tipo 'port' senza match.ports" }
        }
    } else {
        $hasCriteria = ($Rule.match.nameContains -and @($Rule.match.nameContains).Count -gt 0) -or
                       ($Rule.match.pathContains -and @($Rule.match.pathContains).Count -gt 0)
        if (-not $hasCriteria) {
            return @{ Valid = $false; Reason = "nessun criterio di match (nameContains o pathContains)" }
        }
    }

    return @{ Valid = $true; Reason = "" }
}

function Import-DVRules {
    <#
    .SYNOPSIS
        Carica tutte le regole dai file .json presenti nella cartella regole
        (ricorsivamente, quindi anche da eventuali sottocartelle come 'custom').
    .DESCRIPTION
        Ogni file puo' contenere una singola regola (oggetto JSON) oppure un
        elenco di regole (array JSON). File non leggibili, JSON non valido o
        regole che non superano la validazione vengono SCARTATI e riportati in
        'Skipped', senza mai interrompere il caricamento delle altre.
    .OUTPUTS
        Hashtable: Rules (array di regole valide), Skipped (array di descrizioni
        degli scarti), SourceCount (numero di file letti).
    #>
    param([string]$RulesPath)

    if ([string]::IsNullOrWhiteSpace($RulesPath)) { $RulesPath = Get-DVRulesPath }

    $rules = @()
    $skipped = @()
    $fileCount = 0

    if (-not (Test-Path $RulesPath)) {
        return @{ Rules = $rules; Skipped = $skipped; SourceCount = 0 }
    }

    $files = @(Get-ChildItem -Path $RulesPath -Filter "*.json" -Recurse -File -ErrorAction SilentlyContinue)
    foreach ($file in $files) {
        $fileCount++
        try {
            $raw = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($raw)) {
                $skipped += "$($file.Name): file vuoto"
                continue
            }
            $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        } catch {
            $skipped += "$($file.Name): JSON non valido o file illeggibile"
            continue
        }

        foreach ($candidate in @($parsed)) {
            $check = Test-DVRuleValid -Rule $candidate
            if ($check.Valid) {
                # Traccia da quale file proviene la regola: utile per capire chi
                # ha introdotto un falso positivo senza dover cercare a mano.
                Add-Member -InputObject $candidate -NotePropertyName 'SourceFile' -NotePropertyValue $file.Name -Force
                $rules += $candidate
            } else {
                $ruleId = if ($candidate.id) { $candidate.id } else { "(senza id)" }
                $skipped += "$($file.Name) [$ruleId]: $($check.Reason)"
            }
        }
    }

    return @{ Rules = $rules; Skipped = $skipped; SourceCount = $fileCount }
}

function Get-DVRulesByType {
    <#
    .SYNOPSIS
        Filtra le regole caricate per tipo (process/port/service/software/module).
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Rules,
        [Parameter(Mandatory)][string]$Type
    )
    return @($Rules | Where-Object { $_.type -eq $Type })
}

function Test-DVRuleMatch {
    <#
    .SYNOPSIS
        Verifica se un valore (nome processo, servizio, DLL...) e un percorso
        soddisfano i criteri di match di una regola.
    .DESCRIPTION
        Il confronto e' sempre case-insensitive e per sottostringa: e' cio' che
        rende le regole scrivibili anche da chi non conosce le espressioni
        regolari. 'excludeIfPathContains' consente di sopprimere falsi positivi
        noti (es. escludere il percorso ufficiale di un software legittimo).
    #>
    param(
        [Parameter(Mandatory)]$Rule,
        [string]$Name = "",
        [string]$Path = ""
    )

    $nameLower = if ($Name) { $Name.ToLower() } else { "" }
    $pathLower = if ($Path) { $Path.ToLower() } else { "" }

    # Esclusioni: hanno sempre la precedenza sui criteri positivi
    if ($Rule.match.excludeIfPathContains) {
        foreach ($ex in @($Rule.match.excludeIfPathContains)) {
            if ($ex -and $pathLower -and $pathLower.Contains($ex.ToString().ToLower())) { return $false }
        }
    }

    if ($Rule.match.nameContains) {
        foreach ($pattern in @($Rule.match.nameContains)) {
            if ($pattern -and $nameLower -and $nameLower.Contains($pattern.ToString().ToLower())) { return $true }
        }
    }

    if ($Rule.match.pathContains) {
        foreach ($pattern in @($Rule.match.pathContains)) {
            if ($pattern -and $pathLower -and $pathLower.Contains($pattern.ToString().ToLower())) { return $true }
        }
    }

    return $false
}

function Test-DVPortRuleMatch {
    <#
    .SYNOPSIS
        Verifica se una porta numerica e' coperta da una regola di tipo 'port'.
    #>
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][int]$Port
    )
    foreach ($p in @($Rule.match.ports)) {
        if ([int]$p -eq $Port) { return $true }
    }
    return $false
}

function ConvertTo-DVPortDatabase {
    <#
    .SYNOPSIS
        Converte le regole di tipo 'port' nella hashtable attesa dai moduli
        gia' esistenti (chiave = numero porta), per non dover riscrivere
        NetworkAnalyzer e gli altri moduli che la consumano.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Rules)

    $db = @{}
    foreach ($rule in (Get-DVRulesByType -Rules $Rules -Type 'port')) {
        foreach ($p in @($rule.match.ports)) {
            $portNum = 0
            if ([int]::TryParse([string]$p, [ref]$portNum)) {
                if (-not $db.ContainsKey($portNum)) {
                    $db[$portNum] = @{
                        Name        = $rule.name
                        Risk        = $rule.risk
                        Category    = if ($rule.category) { $rule.category } else { "" }
                        Description = if ($rule.description) { $rule.description } else { "" }
                        RuleId      = $rule.id
                    }
                }
            }
        }
    }
    return $db
}

function ConvertTo-DVProcessDatabase {
    <#
    .SYNOPSIS
        Converte le regole di tipo 'process' (e 'service'/'software', che
        condividono lo stesso formato di consumo) nella hashtable attesa dai
        moduli esistenti: chiave = pattern da cercare nel nome.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Rules,
        [string[]]$Types = @('process')
    )

    $db = @{}
    foreach ($rule in @($Rules | Where-Object { $_.type -in $Types })) {
        foreach ($pattern in @($rule.match.nameContains)) {
            if ([string]::IsNullOrWhiteSpace([string]$pattern)) { continue }
            $key = $pattern.ToString().ToLower()
            if (-not $db.ContainsKey($key)) {
                $db[$key] = @{
                    Name     = $rule.name
                    Risk     = $rule.risk
                    Type     = if ($rule.category) { $rule.category } else { "Sconosciuto" }
                    Alert    = if ($null -ne $rule.alert) { [bool]$rule.alert } else { $true }
                    RuleId   = $rule.id
                    Note     = if ($rule.falsePositiveNote) { $rule.falsePositiveNote } else { "" }
                }
            }
        }
    }
    return $db
}

Export-ModuleMember -Function Get-DVRulesPath, Test-DVRuleValid, Import-DVRules, Get-DVRulesByType, `
    Test-DVRuleMatch, Test-DVPortRuleMatch, ConvertTo-DVPortDatabase, ConvertTo-DVProcessDatabase
