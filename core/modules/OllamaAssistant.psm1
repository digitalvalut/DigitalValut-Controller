# DigitalValut Controller v5.0 - OllamaAssistant Module
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
# Spiegazione in linguaggio naturale dei findings, generata con un modello
# linguistico che gira IN LOCALE tramite Ollama (https://ollama.com).
#
# GARANZIA ARCHITETTURALE (non aggirabile da questo modulo):
# - L'UNICO endpoint contattato e' http://127.0.0.1:<porta>, cioe' l'interfaccia
#   di loopback della stessa macchina. Il traffico non attraversa mai una scheda
#   di rete fisica ne' esce dal dispositivo: e' equivalente a una chiamata tra
#   due processi sullo stesso PC, non a una connessione Internet.
# - Se Ollama non e' installato o non e' in esecuzione, ogni funzione di questo
#   modulo fallisce in modo silenzioso e restituisce $null: lo strumento
#   prosegue esattamente come se il modulo non esistesse. Nessuna dipendenza
#   obbligatoria, nessun crash, nessun rallentamento percepibile (timeout breve
#   sul solo controllo di disponibilita').
# - Questo modulo non installa, scarica o configura Ollama: si limita a
#   verificarne la presenza. L'installazione resta una scelta esplicita
#   dell'utente, fatta al di fuori di questo strumento.

$Global:DVOllamaBaseUrl = "http://127.0.0.1:11434"

function Test-DVOllamaAvailable {
    <#
    .SYNOPSIS
        Verifica se Ollama e' in esecuzione in locale (loopback), con timeout breve.
    .OUTPUTS
        Hashtable: Available (bool), Models (array di nomi modello se disponibili).
    #>
    param([int]$TimeoutSec = 2)

    $result = @{ Available = $false; Models = @() }
    try {
        $resp = Invoke-RestMethod -Uri "$Global:DVOllamaBaseUrl/api/tags" -Method Get -TimeoutSec $TimeoutSec -ErrorAction Stop
        $result.Available = $true
        if ($resp.models) {
            $result.Models = @($resp.models | ForEach-Object { $_.name })
        }
    } catch {
        $result.Available = $false
    }
    return $result
}

function Select-DVOllamaModel {
    <#
    .SYNOPSIS
        Sceglie un modello ragionevole tra quelli disponibili localmente,
        preferendo modelli piccoli/veloci se presenti.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$AvailableModels)

    if (-not $AvailableModels -or $AvailableModels.Count -eq 0) { return $null }

    $preferred = @("llama3.2", "llama3.1", "phi3", "mistral", "gemma2", "qwen2.5")
    foreach ($pref in $preferred) {
        $match = $AvailableModels | Where-Object { $_ -like "$pref*" } | Select-Object -First 1
        if ($match) { return $match }
    }
    return $AvailableModels[0]
}

function Get-DVOllamaExplanation {
    <#
    .SYNOPSIS
        Genera una spiegazione in linguaggio naturale dei findings, usando un
        modello Ollama in esecuzione in locale. Non solleva mai eccezioni verso
        il chiamante: in caso di qualunque problema restituisce $null.
    .PARAMETER Findings
        Elenco testuale dei riscontri della scansione (gia' raccolti in locale).
    .PARAMETER Score
        Punteggio di rischio numerico.
    .PARAMETER LevelText
        Livello testuale (SICURO/BASSO/MEDIO/ALTO/CRITICO).
    .PARAMETER Model
        Nome del modello Ollama da usare. Se omesso, viene scelto automaticamente
        tra quelli gia' scaricati in locale.
    .PARAMETER TimeoutSec
        Timeout della chiamata di generazione (puo' richiedere piu' tempo delle
        chiamate di solo controllo disponibilita', specie su hardware modesto).
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Findings,
        [Parameter(Mandatory)][int]$Score,
        [Parameter(Mandatory)][string]$LevelText,
        [string]$Model = "",
        [int]$TimeoutSec = 45
    )

    $availability = Test-DVOllamaAvailable
    if (-not $availability.Available) { return $null }

    if ([string]::IsNullOrWhiteSpace($Model)) {
        $Model = Select-DVOllamaModel -AvailableModels $availability.Models
    }
    if ([string]::IsNullOrWhiteSpace($Model)) { return $null }

    $findingsList = if ($Findings -and $Findings.Count -gt 0) {
        ($Findings | ForEach-Object { "- $_" }) -join "`n"
    } else {
        "- Nessun elemento sospetto rilevato."
    }

    $prompt = @"
Sei un assistente che riassume in italiano semplice, per un lavoratore o un funzionario pubblico SENZA competenze tecniche, il risultato di una scansione di sicurezza del proprio PC.

Punteggio di rischio: $Score ($LevelText)
Riscontri tecnici rilevati:
$findingsList

Scrivi una spiegazione di massimo 8 righe che:
1. riassume in modo semplice e concreto cosa e' stato trovato, senza gergo tecnico non spiegato;
2. NON afferma con certezza che ci sia un illecito o una violazione: usa un linguaggio prudente ("potrebbe indicare", "andrebbe verificato");
3. NON fornisce consulenza legale e NON sostituisce una perizia forense o il parere di un avvocato;
4. suggerisce, se il punteggio e' medio o alto, di conservare il report e contattare il DPO o un professionista, senza altre istruzioni tecniche.

Rispondi solo con il testo della spiegazione, senza titoli, elenchi puntati o markdown.
"@

    $body = @{
        model  = $Model
        prompt = $prompt
        stream = $false
    } | ConvertTo-Json -Depth 5

    try {
        $resp = Invoke-RestMethod -Uri "$Global:DVOllamaBaseUrl/api/generate" -Method Post `
            -ContentType "application/json; charset=utf-8" -Body $body -TimeoutSec $TimeoutSec -ErrorAction Stop
        if ($resp.response) {
            return @{
                Text  = $resp.response.Trim()
                Model = $Model
            }
        }
        return $null
    } catch {
        return $null
    }
}

Export-ModuleMember -Function Test-DVOllamaAvailable, Select-DVOllamaModel, Get-DVOllamaExplanation
