BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "..\core\modules\OllamaAssistant.psm1") -Force
}

Describe "Test-DVOllamaAvailable" {
    It "non lancia mai eccezioni, anche se Ollama non e' in esecuzione" {
        { Test-DVOllamaAvailable -TimeoutSec 1 } | Should -Not -Throw
    }

    It "restituisce una struttura con le chiavi Available e Models" {
        $result = Test-DVOllamaAvailable -TimeoutSec 1
        $result.Keys | Should -Contain "Available"
        $result.Keys | Should -Contain "Models"
        $result.Available | Should -BeOfType [bool]
    }
}

Describe "Select-DVOllamaModel" {
    It "restituisce `$null se non ci sono modelli disponibili" {
        Select-DVOllamaModel -AvailableModels @() | Should -BeNullOrEmpty
    }

    It "preferisce un modello della lista raccomandata se presente" {
        $result = Select-DVOllamaModel -AvailableModels @("mistral:latest", "llama3.2:3b", "custom-model")
        $result | Should -Be "llama3.2:3b"
    }

    It "ricade sul primo modello disponibile se nessuno e' tra i preferiti" {
        $result = Select-DVOllamaModel -AvailableModels @("custom-model-xyz")
        $result | Should -Be "custom-model-xyz"
    }
}

Describe "Get-DVOllamaExplanation" {
    It "restituisce `$null senza eccezioni quando Ollama non e' disponibile (nessun servizio in ascolto)" {
        Mock -ModuleName OllamaAssistant Test-DVOllamaAvailable { return @{ Available = $false; Models = @() } }
        { Get-DVOllamaExplanation -Findings @("test") -Score 50 -LevelText "MEDIO" } | Should -Not -Throw
        $result = Get-DVOllamaExplanation -Findings @("test") -Score 50 -LevelText "MEDIO"
        $result | Should -BeNullOrEmpty
    }

    It "non contatta mai alcun endpoint diverso da 127.0.0.1 (garanzia architetturale)" {
        # Verifica statica: l'URL di base del modulo deve puntare solo al loopback locale.
        (Get-Module OllamaAssistant).Invoke({ $Global:DVOllamaBaseUrl }) | Should -Match '^http://127\.0\.0\.1'
    }
}
