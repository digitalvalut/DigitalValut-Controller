# DigitalValut Controller v5.0 - AuthenticodeChecker Module
# Copyright 2024-2026 Digital Valut APS - www.digitalvalut.it
# Sviluppatore: Dott. Giuseppe Falsone e il team DigitalValut
#
# Questo file e' parte di DigitalValut Controller.
# Licenza Apache, Versione 2.0 (la "Licenza"): puoi usare questo file solo nel
# rispetto della Licenza, di cui trovi copia nel file LICENSE e su
# http://www.apache.org/licenses/LICENSE-2.0
# Salvo diversa disposizione di legge o accordo scritto, il software e' distribuito
# "COSI' COM'E'", SENZA GARANZIE O CONDIZIONI DI ALCUN TIPO, esplicite o implicite.
# Avvertenze e limiti: DISCLAIMER.md
# SPDX-License-Identifier: Apache-2.0
#
# Verifica la firma digitale (Authenticode) degli eseguibili dei processi
# rilevati. Distinguere un TeamViewer autentico e firmato da un eseguibile
# con lo stesso nome ma non firmato (o firmato da un soggetto sconosciuto)
# e' un controllo tecnico reale, non un'euristica sul nome del processo.
#
# LIMITE DICHIARATO: l'assenza di firma non dimostra malevolenza (molto
# software legittimo, specie interno/aziendale, non e' firmato) e la presenza
# di una firma valida non dimostra legittimita' d'uso (un software firmato e
# regolarmente commerciale, es. TeamViewer, puo' comunque essere installato
# senza autorizzazione). E' un elemento a supporto, non una prova.

function Get-DVProcessSignature {
    <#
    .SYNOPSIS
        Verifica la firma Authenticode di un singolo eseguibile.
    .OUTPUTS
        Hashtable con Status (Valid/NotSigned/HashMismatch/NotTrusted/Unknown/Inaccessible),
        SignerSubject, IsMicrosoftSigned.
    #>
    param([string]$Path)

    $result = @{
        Status            = "Unknown"
        SignerSubject     = $null
        IsMicrosoftSigned = $false
    }

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)) {
        $result.Status = "Inaccessible"
        return $result
    }

    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $result.Status = $sig.Status.ToString()
        if ($sig.SignerCertificate) {
            $result.SignerSubject = $sig.SignerCertificate.Subject
            if ($result.SignerSubject -match 'O=Microsoft Corporation') {
                $result.IsMicrosoftSigned = $true
            }
        }
    } catch {
        $result.Status = "Inaccessible"
    }

    return $result
}

function Add-DVSignatureInfo {
    <#
    .SYNOPSIS
        Arricchisce un elenco di processi rilevati (con proprieta' .Path) con
        l'esito della verifica Authenticode del rispettivo eseguibile.
    .DESCRIPTION
        Modifica gli oggetti in-place aggiungendo SignatureStatus e SignerSubject,
        poi restituisce lo stesso elenco. Pensato per gli array prodotti da
        Get-DVProcessScan (RemoteControl/Spyware/EmployeeMonitor/OtherSuspicious).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Entries)

    $cache = @{}
    foreach ($entry in $Entries) {
        $path = $entry.Path
        if ([string]::IsNullOrWhiteSpace($path)) {
            $entry.SignatureStatus = "Inaccessible"
            $entry.SignerSubject   = $null
            continue
        }
        if (-not $cache.ContainsKey($path)) {
            $cache[$path] = Get-DVProcessSignature -Path $path
        }
        $info = $cache[$path]
        $entry.SignatureStatus = $info.Status
        $entry.SignerSubject   = $info.SignerSubject
    }

    return $Entries
}

Export-ModuleMember -Function Get-DVProcessSignature, Add-DVSignatureInfo
