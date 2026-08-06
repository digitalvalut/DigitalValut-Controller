# DigitalValut Controller v4.1 - AuthenticodeChecker Module
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
