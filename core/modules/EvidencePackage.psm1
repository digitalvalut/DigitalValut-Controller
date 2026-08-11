# DigitalValut Controller v5.0 - EvidencePackage Module
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
# PACCHETTO PROVA SIGILLATO
#
# Problema che risolve: finora la verifica dell'integrita' la faceva lo stesso
# programma che aveva creato i file. E' un cerchio che si chiude su se' stesso e
# in contraddittorio non regge: "il tuo programma dice che il tuo file e' buono".
#
# Il pacchetto prova rompe quel cerchio:
#   1. raccoglie TUTTO in un unico file .zip da consegnare a un avvocato;
#   2. include un MANIFESTO con l'hash SHA-256 di ogni singolo file;
#   3. fa datare l'hash del manifesto da un'AUTORITA' TERZA (RFC 3161);
#   4. include un VERIFICATORE AUTONOMO che chiunque puo' eseguire - il legale
#      della controparte, il consulente tecnico d'ufficio, il giudice - senza
#      dover installare o fidarsi di DigitalValut Controller.
#
# Il risultato non e' una perizia forense (quella la redige un perito iscritto
# all'albo, sempre), ma documentazione tecnica datata da terzi e verificabile in
# modo indipendente: il materiale su cui un perito puo' lavorare.

function Get-DVPackageManifest {
    <#
    .SYNOPSIS
        Costruisce il manifesto: elenco dei file con hash SHA-256 di ciascuno,
        piu' l'hash complessivo del manifesto stesso.
    .DESCRIPTION
        L'hash del manifesto e' il valore che viene sottoposto a marca temporale:
        essendo calcolato sugli hash di tutti i file, datare quello equivale a
        datare l'intero contenuto del pacchetto.
    #>
    param(
        [Parameter(Mandatory)][string]$SourceDir,
        [string[]]$ExcludePatterns = @()
    )

    $files = @(Get-ChildItem -Path $SourceDir -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
    $entries = @()

    foreach ($f in $files) {
        $relative = $f.FullName.Substring($SourceDir.Length).TrimStart('\', '/')
        $skip = $false
        foreach ($pattern in $ExcludePatterns) {
            if ($relative -like $pattern) { $skip = $true; break }
        }
        if ($skip) { continue }

        $hash = $null
        try { $hash = (Get-FileHash -Algorithm SHA256 -Path $f.FullName -ErrorAction Stop).Hash.ToLower() } catch { }
        $entries += [ordered]@{
            File   = $relative
            Bytes  = $f.Length
            SHA256 = $hash
        }
    }

    $manifest = [ordered]@{
        FormatoManifesto = "DigitalValut-EvidencePackage/1"
        Generato         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        GeneratoUtc      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss'Z'")
        Computer         = $env:COMPUTERNAME
        Utente           = $env:USERNAME
        VersioneStrumento = if ($Global:DVConfig) { $Global:DVConfig.Version } else { "n/d" }
        NumeroFile       = @($entries).Count
        File             = $entries
    }

    # L'hash del manifesto si calcola sul JSON dei soli contenuti, in modo che sia
    # riproducibile: chi verifica ricostruisce lo stesso JSON e lo confronta.
    $manifestJson = ($manifest | ConvertTo-Json -Depth 6)
    $manifestHash = Get-DVContentHash -Content $manifestJson

    return @{ Manifest = $manifest; Json = $manifestJson; Hash = $manifestHash }
}

function New-DVEvidencePackage {
    <#
    .SYNOPSIS
        Crea il pacchetto prova sigillato: un unico .zip con report, dati grezzi,
        catena di custodia, registro Sentinella, manifesto, marca temporale e
        verificatore autonomo.
    .PARAMETER ReportDir
        Cartella contenente report e materiale da sigillare.
    .PARAMETER RequestTimestamp
        Se attivo, richiede la marca temporale RFC 3161 a un'autorita' terza.
        Invia SOLO l'hash del manifesto, mai i dati. Richiede connessione.
    .PARAMETER ControllerRoot
        Radice del progetto, da cui copiare il verificatore autonomo.
    #>
    param(
        [Parameter(Mandatory)][string]$ReportDir,
        [switch]$RequestTimestamp,
        [string]$ControllerRoot = "",
        [string]$CustomTsaUrl = ""
    )

    $result = @{
        Success        = $false
        PackagePath    = $null
        ManifestHash   = $null
        Timestamped    = $false
        CertifiedTime  = $null
        TsaName        = $null
        TimestampError = $null
        FileCount      = 0
        Error          = $null
    }

    if (-not (Test-Path $ReportDir)) { $result.Error = "Cartella non trovata: $ReportDir"; return $result }

    $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $safeName = $env:COMPUTERNAME -replace '[^\w\-]', '_'
    $stagingDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dv_prova_" + [guid]::NewGuid().ToString("N"))

    try {
        New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

        # 1. Copia il materiale, escludendo eventuali pacchetti gia' creati
        $contentDir = Join-Path $stagingDir "contenuto"
        New-Item -ItemType Directory -Path $contentDir -Force | Out-Null
        Get-ChildItem -Path $ReportDir -Exclude "PACCHETTO_PROVA_*.zip" -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $contentDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        # 2. Manifesto con hash di ogni file
        $mf = Get-DVPackageManifest -SourceDir $contentDir
        $result.ManifestHash = $mf.Hash
        $result.FileCount = $mf.Manifest.NumeroFile
        [System.IO.File]::WriteAllText((Join-Path $stagingDir "MANIFESTO.json"), $mf.Json, (New-Object System.Text.UTF8Encoding($false)))

        # 3. Marca temporale dell'hash del manifesto (opzionale, solo hash in uscita)
        if ($RequestTimestamp) {
            if (Get-Command Request-DVTimestamp -ErrorAction SilentlyContinue) {
                $hashBytes = New-Object byte[] 32
                for ($i = 0; $i -lt 32; $i++) { $hashBytes[$i] = [Convert]::ToByte($mf.Hash.Substring($i*2, 2), 16) }

                $ts = Request-DVTimestamp -Sha256Hash $hashBytes -CustomUrl $CustomTsaUrl
                if ($ts.Success) {
                    [System.IO.File]::WriteAllBytes((Join-Path $stagingDir "MARCA_TEMPORALE.tsr"), $ts.Token)
                    $verify = Test-DVTimestampToken -Token $ts.Token -ExpectedSha256 $hashBytes
                    $result.Timestamped   = $true
                    $result.CertifiedTime = $verify.CertifiedTime
                    $result.TsaName       = $ts.AuthorityName

                    $tsInfo = [ordered]@{
                        Autorita           = $ts.AuthorityName
                        Url                = $ts.AuthorityUrl
                        QualificataEidas   = $ts.Qualified
                        HashCertificato    = $mf.Hash
                        DataCertificataUtc = if ($verify.CertifiedTime) { $verify.CertifiedTime.ToString("yyyy-MM-dd HH:mm:ss'Z'") } else { $null }
                        CertificatoTsa     = $verify.TsaSubject
                        FirmaValida        = $verify.SignatureValid
                    }
                    [System.IO.File]::WriteAllText((Join-Path $stagingDir "MARCA_TEMPORALE.json"),
                        ($tsInfo | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
                } else {
                    $result.TimestampError = $ts.Error
                }
            } else {
                $result.TimestampError = "Modulo di marcatura temporale non disponibile."
            }
        }

        # 4. Verificatore autonomo, eseguibile da chiunque
        if ($ControllerRoot) {
            $verifier = Join-Path $ControllerRoot "VERIFICA_PROVA.ps1"
            if (Test-Path $verifier) { Copy-Item $verifier -Destination $stagingDir -Force }
            $verifierBat = Join-Path $ControllerRoot "VERIFICA_PROVA.bat"
            if (Test-Path $verifierBat) { Copy-Item $verifierBat -Destination $stagingDir -Force }
        }

        # 5. Istruzioni per il destinatario (avvocato, perito, controparte)
        $istruzioni = New-DVPackageInstructions -ManifestHash $mf.Hash -Timestamped $result.Timestamped `
            -TsaName $result.TsaName -CertifiedTime $result.CertifiedTime
        [System.IO.File]::WriteAllText((Join-Path $stagingDir "LEGGIMI_PRIMA.txt"), $istruzioni, (New-Object System.Text.UTF8Encoding($false)))

        # 6. Sigillo finale
        $packagePath = Join-Path $ReportDir "PACCHETTO_PROVA_${safeName}_${stamp}.zip"
        if (Test-Path $packagePath) { Remove-Item $packagePath -Force }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($stagingDir, $packagePath)

        $result.Success = $true
        $result.PackagePath = $packagePath
        return $result
    } catch {
        $result.Error = $_.Exception.Message
        return $result
    } finally {
        if (Test-Path $stagingDir) { Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function New-DVPackageInstructions {
    <#
    .SYNOPSIS
        Genera il testo di istruzioni incluso nel pacchetto, rivolto a chi lo
        riceve (avvocato, perito, controparte) e non a chi lo ha creato.
    #>
    param(
        [Parameter(Mandatory)][string]$ManifestHash,
        [bool]$Timestamped = $false,
        [string]$TsaName = "",
        $CertifiedTime = $null
    )

    $blocco = if ($Timestamped) {
@"
MARCA TEMPORALE PRESENTE
------------------------
Autorita' di marcatura : $TsaName
Data certificata (UTC) : $(if ($CertifiedTime) { $CertifiedTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'n/d' })

Un soggetto TERZO e INDIPENDENTE ha attestato crittograficamente che il
contenuto di questo pacchetto esisteva gia' in quel preciso momento. Chi ha
generato il pacchetto NON puo' aver retrodatato il materiale.

Alla marcatrice temporale e' stato inviato ESCLUSIVAMENTE l'hash SHA-256 del
manifesto (32 byte): nessun dato di merito ha lasciato il computer analizzato.
"@
    } else {
@"
MARCA TEMPORALE ASSENTE
-----------------------
Questo pacchetto NON e' stato datato da un'autorita' terza (funzione non
attivata, oppure connessione assente al momento della creazione).

CONSEGUENZA DA VALUTARE: le date indicate provengono dall'orologio del computer
analizzato, che e' modificabile da chi lo utilizza. L'integrita' dei file resta
verificabile, ma la loro DATA non e' attestata da terzi.
"@
    }

    return @"
================================================================================
              PACCHETTO PROVA - DigitalValut Controller
              ISTRUZIONI PER CHI RICEVE QUESTO MATERIALE
================================================================================

A CHE COSA SERVE QUESTO FILE
----------------------------
Contiene il risultato di una verifica tecnica eseguita su un computer, con i
dati grezzi da cui il risultato e' stato ricavato. E' pensato per essere
consegnato a un avvocato o a un perito informatico forense.

CHE COSA NON E'
---------------
NON e' una perizia informatica forense. NON e' un'acquisizione forense ai sensi
della Legge 48/2008. NON accerta la liceita' o illiceita' di alcunche'.
E' documentazione tecnica di primo livello, prodotta da uno strumento
automatico, che un professionista puo' usare come punto di partenza.

$blocco

COME VERIFICARE CHE NULLA SIA STATO ALTERATO
--------------------------------------------
Non occorre fidarsi di chi ha generato il pacchetto, ne' installare alcunche'.

  1. Estrai questo file .zip in una cartella.
  2. Fai doppio clic su VERIFICA_PROVA.bat
     (oppure, da PowerShell: .\VERIFICA_PROVA.ps1)
  3. Leggi l'esito.

Il verificatore ricalcola l'hash SHA-256 di ogni file e lo confronta con il
MANIFESTO. Se anche un solo byte fosse stato modificato dopo la creazione, lo
segnala indicando quale file.

VERIFICA INDIPENDENTE DELLA MARCA TEMPORALE (per il tecnico)
------------------------------------------------------------
La marca temporale e' un token RFC 3161 standard, verificabile con qualunque
strumento conforme, senza usare software di DigitalValut. Con OpenSSL:

    openssl ts -reply -in MARCA_TEMPORALE.tsr -text

Per la verifica completa della catena di certificazione occorre il certificato
radice dell'autorita' indicata in MARCA_TEMPORALE.json:

    openssl ts -verify -data MANIFESTO.json -in MARCA_TEMPORALE.tsr -CAfile <radice_tsa>.pem

CONTENUTO DEL PACCHETTO
-----------------------
  MANIFESTO.json        Elenco di tutti i file con il rispettivo hash SHA-256
  MARCA_TEMPORALE.tsr   Token RFC 3161 (se richiesto)
  MARCA_TEMPORALE.json  Dati leggibili della marca temporale
  VERIFICA_PROVA.ps1    Verificatore autonomo
  contenuto\            Report, dati grezzi, catena di custodia, registro Sentinella

Hash del manifesto (SHA-256):
$ManifestHash

AVVERTENZA
----------
Lo strumento che ha prodotto questo materiale e' distribuito gratuitamente,
senza garanzie, sotto licenza GNU GPL v3.0. L'autore declina ogni
responsabilita' per l'interpretazione dei risultati e per le conseguenze di
qualsiasi azione intrapresa sulla base di essi. I riscontri possono contenere
falsi positivi e falsi negativi. Vedi il file DISCLAIMER.md incluso.

DigitalValut - www.digitalvalut.it
================================================================================
"@
}

Export-ModuleMember -Function Get-DVPackageManifest, New-DVEvidencePackage, New-DVPackageInstructions
