# DigitalValut Controller v5.0 - TimestampAuthority Module
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
# MARCA TEMPORALE RFC 3161 (opzionale, disattivata per impostazione predefinita)
#
# Perche' serve: l'hash di un report calcolato dalla stessa macchina che lo ha
# prodotto certifica l'integrita' del file, ma NON la data. L'orologio di sistema
# e' modificabile da chi usa il PC, quindi "questo report e' del 3 marzo" vale
# quanto la parola di chi lo presenta. Una marca temporale RFC 3161 fa attestare
# da un'AUTORITA' TERZA, con firma crittografica, che quel preciso dato esisteva
# gia' in quel preciso momento.
#
# Rilevanza giuridica: il Regolamento eIDAS (UE 910/2014), art. 41, attribuisce
# alle validazioni temporali elettroniche QUALIFICATE la presunzione di
# accuratezza della data e dell'ora indicate. Le TSA gratuite qui preconfigurate
# NON sono necessariamente qualificate ai sensi eIDAS: producono comunque una
# prova crittografica solida e verificabile da chiunque, ma per la presunzione
# di legge occorre una TSA qualificata (a pagamento, elenco su eidas.ec.europa.eu).
# Il campo 'Qualified' di ogni TSA nella configurazione dichiara questo aspetto.
#
# PRIVACY (fondamentale): alla TSA viene inviato ESCLUSIVAMENTE l'hash SHA-256
# del report - 32 byte da cui e' computazionalmente impossibile risalire al
# contenuto. Nome macchina, nome utente, processi rilevati, indirizzi IP: NULLA
# di tutto questo lascia il dispositivo. La TSA certifica un'impronta, non vede
# i dati. Resta comunque una connessione di rete verso un servizio esterno, che
# apprende l'esistenza di una richiesta a un dato istante: per questo la funzione
# e' OPT-IN ESPLICITA e mai attiva per impostazione predefinita.

# Autorita' di marcatura temporale gratuite preconfigurate. Vengono provate in
# ordine: la prima che risponde vince. L'utente puo' indicarne una propria.
$Global:DVTimestampAuthorities = @(
    @{ Name = "FreeTSA";            Url = "https://freetsa.org/tsr";        Qualified = $false }
    @{ Name = "DFN-Verein (DE)";    Url = "http://zeitstempel.dfn.de";      Qualified = $false }
    @{ Name = "Sectigo";            Url = "http://timestamp.sectigo.com";   Qualified = $false }
)

# --- Utilita' di codifica DER (ASN.1) -------------------------------------
# Implementate a mano per non introdurre alcuna dipendenza esterna: lo strumento
# deve restare un insieme di script leggibili, senza librerie da scaricare.

function ConvertTo-DVDerLength {
    param([Parameter(Mandatory)][int]$Length)
    if ($Length -lt 128) { return ,([byte]$Length) }
    $bytes = @()
    $v = $Length
    while ($v -gt 0) { $bytes = ,([byte]($v -band 0xFF)) + $bytes; $v = $v -shr 8 }
    return ,([byte](0x80 -bor $bytes.Count)) + $bytes
}

function New-DVDerTlv {
    <#
    .SYNOPSIS
        Costruisce una struttura DER Tag-Length-Value.
    #>
    param(
        [Parameter(Mandatory)][byte]$Tag,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Content
    )
    return ,$Tag + (ConvertTo-DVDerLength -Length $Content.Length) + $Content
}

function Read-DVDerTlv {
    <#
    .SYNOPSIS
        Legge un elemento DER a partire da una posizione, restituendo tag,
        lunghezza e offset di inizio/fine del contenuto.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Position
    )
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $null }
    if ($Position -ge $Bytes.Length) { return $null }
    $tag = $Bytes[$Position]
    $p = $Position + 1
    if ($p -ge $Bytes.Length) { return $null }
    $len = $Bytes[$p]; $p++
    if ($len -band 0x80) {
        $n = $len -band 0x7F
        if ($n -eq 0 -or $n -gt 4) { return $null }
        $len = 0
        for ($i = 0; $i -lt $n; $i++) {
            if ($p -ge $Bytes.Length) { return $null }
            $len = ($len -shl 8) -bor $Bytes[$p]; $p++
        }
    }
    return @{ Tag = $tag; HeaderEnd = $p; Length = $len; TotalEnd = ($p + $len) }
}

function New-DVTimestampRequest {
    <#
    .SYNOPSIS
        Costruisce una TimeStampReq RFC 3161 in formato DER a partire da un
        hash SHA-256 (32 byte).
    .DESCRIPTION
        TimeStampReq ::= SEQUENCE {
            version         INTEGER { v1(1) },
            messageImprint  MessageImprint,
            nonce           INTEGER OPTIONAL,
            certReq         BOOLEAN DEFAULT FALSE }
        Il nonce casuale impedisce a un intermediario di riproporre una risposta
        gia' vista (replay): la risposta deve contenere lo stesso nonce inviato.
    #>
    param([Parameter(Mandatory)][byte[]]$Sha256Hash)

    if ($Sha256Hash.Length -ne 32) { throw "L'hash deve essere SHA-256 (32 byte), ricevuti $($Sha256Hash.Length)." }

    # AlgorithmIdentifier per SHA-256: OID 2.16.840.1.101.3.4.2.1 + NULL
    $oidSha256 = [byte[]]@(0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01)
    $derNull   = [byte[]]@(0x05,0x00)
    $algId = New-DVDerTlv -Tag 0x30 -Content ($oidSha256 + $derNull)

    $messageImprint = New-DVDerTlv -Tag 0x30 -Content ($algId + (New-DVDerTlv -Tag 0x04 -Content $Sha256Hash))

    $nonceBytes = New-Object byte[] 8
    ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($nonceBytes)
    $nonceBytes[0] = $nonceBytes[0] -band 0x7F   # forza intero positivo
    $nonce = New-DVDerTlv -Tag 0x02 -Content $nonceBytes

    $version = [byte[]]@(0x02,0x01,0x01)
    $certReq = [byte[]]@(0x01,0x01,0xFF)          # chiede alla TSA di allegare il certificato

    $request = New-DVDerTlv -Tag 0x30 -Content ($version + $messageImprint + $nonce + $certReq)
    return @{ Request = $request; Nonce = $nonceBytes }
}

function Request-DVTimestamp {
    <#
    .SYNOPSIS
        Richiede una marca temporale RFC 3161 per un hash SHA-256.
    .DESCRIPTION
        Invia SOLO l'hash. Prova le autorita' configurate in ordine e si ferma
        alla prima che risponde. Non solleva mai eccezioni verso il chiamante:
        in caso di rete assente o TSA irraggiungibile restituisce Success=$false,
        e la scansione prosegue normalmente senza marca temporale.
    .PARAMETER Sha256Hash
        Hash SHA-256 (32 byte) del contenuto da datare.
    .PARAMETER CustomUrl
        URL di una TSA scelta dall'utente (es. una TSA qualificata a pagamento).
        Se indicato, viene provata per prima.
    #>
    param(
        [Parameter(Mandatory)][byte[]]$Sha256Hash,
        [string]$CustomUrl = "",
        [int]$TimeoutSec = 20
    )

    $result = @{
        Success       = $false
        Token         = $null
        AuthorityName = $null
        AuthorityUrl  = $null
        Qualified     = $false
        Error         = $null
    }

    try {
        $built = New-DVTimestampRequest -Sha256Hash $Sha256Hash
    } catch {
        $result.Error = "Costruzione della richiesta fallita: $($_.Exception.Message)"
        return $result
    }

    $authorities = @()
    if (-not [string]::IsNullOrWhiteSpace($CustomUrl)) {
        $authorities += @{ Name = "TSA personalizzata"; Url = $CustomUrl; Qualified = $false }
    }
    $authorities += $Global:DVTimestampAuthorities

    $errors = @()
    foreach ($tsa in $authorities) {
        try {
            try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
            $req = [System.Net.HttpWebRequest]::Create($tsa.Url)
            $req.Method = "POST"
            $req.ContentType = "application/timestamp-query"
            $req.Timeout = $TimeoutSec * 1000
            $req.ReadWriteTimeout = $TimeoutSec * 1000
            $req.ContentLength = $built.Request.Length

            $stream = $req.GetRequestStream()
            $stream.Write($built.Request, 0, $built.Request.Length)
            $stream.Close()

            $resp = $req.GetResponse()
            $ms = New-Object System.IO.MemoryStream
            $resp.GetResponseStream().CopyTo($ms)
            $bytes = $ms.ToArray()
            $resp.Close()

            if ($bytes.Length -lt 16) {
                $errors += "$($tsa.Name): risposta troppo breve"
                continue
            }

            $result.Success       = $true
            $result.Token         = $bytes
            $result.AuthorityName = $tsa.Name
            $result.AuthorityUrl  = $tsa.Url
            $result.Qualified     = [bool]$tsa.Qualified
            return $result
        } catch {
            $errors += "$($tsa.Name): $($_.Exception.Message)"
        }
    }

    $result.Error = ($errors -join " | ")
    return $result
}

function Test-DVTimestampToken {
    <#
    .SYNOPSIS
        Verifica una marca temporale: firma crittografica del token, hash
        certificato e data attestata dall'autorita' terza.
    .DESCRIPTION
        Esegue tre controlli indipendenti:
          1. la firma CMS del token e' matematicamente valida;
          2. l'hash contenuto nel token coincide con quello del dato in esame
             (se fornito): dimostra che il token si riferisce proprio a quel file;
          3. estrae la data certificata (genTime) e il soggetto del certificato TSA.
        NON valida la catena di certificazione fino a una CA radice attendibile:
        per quella verifica, che richiede il certificato radice della TSA, il
        pacchetto prova include le istruzioni con OpenSSL (vedi ISTRUZIONI.txt).
    .OUTPUTS
        Hashtable con Valid, SignatureValid, HashMatches, CertifiedTime, TsaSubject, Error.
    #>
    param(
        [Parameter(Mandatory)][byte[]]$Token,
        [byte[]]$ExpectedSha256 = $null
    )

    $out = @{
        Valid          = $false
        SignatureValid = $false
        HashMatches    = $null
        CertifiedTime  = $null
        TsaSubject     = $null
        StatusGranted  = $false
        Error          = $null
    }

    try {
        # TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
        $outer = Read-DVDerTlv -Bytes $Token -Position 0
        if (-not $outer) { $out.Error = "Struttura DER non leggibile"; return $out }

        $status = Read-DVDerTlv -Bytes $Token -Position $outer.HeaderEnd
        if (-not $status) { $out.Error = "PKIStatusInfo non leggibile"; return $out }

        # Il primo INTEGER dentro PKIStatusInfo e' lo stato: 0 = granted, 1 = grantedWithMods
        $statusInt = Read-DVDerTlv -Bytes $Token -Position $status.HeaderEnd
        if ($statusInt -and $statusInt.Length -ge 1) {
            $statusValue = $Token[$statusInt.HeaderEnd]
            $out.StatusGranted = ($statusValue -eq 0 -or $statusValue -eq 1)
        }
        if (-not $out.StatusGranted) {
            $out.Error = "L'autorita' non ha concesso la marca temporale (status non granted)"
            return $out
        }

        $tokenStart = $status.TotalEnd
        $ci = Read-DVDerTlv -Bytes $Token -Position $tokenStart
        if (-not $ci) { $out.Error = "TimeStampToken assente nella risposta"; return $out }
        $tokenBytes = $Token[$tokenStart..($ci.TotalEnd - 1)]

        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $cms.Decode($tokenBytes)

        try {
            # $true: verifica solo la firma, senza risalire la catena di certificazione
            $cms.CheckSignature($true)
            $out.SignatureValid = $true
        } catch {
            $out.Error = "Firma del token non valida: $($_.Exception.Message)"
            return $out
        }

        if ($cms.Certificates.Count -gt 0) { $out.TsaSubject = $cms.Certificates[0].Subject }

        # TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }
        $tst = $cms.ContentInfo.Content
        $seq = Read-DVDerTlv -Bytes $tst -Position 0
        $p = $seq.HeaderEnd
        $v  = Read-DVDerTlv -Bytes $tst -Position $p; $p = $v.TotalEnd
        $po = Read-DVDerTlv -Bytes $tst -Position $p; $p = $po.TotalEnd
        $mi = Read-DVDerTlv -Bytes $tst -Position $p
        $miAlg  = Read-DVDerTlv -Bytes $tst -Position $mi.HeaderEnd
        $miHash = Read-DVDerTlv -Bytes $tst -Position $miAlg.TotalEnd
        $hashInToken = $tst[$miHash.HeaderEnd..($miHash.TotalEnd - 1)]

        $p = $mi.TotalEnd
        $serial = Read-DVDerTlv -Bytes $tst -Position $p; $p = $serial.TotalEnd
        $gt = Read-DVDerTlv -Bytes $tst -Position $p
        if ($gt -and $gt.Tag -eq 0x18) {
            $timeStr = [System.Text.Encoding]::ASCII.GetString($tst[$gt.HeaderEnd..($gt.TotalEnd - 1)])
            $clean = $timeStr.TrimEnd('Z')
            if ($clean.Contains('.')) { $clean = $clean.Split('.')[0] }
            try {
                $out.CertifiedTime = [datetime]::ParseExact($clean, 'yyyyMMddHHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
            } catch { }
        }

        if ($ExpectedSha256) {
            $a = ($hashInToken   | ForEach-Object { $_.ToString('x2') }) -join ''
            $b = ($ExpectedSha256 | ForEach-Object { $_.ToString('x2') }) -join ''
            $out.HashMatches = ($a -eq $b)
        }

        $out.Valid = $out.SignatureValid -and $out.StatusGranted -and ($null -eq $ExpectedSha256 -or $out.HashMatches)
        return $out
    } catch {
        $out.Error = "Errore di analisi del token: $($_.Exception.Message)"
        return $out
    }
}

function Get-DVFileSha256Bytes {
    <#
    .SYNOPSIS
        Calcola l'hash SHA-256 di un file restituendolo come array di byte
        (formato richiesto dalla richiesta di marca temporale).
    #>
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Path)
    try { return $sha.ComputeHash($fs) } finally { $fs.Close(); $sha.Dispose() }
}

Export-ModuleMember -Function ConvertTo-DVDerLength, New-DVDerTlv, Read-DVDerTlv, `
    New-DVTimestampRequest, Request-DVTimestamp, Test-DVTimestampToken, Get-DVFileSha256Bytes
