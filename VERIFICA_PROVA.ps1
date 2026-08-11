#Requires -Version 5.1
<#
.SYNOPSIS
    Verificatore autonomo di un pacchetto prova DigitalValut.

.DESCRIPTION
    Questo script e' DELIBERATAMENTE AUTOSUFFICIENTE: non importa alcun modulo di
    DigitalValut Controller e non dipende da nulla che non sia gia' presente in
    Windows. Puo' essere eseguito da chiunque riceva il pacchetto - l'avvocato,
    il perito di parte, il consulente tecnico d'ufficio, la controparte - senza
    installare software e senza dover riporre alcuna fiducia in chi ha generato
    il materiale.

    Esegue tre controlli indipendenti:
      1. INTEGRITA'  - ricalcola l'hash SHA-256 di ogni file e lo confronta con
                       il manifesto; segnala file modificati, mancanti o aggiunti.
      2. MANIFESTO   - verifica che il manifesto stesso non sia stato riscritto.
      3. DATA        - se presente una marca temporale RFC 3161, ne verifica la
                       firma crittografica ed estrae la data attestata da terzi.

.NOTES
    Licenza GNU GPL v3.0 - DigitalValut - www.digitalvalut.it
    Questo strumento NON esprime valutazioni sul merito: dice soltanto se il
    materiale e' integro e da quando esiste.
#>
param(
    [string]$PackageDir = ""
)

$ErrorActionPreference = "Continue"
if ([string]::IsNullOrWhiteSpace($PackageDir)) { $PackageDir = $PSScriptRoot }

function Write-Titolo($testo) {
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkGray
    Write-Host "  $testo" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkGray
}

function Get-ContentHashString([string]$Content) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLower() }
    finally { $sha.Dispose() }
}

# --- Lettore DER minimale, per la marca temporale ---
function Read-DerTlv([byte[]]$Bytes, [int]$Position) {
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $null }
    if ($Position -ge $Bytes.Length) { return $null }
    $tag = $Bytes[$Position]; $p = $Position + 1
    if ($p -ge $Bytes.Length) { return $null }
    $len = $Bytes[$p]; $p++
    if ($len -band 0x80) {
        $n = $len -band 0x7F
        if ($n -eq 0 -or $n -gt 4) { return $null }
        $len = 0
        for ($i = 0; $i -lt $n; $i++) { $len = ($len -shl 8) -bor $Bytes[$p]; $p++ }
    }
    return @{ Tag = $tag; HeaderEnd = $p; Length = $len; TotalEnd = ($p + $len) }
}

Write-Host ""
Write-Host "  VERIFICA PACCHETTO PROVA - DigitalValut Controller" -ForegroundColor White
Write-Host "  Strumento autonomo: non richiede software aggiuntivo." -ForegroundColor DarkGray
Write-Host "  Cartella esaminata: $PackageDir" -ForegroundColor DarkGray

$manifestPath = Join-Path $PackageDir "MANIFESTO.json"
$contentDir   = Join-Path $PackageDir "contenuto"

if (-not (Test-Path $manifestPath)) {
    Write-Host ""
    Write-Host "  [ERRORE] MANIFESTO.json non trovato in questa cartella." -ForegroundColor Red
    Write-Host "           Estrai prima il file .zip ed esegui lo script dalla cartella estratta."
    Write-Host ""
    exit 2
}

# ============================ 1. INTEGRITA' DEI FILE ============================
Write-Titolo "1. INTEGRITA' DEI FILE"

try {
    $manifestJson = Get-Content -Path $manifestPath -Raw -Encoding UTF8
    $manifest = $manifestJson | ConvertFrom-Json
} catch {
    Write-Host "  [ERRORE] Il manifesto non e' leggibile: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

Write-Host "  Pacchetto generato il : $($manifest.Generato) (ora del computer analizzato)"
Write-Host "  Computer analizzato   : $($manifest.Computer)"
Write-Host "  Utente                : $($manifest.Utente)"
Write-Host "  Versione strumento    : $($manifest.VersioneStrumento)"
Write-Host "  File dichiarati       : $($manifest.NumeroFile)"
Write-Host ""

$modificati = @()
$mancanti = @()
$verificati = 0

foreach ($entry in $manifest.File) {
    $full = Join-Path $contentDir $entry.File
    if (-not (Test-Path -LiteralPath $full)) {
        $mancanti += $entry.File
        continue
    }
    try {
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $full -ErrorAction Stop).Hash.ToLower()
        if ($actual -ne $entry.SHA256) { $modificati += $entry.File } else { $verificati++ }
    } catch {
        $mancanti += "$($entry.File) (non leggibile)"
    }
}

# File presenti ma non dichiarati nel manifesto (aggiunti dopo la sigillatura)
$aggiunti = @()
if (Test-Path $contentDir) {
    $dichiarati = @($manifest.File | ForEach-Object { $_.File })
    foreach ($f in @(Get-ChildItem -Path $contentDir -Recurse -File -ErrorAction SilentlyContinue)) {
        $rel = $f.FullName.Substring($contentDir.Length).TrimStart('\', '/')
        if ($dichiarati -notcontains $rel) { $aggiunti += $rel }
    }
}

Write-Host "  File verificati e integri : $verificati" -ForegroundColor Green
if ($modificati.Count -gt 0) {
    Write-Host "  File MODIFICATI           : $($modificati.Count)" -ForegroundColor Red
    $modificati | ForEach-Object { Write-Host "      - $_" -ForegroundColor Red }
}
if ($mancanti.Count -gt 0) {
    Write-Host "  File MANCANTI             : $($mancanti.Count)" -ForegroundColor Red
    $mancanti | ForEach-Object { Write-Host "      - $_" -ForegroundColor Red }
}
if ($aggiunti.Count -gt 0) {
    Write-Host "  File AGGIUNTI dopo        : $($aggiunti.Count)" -ForegroundColor Yellow
    $aggiunti | ForEach-Object { Write-Host "      - $_" -ForegroundColor Yellow }
}

$integrita = ($modificati.Count -eq 0 -and $mancanti.Count -eq 0 -and $aggiunti.Count -eq 0)

# ============================ 2. INTEGRITA' DEL MANIFESTO ============================
Write-Titolo "2. INTEGRITA' DEL MANIFESTO"

# Si ricostruisce il manifesto SENZA le proprieta' aggiunte in lettura, per
# ottenere lo stesso JSON usato al momento della firma.
$ricostruito = [ordered]@{}
foreach ($p in $manifest.PSObject.Properties) { $ricostruito[$p.Name] = $p.Value }
$manifestHashCalcolato = Get-ContentHashString -Content ($ricostruito | ConvertTo-Json -Depth 6)

Write-Host "  Hash del manifesto (ricalcolato):"
Write-Host "    $manifestHashCalcolato"

$tsJsonPath = Join-Path $PackageDir "MARCA_TEMPORALE.json"
$manifestoCoerente = $null
if (Test-Path $tsJsonPath) {
    try {
        $tsInfo = Get-Content $tsJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-Host "  Hash certificato nella marca temporale:"
        Write-Host "    $($tsInfo.HashCertificato)"
        $manifestoCoerente = ($tsInfo.HashCertificato -eq $manifestHashCalcolato)
        if ($manifestoCoerente) {
            Write-Host "  [OK] Il manifesto corrisponde a quello datato dall'autorita' terza." -ForegroundColor Green
        } else {
            Write-Host "  [ALLARME] Il manifesto NON corrisponde a quello datato: e' stato modificato." -ForegroundColor Red
        }
    } catch { }
}

# ============================ 3. MARCA TEMPORALE ============================
Write-Titolo "3. DATA CERTIFICATA DA TERZI"

$tsrPath = Join-Path $PackageDir "MARCA_TEMPORALE.tsr"
$marcaValida = $null

if (-not (Test-Path $tsrPath)) {
    Write-Host "  Nessuna marca temporale presente nel pacchetto." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Le date indicate provengono dall'orologio del computer analizzato," -ForegroundColor Yellow
    Write-Host "  che e' modificabile da chi lo utilizza. L'integrita' dei file resta" -ForegroundColor Yellow
    Write-Host "  verificabile, ma la loro DATA non e' attestata da un soggetto terzo." -ForegroundColor Yellow
} else {
    try {
        $token = [System.IO.File]::ReadAllBytes($tsrPath)
        $outer = Read-DerTlv $token 0
        $status = Read-DerTlv $token $outer.HeaderEnd
        $statusInt = Read-DerTlv $token $status.HeaderEnd
        $granted = ($token[$statusInt.HeaderEnd] -eq 0 -or $token[$statusInt.HeaderEnd] -eq 1)

        $tokenStart = $status.TotalEnd
        $ci = Read-DerTlv $token $tokenStart
        $tokenBytes = $token[$tokenStart..($ci.TotalEnd - 1)]

        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $cms.Decode($tokenBytes)

        $firmaOk = $false
        try { $cms.CheckSignature($true); $firmaOk = $true } catch { }

        $tst = $cms.ContentInfo.Content
        $seq = Read-DerTlv $tst 0
        $p = $seq.HeaderEnd
        $v = Read-DerTlv $tst $p; $p = $v.TotalEnd
        $po = Read-DerTlv $tst $p; $p = $po.TotalEnd
        $mi = Read-DerTlv $tst $p
        $miAlg = Read-DerTlv $tst $mi.HeaderEnd
        $miHash = Read-DerTlv $tst $miAlg.TotalEnd
        $hashNelToken = (($tst[$miHash.HeaderEnd..($miHash.TotalEnd - 1)]) | ForEach-Object { $_.ToString('x2') }) -join ''
        $p = $mi.TotalEnd
        $serial = Read-DerTlv $tst $p; $p = $serial.TotalEnd
        $gt = Read-DerTlv $tst $p

        $dataCert = $null
        if ($gt -and $gt.Tag -eq 0x18) {
            $s = [System.Text.Encoding]::ASCII.GetString($tst[$gt.HeaderEnd..($gt.TotalEnd - 1)]).TrimEnd('Z')
            if ($s.Contains('.')) { $s = $s.Split('.')[0] }
            try { $dataCert = [datetime]::ParseExact($s, 'yyyyMMddHHmmss', [System.Globalization.CultureInfo]::InvariantCulture) } catch { }
        }

        Write-Host "  Stato della richiesta   : $(if ($granted) { 'concessa' } else { 'NON concessa' })"
        Write-Host "  Firma crittografica     : $(if ($firmaOk) { 'VALIDA' } else { 'NON VALIDA' })" -ForegroundColor $(if ($firmaOk) { 'Green' } else { 'Red' })
        if ($cms.Certificates.Count -gt 0) {
            Write-Host "  Autorita' firmataria    : $($cms.Certificates[0].Subject)"
        }
        Write-Host "  Hash certificato        : $hashNelToken"
        Write-Host "  Corrisponde al manifesto: $(if ($hashNelToken -eq $manifestHashCalcolato) { 'SI' } else { 'NO' })" -ForegroundColor $(if ($hashNelToken -eq $manifestHashCalcolato) { 'Green' } else { 'Red' })
        if ($dataCert) {
            Write-Host ""
            Write-Host "  DATA ATTESTATA DA TERZI : $($dataCert.ToString('dd/MM/yyyy HH:mm:ss')) UTC" -ForegroundColor Green
            Write-Host "  Il contenuto di questo pacchetto esisteva gia' a quella data." -ForegroundColor Green
        }

        $marcaValida = ($granted -and $firmaOk -and ($hashNelToken -eq $manifestHashCalcolato))
    } catch {
        Write-Host "  [ERRORE] Impossibile analizzare la marca temporale: $($_.Exception.Message)" -ForegroundColor Red
        $marcaValida = $false
    }
}

# ============================ ESITO ============================
Write-Titolo "ESITO COMPLESSIVO"

$exitCode = 0
if ($integrita) {
    Write-Host "  [OK] Tutti i file corrispondono al manifesto: nessuna alterazione." -ForegroundColor Green
} else {
    Write-Host "  [ALLARME] Il contenuto NON corrisponde al manifesto (vedi sopra)." -ForegroundColor Red
    $exitCode = 1
}

if ($null -ne $marcaValida) {
    if ($marcaValida) {
        Write-Host "  [OK] Marca temporale valida: la data e' attestata da un soggetto terzo." -ForegroundColor Green
    } else {
        Write-Host "  [ALLARME] Marca temporale non valida o non corrispondente al contenuto." -ForegroundColor Red
        $exitCode = 1
    }
} else {
    Write-Host "  [i]  Marca temporale assente: la data non e' attestata da terzi." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  NOTA: questo strumento verifica soltanto INTEGRITA' e DATA del materiale." -ForegroundColor DarkGray
Write-Host "  Non esprime alcuna valutazione sul merito e non sostituisce una perizia" -ForegroundColor DarkGray
Write-Host "  informatica forense ne' un parere legale." -ForegroundColor DarkGray
Write-Host ""

exit $exitCode
