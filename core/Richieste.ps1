#Requires -Version 5.1
<#
.SYNOPSIS
    DigitalValut Controller v5.1 - Richieste di chiarimento e scadenzario

.DESCRIPTION
    Prepara il TESTO di richieste formali (DPO, RSU, Ispettorato, Garante) a partire
    dall'ultimo report, e tiene un registro con le scadenze di risposta.
    Il programma NON invia nulla: PEC o raccomandata le invii tu.
    Non e' consulenza legale: fai rivedere i testi a un legale o al tuo sindacato.

.LICENSE
    Apache License, Version 2.0 (SPDX: Apache-2.0)
    Copyright 2024-2026 Digital Valut APS - www.digitalvalut.it
    Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
    See the LICENSE and NOTICE files for details.
#>

param(
    # Mostra lo stato delle richieste e le scadenze, poi esce.
    [switch]$Stato,

    # Verifica l'integrita' del registro delle richieste, poi esce.
    [switch]$Verifica,

    # Prepara una nuova richiesta del tipo indicato senza menu.
    [ValidateSet('DPO-ISTANZA', 'DPO-SOLLECITO', 'RSU', 'INL', 'GARANTE-RECLAMO')]
    [string]$Nuova,

    # Registra un evento su una richiesta esistente (serve -Id e -Evento).
    [string]$Id,
    [ValidateSet('INVIATA', 'RISPOSTA_RICEVUTA', 'CHIUSA', 'NOTA')]
    [string]$Evento,
    [string]$Canale = '',
    [string]$Riferimento = '',
    [string]$Nota = '',
    # Data dell'evento (gg/mm/aaaa). Per INVIATA e' la data di consegna: da qui parte il termine.
    [string]$Data = ''
)

$ErrorActionPreference = 'Stop'
$controllerRoot = (Get-Item $PSScriptRoot).Parent.FullName
$reportDir = Join-Path $controllerRoot 'DigitalValut_Reports'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
$docDir = Join-Path $reportDir 'Richieste'
$ledger = $null
$profilePath = Join-Path $reportDir 'richieste_profilo.json'

Import-Module (Join-Path $PSScriptRoot 'modules\RequestManager.psm1') -Force
$ledger = Get-DVRequestLedgerPath -ReportDir $reportDir

function Read-DVValue {
    param([string]$Prompt, [string]$Default = '')
    $suffix = if ($Default) { " [$Default]" } else { '' }
    $v = Read-Host "  $Prompt$suffix"
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v.Trim()
}

function Get-DVProfile {
    $p = @{}
    if (Test-Path $profilePath) {
        try {
            $obj = Get-Content $profilePath -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($prop in $obj.PSObject.Properties) { $p[$prop.Name] = [string]$prop.Value }
        } catch { Write-Host '  [!] Profilo illeggibile: lo ricompilo.' -ForegroundColor Yellow }
    }
    return $p
}

function Update-DVProfile {
    param([hashtable]$Profile)
    Write-Host ''
    Write-Host '  I tuoi dati servono solo per compilare le lettere. Restano in questa cartella,' -ForegroundColor DarkGray
    Write-Host '  sul tuo computer (DigitalValut_Reports\richieste_profilo.json). Invio = tieni il valore.' -ForegroundColor DarkGray
    Write-Host ''
    $fields = [ordered]@{
        NOME_COGNOME       = 'Nome e cognome'
        QUALIFICA          = 'Qualifica (es. tecnico informatico)'
        STRUTTURA          = 'Struttura/ufficio'
        ENTE               = "Ente (es. ASP di ...)"
        SEDE_ENTE          = "Sede dell'Ente (indirizzo)"
        LUOGO              = 'Luogo (per la data della lettera)'
        RECAPITO           = 'Tuo recapito per le risposte (PEC o email)'
        DESTINATARIO_NOME  = 'Nome del DPO (o ufficio destinatario)'
        DESTINATARIO_PEC   = 'PEC del destinatario'
    }
    foreach ($k in $fields.Keys) {
        $cur = if ($Profile.ContainsKey($k)) { $Profile[$k] } else { '' }
        $Profile[$k] = Read-DVValue -Prompt $fields[$k] -Default $cur
    }
    $Profile['DESTINATARIO_NOME_DPO'] = $Profile['DESTINATARIO_NOME']
    $Profile['PEC_DPO'] = $Profile['DESTINATARIO_PEC']
    $Profile | ConvertTo-Json | Set-Content -Path $profilePath -Encoding UTF8
    return $Profile
}

function Show-DVStatus {
    $events = @(Get-DVRequestEvents -LedgerPath $ledger)
    if ($events.Count -eq 0) {
        Write-Host '  Nessuna richiesta registrata.' -ForegroundColor DarkGray
        return
    }
    $rows = @(Get-DVRequestSummary -Events $events)
    Write-Host ''
    foreach ($r in $rows) {
        $color = switch ($r.Stato) { 'SCADUTA' { 'Red' } 'INVIATA' { 'Yellow' } 'RISPOSTA_RICEVUTA' { 'Cyan' } 'CHIUSA' { 'DarkGray' } default { 'White' } }
        Write-Host ("  {0}  {1,-16} {2,-18} scadenza: {3}" -f $r.Id, $r.Tipo, $r.Stato, $(if ($r.Scadenza) { $r.Scadenza } else { '-' })) -ForegroundColor $color
        Write-Host ("      -> {0}" -f $r.ProssimoPasso) -ForegroundColor $color
    }
    Write-Host ''
}

function New-DVRequestInteractive {
    param([string]$Type)
    $typesInfo = @(Get-DVRequestTypes)
    if (-not $Type) {
        Write-Host ''
        for ($i = 0; $i -lt $typesInfo.Count; $i++) {
            Write-Host ("   [{0}] {1}" -f ($i + 1), $typesInfo[$i].Titolo)
        }
        $sel = Read-DVValue -Prompt 'Quale richiesta vuoi preparare? (numero)' -Default '1'
        $idx = 0
        if (-not [int]::TryParse($sel, [ref]$idx) -or $idx -lt 1 -or $idx -gt $typesInfo.Count) { Write-Host '  Scelta non valida.' -ForegroundColor Red; return }
        $Type = $typesInfo[$idx - 1].Tipo
    }

    $scan = Get-DVLatestScanSummary -ReportDir $reportDir
    if (-not $scan) {
        Write-Host '  [!] Nessun report di scansione trovato: lancia prima AVVIA_CONTROLLO.bat.' -ForegroundColor Yellow
        Write-Host '      Posso comunque preparare il testo, con i dati della rilevazione da compilare a mano.' -ForegroundColor Yellow
    } else {
        Write-Host ("  Uso l'ultimo report: {0} (scansione del {1})" -f $scan.ReportFileName, $scan.ScanDate) -ForegroundColor Cyan
    }

    $profile = Get-DVProfile
    $profile = Update-DVProfile -Profile $profile
    $extra = @{}
    foreach ($k in $profile.Keys) { $extra[$k] = $profile[$k] }

    if ($Type -in @('DPO-SOLLECITO', 'GARANTE-RECLAMO')) {
        $events = @(Get-DVRequestEvents -LedgerPath $ledger)
        $sentIstanza = @($events | Where-Object { $_.Event -eq 'INVIATA' -and $_.Type -eq 'DPO-ISTANZA' }) | Select-Object -Last 1
        if ($sentIstanza) {
            $dt = [datetime]::ParseExact([string]$sentIstanza.EventDate, 'yyyy-MM-dd', $null)
            $extra['DATA_INVIO_PRECEDENTE'] = $dt.ToString('dd/MM/yyyy')
            $extra['DATA_ISTANZA'] = $dt.ToString('dd/MM/yyyy')
            $extra['RIFERIMENTO_PRECEDENTE'] = [string]$sentIstanza.Reference
            $extra['RIFERIMENTO_ISTANZA'] = [string]$sentIstanza.Reference
            if ($sentIstanza.Deadline) {
                $extra['SCADENZA_PRECEDENTE'] = ([datetime]::ParseExact([string]$sentIstanza.Deadline, 'yyyy-MM-dd', $null)).ToString('dd/MM/yyyy')
            }
            Write-Host ("  Trovata la tua istanza inviata il {0}: la richiamo nel testo." -f $extra['DATA_ISTANZA']) -ForegroundColor Cyan
        } else {
            Write-Host '  [i] Non risulta nel registro un invio della DPO-ISTANZA: dovrai compilare a mano date e riferimenti.' -ForegroundColor Yellow
        }
    }
    if ($Type -eq 'INL') {
        $extra['DESTINATARIO_NOME'] = Read-DVValue -Prompt "Sede dell'Ispettorato territoriale (citta')" -Default ''
        $extra['DESTINATARIO_PEC'] = Read-DVValue -Prompt "PEC dell'Ispettorato" -Default ''
    }
    if ($Type -eq 'RSU') {
        $extra['DESTINATARIO_PEC'] = Read-DVValue -Prompt 'Recapito della RSU/OO.SS.' -Default ''
    }
    if ($Type -eq 'GARANTE-RECLAMO') {
        $extra['DESTINATARIO_PEC'] = Read-DVValue -Prompt 'PEC del Garante (verificala sul sito garanteprivacy.it)' -Default ''
    }

    $text = New-DVRequestText -Type $Type -Data $extra -Scan $scan
    if (-not (Test-Path $docDir)) { New-Item -ItemType Directory -Path $docDir -Force | Out-Null }
    $rid = New-DVRequestId
    $file = Join-Path $docDir ("{0}_{1}.txt" -f $rid, $Type)
    # UTF-8 con BOM: Blocco note mostra correttamente le lettere accentate.
    [System.IO.File]::WriteAllText($file, $text, (New-Object System.Text.UTF8Encoding($true)))
    $hash = (Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLower()
    Add-DVRequestEvent -LedgerPath $ledger -Id $rid -Event PREPARATA -Type $Type `
        -Recipient ([string]$extra['DESTINATARIO_NOME']) -DocumentFile (Split-Path -Leaf $file) -DocumentHash $hash | Out-Null

    $open = Get-DVRequestOpenPoints -Text $text
    Write-Host ''
    Write-Host "  [OK] Testo preparato: $file" -ForegroundColor Green
    if ($open -gt 0) { Write-Host "  [!] Nel testo restano $open punti da completare o scegliere (cerca [DA COMPILARE], [SCEGLIERE], [INDICARE], ____)." -ForegroundColor Yellow }
    Write-Host "  [OK] Registrata come $rid (impronta documento: $hash)" -ForegroundColor Green
    Write-Host ''
    Write-Host '  PRIMA DI INVIARE:' -ForegroundColor Yellow
    Write-Host '   1. Apri il file, cerca [DA COMPILARE ...] e completa/cancella ogni punto.' -ForegroundColor Yellow
    Write-Host '   2. Fai rivedere il testo a un avvocato giuslavorista o al tuo sindacato.' -ForegroundColor Yellow
    Write-Host '   3. Invialo TU (PEC o raccomandata): il programma non invia nulla.' -ForegroundColor Yellow
    Write-Host '   4. Poi registra l''invio con la data di consegna: da li parte la scadenza.' -ForegroundColor Yellow
    try { Start-Process notepad.exe -ArgumentList "`"$file`"" } catch { Write-Verbose 'Blocco note non avviabile' }
}

function Register-DVEventInteractive {
    param([string]$RequestId, [string]$Ev, [string]$Chan, [string]$Ref, [string]$Note, [string]$DateText)

    $events = @(Get-DVRequestEvents -LedgerPath $ledger)
    if ($events.Count -eq 0) { Write-Host '  Nessuna richiesta registrata.' -ForegroundColor Yellow; return }
    if (-not $RequestId) {
        Show-DVStatus
        $RequestId = Read-DVValue -Prompt 'Id della richiesta (es. RQ-20261013-101500)'
    }
    $mine = @($events | Where-Object { $_.Id -eq $RequestId })
    if ($mine.Count -eq 0) { Write-Host "  Id non trovato: $RequestId" -ForegroundColor Red; return }
    if (-not $Ev) {
        Write-Host '   [1] INVIATA  [2] RISPOSTA_RICEVUTA  [3] CHIUSA  [4] NOTA'
        $n = Read-DVValue -Prompt 'Evento (numero)' -Default '1'
        $Ev = @('INVIATA', 'RISPOSTA_RICEVUTA', 'CHIUSA', 'NOTA')[[math]::Max(0, [math]::Min(3, ([int]$n) - 1))]
    }
    if (-not $DateText) { $DateText = Read-DVValue -Prompt 'Data dell''evento (gg/mm/aaaa; per INVIATA = data di consegna PEC/raccomandata)' -Default (Get-Date).ToString('dd/MM/yyyy') }
    $dt = [datetime]::MinValue
    if (-not [datetime]::TryParseExact($DateText, 'dd/MM/yyyy', $null, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
        Write-Host '  Data non valida: usa gg/mm/aaaa.' -ForegroundColor Red; return
    }
    if (-not $Chan -and $Ev -eq 'INVIATA') { $Chan = Read-DVValue -Prompt 'Canale (PEC, raccomandata, a mano)' -Default 'PEC' }
    if (-not $Ref -and $Ev -in @('INVIATA', 'RISPOSTA_RICEVUTA')) { $Ref = Read-DVValue -Prompt 'Riferimento (protocollo, ricevuta PEC, numero raccomandata)' -Default '' }
    if (-not $Note -and $Ev -eq 'NOTA') { $Note = Read-DVValue -Prompt 'Nota' -Default '' }

    $rec = Add-DVRequestEvent -LedgerPath $ledger -Id $RequestId -Event $Ev -Type ([string]$mine[0].Type) `
        -EventDate $dt -Recipient ([string]($mine | Where-Object { $_.Recipient } | Select-Object -Last 1).Recipient) `
        -Channel $Chan -Reference $Ref -Note $Note
    Write-Host ''
    Write-Host "  [OK] Registrato: $Ev del $($dt.ToString('dd/MM/yyyy'))" -ForegroundColor Green
    if ($rec.Deadline) {
        Write-Host ("  [OK] Scadenza di risposta: {0}" -f ([datetime]::ParseExact($rec.Deadline, 'yyyy-MM-dd', $null)).ToString('dd/MM/yyyy')) -ForegroundColor Green
    }
    Write-Host '  Conserva la ricevuta di consegna PEC: e'' la tua prova della data.' -ForegroundColor Yellow
}

# === ESECUZIONE ===
if ($Verifica) {
    $r = Test-DVRequestChain -LedgerPath $ledger
    Write-Host ''
    if ($r.Valid) { Write-Host "  [OK] $($r.Message)" -ForegroundColor Green } else { Write-Host "  [ALLARME] $($r.Message)" -ForegroundColor Red }
    Write-Host "  Registro: $ledger"
    exit $(if ($r.Valid) { 0 } else { 1 })
}
if ($Stato) { Show-DVStatus; exit 0 }
if ($Nuova) { New-DVRequestInteractive -Type $Nuova; exit 0 }
if ($Id -and $Evento) { Register-DVEventInteractive -RequestId $Id -Ev $Evento -Chan $Canale -Ref $Riferimento -Note $Nota -DateText $Data; exit 0 }

# Menu
Write-Host ''
Write-Host '  DIGITALVALUT - RICHIESTE DI CHIARIMENTO E SCADENZARIO' -ForegroundColor Cyan
Write-Host '  Prepara lettere formali e tiene il conto delle scadenze. NON invia nulla.' -ForegroundColor DarkGray
Show-DVStatus
while ($true) {
    Write-Host '   [1] Prepara una nuova richiesta'
    Write-Host '   [2] Registra invio / risposta / chiusura'
    Write-Host '   [3] Stato richieste e scadenze'
    Write-Host '   [4] Verifica integrita'' del registro'
    Write-Host '   [5] Esci'
    $c = Read-DVValue -Prompt 'Scelta' -Default '5'
    switch ($c) {
        '1' { New-DVRequestInteractive -Type '' }
        '2' { Register-DVEventInteractive -RequestId '' -Ev '' -Chan '' -Ref '' -Note '' -DateText '' }
        '3' { Show-DVStatus }
        '4' { $r = Test-DVRequestChain -LedgerPath $ledger; Write-Host ("  " + $r.Message) -ForegroundColor $(if ($r.Valid) { 'Green' } else { 'Red' }) }
        '5' { exit 0 }
        default { Write-Host '  Scelta non valida.' -ForegroundColor Red }
    }
    Write-Host ''
}
