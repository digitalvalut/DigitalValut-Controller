# DigitalValut Controller v5.1 - RequestManager Module
# Richieste formali di chiarimento (DPO, sindacato, Ispettorato, Garante) e scadenzario.
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
# COSA FA
#   1. Genera il TESTO di richieste formali (mai inviate dal programma) a partire
#      dall'ultimo report di scansione.
#   2. Tiene un registro a catena di hash (tamper-evident) di cosa e' stato
#      preparato, inviato, risposto, con la scadenza di risposta calcolata.
#   3. Dice quali richieste sono scadute e qual e' il passo successivo ragionevole.
#
# COSA NON FA (scelta di progetto)
#   - NON invia nulla in rete: PEC, raccomandata o consegna a mano le fai TU.
#     Cosi' resta vera la promessa "il programma non trasmette dati".
#   - NON accusa nessuno: i modelli sono formulati come richieste di chiarimento.
#   - NON e' consulenza legale. I modelli vanno fatti rivedere da un avvocato
#     giuslavorista o dal tuo sindacato prima dell'uso, soprattutto la
#     competenza degli enti (es. Ispettorato del lavoro per il pubblico impiego).
#
# RIFERIMENTI NORMATIVI USATI NEI MODELLI (verificare sempre il testo vigente)
#   - Reg. UE 2016/679 (GDPR): artt. 5, 12 (par. 3: riscontro entro un mese,
#     prorogabile di due mesi in casi complessi con comunicazione motivata),
#     13, 15, 35, 77.
#   - D.Lgs. 196/2003 (Codice privacy): art. 114 (richiamo all'art. 4 L. 300/1970),
#     artt. 140-bis e 142 (reclamo al Garante).
#   - L. 300/1970 art. 4 (strumenti di controllo a distanza).

$script:RequestTypes = [ordered]@{
    'DPO-ISTANZA'    = @{ Titolo = 'Richiesta di informazioni e accesso al DPO (artt. 12, 13, 15 GDPR; art. 4 L. 300/1970)'; Destinatario = 'DPO dell''Ente'; Mesi = 1; Giorni = 0 }
    'DPO-SOLLECITO'  = @{ Titolo = 'Sollecito di riscontro al DPO'; Destinatario = 'DPO dell''Ente'; Mesi = 0; Giorni = 10 }
    'RSU'            = @{ Titolo = 'Richiesta di informazioni alla RSU / organizzazioni sindacali (art. 4 L. 300/1970)'; Destinatario = 'RSU / OO.SS.'; Mesi = 0; Giorni = 0 }
    'INL'            = @{ Titolo = 'Segnalazione e richiesta di informazioni all''Ispettorato territoriale del lavoro'; Destinatario = 'Ispettorato territoriale del lavoro'; Mesi = 0; Giorni = 0 }
    'GARANTE-RECLAMO' = @{ Titolo = 'Reclamo al Garante per la protezione dei dati personali (art. 77 GDPR)'; Destinatario = 'Garante privacy'; Mesi = 0; Giorni = 0 }
}

$script:RequestEvents = @('PREPARATA', 'INVIATA', 'RISPOSTA_RICEVUTA', 'CHIUSA', 'NOTA')

function Get-DVRequestTypes {
    <#
    .SYNOPSIS
        Elenca i tipi di richiesta disponibili con titolo, destinatario e termine di risposta.
    #>
    $out = @()
    foreach ($k in $script:RequestTypes.Keys) {
        $t = $script:RequestTypes[$k]
        $out += [PSCustomObject]@{ Tipo = $k; Titolo = $t.Titolo; Destinatario = $t.Destinatario; Mesi = $t.Mesi; Giorni = $t.Giorni }
    }
    return $out
}

function Get-DVResponseDeadline {
    <#
    .SYNOPSIS
        Calcola la data limite di risposta a partire dalla data di ricevimento.
        Funzione PURA. Per l'istanza GDPR il termine e' "un mese" di calendario
        (art. 12, par. 3), non 30 giorni.
    .NOTES
        La scadenza decorre dal RICEVIMENTO da parte dell'Ente: con la PEC e' la
        data della ricevuta di avvenuta consegna. Una proroga (art. 12, par. 3:
        fino a due mesi ulteriori) e' ammessa solo con comunicazione motivata
        entro il primo mese: se arriva, registra una NOTA e ricalcola a mano.
    #>
    param(
        [Parameter(Mandatory)][datetime]$ReceivedDate,
        [int]$Months = 0,
        [int]$Days = 0
    )
    if ($Months -le 0 -and $Days -le 0) { return $null }
    $d = $ReceivedDate.Date
    if ($Months -gt 0) { $d = $d.AddMonths($Months) }
    if ($Days -gt 0)   { $d = $d.AddDays($Days) }
    return $d
}

function ConvertTo-DVNeutralFinding {
    <#
    .SYNOPSIS
        Toglie le etichette di gravita' ("[CRITICO]", ...) da una rilevazione del report
        per riportarla in una lettera in modo descrittivo e non accusatorio.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Finding)
    if ([string]::IsNullOrWhiteSpace($Finding)) { return '' }
    return (($Finding -replace '^\s*\[[^\]]+\]\s*', '') -replace '\s+', ' ').Trim()
}

function Get-DVLatestScanSummary {
    <#
    .SYNOPSIS
        Legge l'ultimo report JSON (DV_Report_*.json) e ne ricava i dati utili per le
        lettere: nome PC, data scansione, rilevazioni in forma neutra, impronta SHA-256.
    .OUTPUTS
        PSCustomObject, oppure $null se non esiste nessun report.
    #>
    param([Parameter(Mandatory)][string]$ReportDir)

    if (-not (Test-Path $ReportDir)) { return $null }
    $jsonFile = Get-ChildItem -Path $ReportDir -Filter 'DV_Report_*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object Name | Select-Object -Last 1
    if (-not $jsonFile) { return $null }

    $data = $null
    try {
        $data = Get-Content -Path $jsonFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        return $null
    }

    $lines = New-Object System.Collections.Generic.List[string]
    if ($data.ThreatScore -and $data.ThreatScore.Findings) {
        foreach ($f in @($data.ThreatScore.Findings)) {
            $n = ConvertTo-DVNeutralFinding -Finding ([string]$f)
            if ($n -and -not $lines.Contains($n)) { $lines.Add($n) }
        }
    }
    foreach ($c in @($data.ActiveRemoteConnections)) {
        if (-not $c) { continue }
        if ($c.Rischio -and ([string]$c.Rischio).ToUpper() -eq 'BASSO') { continue }
        # RPC/NetBIOS/SMB sono servizi standard di Windows: non vanno in una lettera (anche se un report vecchio li segnalava)
        if ($c.PortaLocale -in @(135, 139, 445)) { continue }
        $n = "Porta locale $($c.PortaLocale), processo $($c.Processo): $(([string]$c.Stato) -replace ' - .*$', '')"
        if (-not $lines.Contains($n)) { $lines.Add($n) }
    }

    $htmlName = [System.IO.Path]::ChangeExtension($jsonFile.Name, '.html')
    $hash = $null
    $htmlPath = Join-Path $ReportDir $htmlName
    if (Test-Path $htmlPath) {
        try { $hash = (Get-FileHash -Algorithm SHA256 -Path $htmlPath).Hash.ToLower() } catch { $hash = $null }
    }

    $sys = $data.SystemInfo

    # Esito del registro locale dello strumento (connessioni passate), se letto.
    $logOutcome = ''
    $ul = $data.UltraVncLog
    if ($ul -and [int]$ul.RemoteConnectionCount -gt 0) {
        $addrs = @($ul.DistinctRemoteAddresses | Select-Object -First 10)
        $addrText = ($addrs -join ', ')
        if (@($ul.DistinctRemoteAddresses).Count -gt 10) { $addrText += ', ...' }
        $per = ''
        if ($ul.FirstSeenText -and $ul.LastSeenText) { $per = ", registrate tra il $($ul.FirstSeenText) e il $($ul.LastSeenText)" }
        $logOutcome = "Dalla lettura del registro locale dello strumento risultano $(if ($ul.RemoteSessionCount) { [int]$ul.RemoteSessionCount } else { [int]$ul.RemoteConnectionCount }) sessioni da $(@($ul.DistinctRemoteAddresses).Count) indirizzi non locali ($addrText)$per. Si chiede di indicare a quali soggetti appartengano tali indirizzi, con quale finalita' e in forza di quale autorizzazione le connessioni siano state effettuate."
    }

    # Esito della configurazione del consenso, se la scansione lo ha letto: distingue
    # un'assistenza richiesta dall'utente da un accesso silenzioso.
    $consentOutcome = ''
    $consentReason = ''
    if ($data.RemoteToolConfig -and $data.RemoteToolConfig.UltraVNC -and $data.RemoteToolConfig.UltraVNC.Consent) {
        $consentOutcome = [string]$data.RemoteToolConfig.UltraVNC.Consent.Outcome
        $consentReason = [string]$data.RemoteToolConfig.UltraVNC.Consent.Reason
    }

    # Nei report generati prima della v5.2.0 il campo non esiste: in tal caso resta
    # $null e le lettere non affermano nulla sui privilegi.
    $elevated = $null
    if ($null -ne $data.IsElevated) { $elevated = [bool]$data.IsElevated }
    $adminMember = 'Indeterminato'
    if ($data.AdminGroupMember) { $adminMember = [string]$data.AdminGroupMember }

    return [PSCustomObject]@{
        ReportFileName = $htmlName
        ReportHash     = $hash
        ComputerName   = if ($sys) { [string]$sys.ComputerName } else { '' }
        ScanDate       = if ($sys -and $sys.ScanDate) { [string]$sys.ScanDate } else { [string]$data.GeneratedAt }
        Findings       = @($lines)
        IsElevated     = $elevated
        AdminGroupMember = $adminMember
        ConsentOutcome = $consentOutcome
        ConsentReason  = $consentReason
        LogOutcome     = $logOutcome
    }
}

# --------------------------------------------------------------------------
# MODELLI DI RICHIESTA
# Segnaposto {{CHIAVE}}: se il valore manca resta "[DA COMPILARE: chiave]" cosi' e'
# impossibile spedire per errore una lettera incompleta senza accorgersene.
# --------------------------------------------------------------------------

function Expand-DVTemplate {
    param(
        [Parameter(Mandatory)][string]$Template,
        [hashtable]$Data = @{}
    )
    return [regex]::Replace($Template, '\{\{([A-Z_]+)\}\}', {
        param($m)
        $key = $m.Groups[1].Value
        if ($Data.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace([string]$Data[$key])) {
            return [string]$Data[$key]
        }
        return "[DA COMPILARE: $key]"
    })
}

function Get-DVRequestTemplateText {
    param([Parameter(Mandatory)][string]$Type)

    switch ($Type) {
        'DPO-ISTANZA' { return @'
{{LUOGO}}, {{DATA}}

Via PEC: {{DESTINATARIO_PEC}}
Spett.le {{DESTINATARIO_NOME}}
Responsabile della protezione dei dati (DPO) - {{ENTE}}
(per conoscenza: Titolare del trattamento - Direzione, {{ENTE}})

OGGETTO: Richiesta di informazioni e di accesso ai dati personali (artt. 12, 13 e 15 Reg. UE 2016/679) e di documentazione ex art. 4 L. 300/1970 - software di accesso remoto sulla postazione di lavoro {{NOME_PC}}

Il/La sottoscritto/a {{NOME_COGNOME}}, {{QUALIFICA}} presso {{STRUTTURA}},

PREMESSO CHE

in data {{DATA_RILEVAZIONE}} ho eseguito, sulla postazione di lavoro a me assegnata ({{NOME_PC}}), una verifica tecnica automatizzata di primo livello con lo strumento open source "DigitalValut Controller" (licenza Apache 2.0). Lo strumento non modifica il sistema ed e' soggetto a falsi positivi e falsi negativi: il suo esito non costituisce perizia ne' prova di un illecito.

La verifica ha evidenziato i seguenti elementi, che riporto al solo fine di ottenere chiarimenti:
{{ELENCO_RILEVAZIONI}}

Impronta SHA-256 del report generato ({{FILE_REPORT}}): {{HASH_REPORT}}
Il report e' a disposizione dell'Ente.

{{CONFIGURAZIONE_CONSENSO}}

{{REGISTRO_STRUMENTO}}

{{PRIVILEGI}}

{{INFORMATIVA_SCELTA}}

CHIEDE

1. di confermare se i software o le funzionalita' sopra indicati siano installati, configurati o gestiti dall'Ente (o da un fornitore per suo conto), da quale soggetto e per quale finalita';
2. di indicare la base giuridica del trattamento e di trasmettere copia dell'informativa ai sensi dell'art. 13 GDPR e dell'art. 4, comma 3, L. 300/1970 relativa a tali strumenti;
3. di indicare se per tali strumenti esista un accordo con le rappresentanze sindacali o un'autorizzazione dell'Ispettorato del lavoro ai sensi dell'art. 4, comma 1, L. 300/1970, trasmettendone copia o gli estremi;
4. di indicare le categorie di soggetti autorizzati ad accedere da remoto alla mia postazione, con quali modalita' (ad esempio: previa richiesta o consenso dell'utente, avviso a video, accesso non presidiato) e con quali misure di sicurezza e autenticazione;
5. ai sensi dell'art. 15 GDPR, di fornire copia dei dati personali che mi riguardano trattati mediante tali strumenti, compresi i registri (log) degli accessi remoti alla mia postazione relativi al periodo {{PERIODO_LOG}}, e di indicarne i tempi di conservazione;
6. di indicare se per tali trattamenti sia stata effettuata una valutazione d'impatto (art. 35 GDPR) e se il DPO sia stato consultato.

TERMINE DI RISCONTRO

Ai sensi dell'art. 12, par. 3, GDPR si chiede riscontro senza ingiustificato ritardo e comunque entro un mese dal ricevimento della presente (termine prorogabile solo nei casi e con la comunicazione motivata previsti dal medesimo articolo). Data limite calcolata dalla data di invio: {{SCADENZA}}.

RISERVA

In mancanza di riscontro, o in caso di riscontro incompleto, mi riservo di tutelare i miei diritti anche mediante reclamo al Garante per la protezione dei dati personali (art. 77 GDPR) e segnalazione alle rappresentanze sindacali e agli organi competenti. La presente richiesta non costituisce accusa di illecito nei confronti di alcuno: e' volta esclusivamente a ottenere chiarimenti e documentazione.

Si prega di rispondere al seguente recapito: {{RECAPITO}}

Distinti saluti.
{{NOME_COGNOME}}

Firma: ______________________

Allegati: {{ALLEGATI}}
'@ }

        'DPO-SOLLECITO' { return @'
{{LUOGO}}, {{DATA}}

Via PEC: {{DESTINATARIO_PEC}}
Spett.le {{DESTINATARIO_NOME}}
Responsabile della protezione dei dati (DPO) - {{ENTE}}
(per conoscenza: Titolare del trattamento - Direzione, {{ENTE}})

OGGETTO: SOLLECITO di riscontro - mia richiesta del {{DATA_INVIO_PRECEDENTE}} (rif. {{RIFERIMENTO_PRECEDENTE}}) ai sensi degli artt. 12, 13 e 15 Reg. UE 2016/679 - postazione {{NOME_PC}}

Il/La sottoscritto/a {{NOME_COGNOME}}, {{QUALIFICA}} presso {{STRUTTURA}},

RICHIAMATA la richiesta indicata in oggetto, trasmessa in data {{DATA_INVIO_PRECEDENTE}} e ricevuta dall'Ente, il cui termine di riscontro e' scaduto il {{SCADENZA_PRECEDENTE}};

PRESO ATTO che alla data odierna {{STATO_RISCONTRO}};

SOLLECITA

un riscontro completo ai punti della richiesta originaria (che si allega) entro {{GIORNI}} giorni dal ricevimento della presente, ovvero, se ritenuto sussistente un caso di proroga ai sensi dell'art. 12, par. 3, GDPR, la comunicazione motivata prevista dalla norma.

In mancanza, mi riservo di proporre reclamo al Garante per la protezione dei dati personali (art. 77 GDPR) e di informare le rappresentanze sindacali e gli organi competenti. La presente non costituisce accusa di illecito: e' un sollecito a ottenere chiarimenti e documentazione dovuti.

Recapito per la risposta: {{RECAPITO}}

Distinti saluti.
{{NOME_COGNOME}}

Firma: ______________________

Allegati: copia della richiesta originaria e della ricevuta di consegna PEC/raccomandata.
'@ }

        'RSU' { return @'
{{LUOGO}}, {{DATA}}

Alla RSU / alle Organizzazioni sindacali - {{ENTE}}
Recapito: {{DESTINATARIO_PEC}}

OGGETTO: Richiesta di informazioni su eventuali accordi ex art. 4 L. 300/1970 relativi a strumenti di accesso remoto alle postazioni di lavoro

Il/La sottoscritto/a {{NOME_COGNOME}}, {{QUALIFICA}} presso {{STRUTTURA}},

in data {{DATA_RILEVAZIONE}} ho eseguito sulla postazione a me assegnata ({{NOME_PC}}) una verifica tecnica automatizzata di primo livello (strumento open source "DigitalValut Controller"; possibili falsi positivi, non e' una perizia). Sono stati evidenziati i seguenti elementi, riportati al solo fine di chiedere chiarimenti:
{{ELENCO_RILEVAZIONI}}
Impronta SHA-256 del report ({{FILE_REPORT}}): {{HASH_REPORT}}

{{CONFIGURAZIONE_CONSENSO}}

{{REGISTRO_STRUMENTO}}

{{PRIVILEGI}}

CHIEDO

1. se risulti alla RSU/alle OO.SS. un accordo ai sensi dell'art. 4, comma 1, L. 300/1970 (o un'autorizzazione dell'Ispettorato del lavoro) riguardante strumenti di accesso o assistenza remota alle postazioni, e in caso positivo di averne copia;
2. se i lavoratori abbiano ricevuto l'informativa prevista dall'art. 4, comma 3, L. 300/1970 e dall'art. 13 GDPR;
3. se la RSU ritenga opportuno richiedere chiarimenti all'Ente.

Mi rendo disponibile a mettere il report a disposizione della RSU. Chiedo che le informazioni siano trattate con riservatezza. La presente non costituisce accusa di illecito nei confronti di alcuno.

Recapito: {{RECAPITO}}

Cordiali saluti.
{{NOME_COGNOME}}

Allegati: {{ALLEGATI}}
'@ }

        'INL' { return @'
{{LUOGO}}, {{DATA}}

Via PEC: {{DESTINATARIO_PEC}}
Spett.le Ispettorato territoriale del lavoro di {{DESTINATARIO_NOME}}

OGGETTO: Segnalazione e richiesta di informazioni - strumenti di accesso remoto alle postazioni di lavoro presso {{ENTE}} (art. 4 L. 300/1970)

Il/La sottoscritto/a {{NOME_COGNOME}}, {{QUALIFICA}} presso {{STRUTTURA}},

SEGNALA che in data {{DATA_RILEVAZIONE}}, con una verifica tecnica automatizzata di primo livello (strumento open source "DigitalValut Controller"; possibili falsi positivi, non e' una perizia), sono stati evidenziati sulla postazione {{NOME_PC}} i seguenti elementi:
{{ELENCO_RILEVAZIONI}}
Impronta SHA-256 del report ({{FILE_REPORT}}): {{HASH_REPORT}}

{{STATO_PRECEDENTI}}

CHIEDE di sapere, per quanto di competenza di codesto Ufficio:
1. se risultino provvedimenti di autorizzazione ai sensi dell'art. 4, comma 1, L. 300/1970 riferiti a {{ENTE}} per strumenti di accesso o assistenza remota alle postazioni di lavoro;
2. quali ulteriori passi siano eventualmente opportuni da parte del lavoratore, ovvero a quale diverso ufficio rivolgersi qualora la materia non rientri nella competenza dell'Ispettorato.

La presente non costituisce accusa di illecito nei confronti di alcuno: e' una segnalazione e richiesta di informazioni.

Recapito: {{RECAPITO}}

Distinti saluti.
{{NOME_COGNOME}}

Firma: ______________________

Allegati: {{ALLEGATI}}
'@ }

        'GARANTE-RECLAMO' { return @'
{{LUOGO}}, {{DATA}}

Via PEC: {{DESTINATARIO_PEC}}
Al Garante per la protezione dei dati personali
Piazza Venezia n. 11 - 00187 Roma

OGGETTO: RECLAMO ai sensi dell'art. 77 Reg. UE 2016/679 e degli artt. 140-bis e 142 D.Lgs. 196/2003

1. RECLAMANTE
{{NOME_COGNOME}}, {{QUALIFICA}} presso {{STRUTTURA}}. Recapito per le comunicazioni: {{RECAPITO}}.

2. TITOLARE DEL TRATTAMENTO
{{ENTE}} - sede: {{SEDE_ENTE}}. DPO: {{DESTINATARIO_NOME_DPO}} (PEC: {{PEC_DPO}}).

3. FATTI
a) In data {{DATA_RILEVAZIONE}} ho eseguito sulla postazione di lavoro assegnatami ({{NOME_PC}}) una verifica tecnica automatizzata di primo livello (strumento open source "DigitalValut Controller"; possibili falsi positivi; non e' una perizia). Sono stati evidenziati:
{{ELENCO_RILEVAZIONI}}
Impronta SHA-256 del report ({{FILE_REPORT}}): {{HASH_REPORT}}
b) In data {{DATA_ISTANZA}} ho trasmesso al DPO dell'Ente una richiesta di informazioni e di accesso (artt. 12, 13, 15 GDPR) - riferimento/ricevuta: {{RIFERIMENTO_ISTANZA}}.
c) {{CRONOLOGIA_SOLLECITI}}
d) {{ESITO_RISCONTRO}}

4. DISPOSIZIONI CHE SI RITIENE POSSANO ESSERE STATE VIOLATE
Alla luce dei fatti esposti, e salvo ogni valutazione del Garante, si ritengono potenzialmente non rispettati: art. 12 (riscontro all'interessato nei termini) e art. 15 GDPR (accesso); artt. 5, par. 1, lett. a), e 13 GDPR (trasparenza e informativa) e art. 4 L. 300/1970, richiamato dall'art. 114 D.Lgs. 196/2003, per quanto riguarda l'eventuale mancanza di informativa, accordo o autorizzazione. {{NOTA_DISPOSIZIONI}}

5. RICHIESTE
Si chiede al Garante di accertare i fatti e di adottare i provvedimenti ritenuti opportuni, tra cui invitare/ordinare al titolare di dare riscontro alla richiesta dell'interessato.

6. DOCUMENTI ALLEGATI
{{ALLEGATI}}

Luogo e data: {{LUOGO}}, {{DATA}}
Firma: ______________________
'@ }
        default { throw "Tipo di richiesta sconosciuto: $Type" }
    }
}

function Get-DVRequestOpenPoints {
    <#
    .SYNOPSIS
        Conta i punti ancora da completare in un testo: segnaposto [DA COMPILARE],
        scelte [SCEGLIERE], indicazioni [INDICARE] e righe vuote "____".
    #>
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 0 }
    $n = [regex]::Matches($Text, '\[(DA COMPILARE|SCEGLIERE|INDICARE)[^\]]*\]').Count
    $n += [regex]::Matches($Text, '_{4,}').Count - [regex]::Matches($Text, 'Firma: _{4,}').Count
    return [math]::Max(0, $n)
}

function New-DVRequestText {
    <#
    .SYNOPSIS
        Compone il testo di una richiesta dal modello, dai dati dell'utente e dall'ultima scansione.
    .PARAMETER Type
        Uno tra: DPO-ISTANZA, DPO-SOLLECITO, RSU, INL, GARANTE-RECLAMO.
    .PARAMETER Data
        Hashtable con i valori dei segnaposto (chiavi in MAIUSCOLO, es. NOME_COGNOME).
    .PARAMETER Scan
        Oggetto restituito da Get-DVLatestScanSummary (facoltativo).
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('DPO-ISTANZA', 'DPO-SOLLECITO', 'RSU', 'INL', 'GARANTE-RECLAMO')][string]$Type,
        [hashtable]$Data = @{},
        [object]$Scan = $null,
        [datetime]$Today = (Get-Date)
    )
    $d = @{}
    foreach ($k in $Data.Keys) { $d[$k.ToString().ToUpper()] = $Data[$k] }

    if (-not $d.ContainsKey('DATA'))  { $d['DATA'] = $Today.ToString('dd/MM/yyyy') }
    if ($Scan) {
        if (-not $d.ContainsKey('NOME_PC'))           { $d['NOME_PC'] = $Scan.ComputerName }
        if (-not $d.ContainsKey('DATA_RILEVAZIONE')) {
            $sd = [string]$Scan.ScanDate
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParseExact($sd, 'yyyy-MM-dd HH:mm:ss', $null, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
                $sd = $parsed.ToString('dd/MM/yyyy') + ' alle ore ' + $parsed.ToString('HH:mm')
            }
            $d['DATA_RILEVAZIONE'] = $sd
        }
        if (-not $d.ContainsKey('HASH_REPORT'))       { $d['HASH_REPORT'] = $Scan.ReportHash }
        if (-not $d.ContainsKey('FILE_REPORT'))       { $d['FILE_REPORT'] = $Scan.ReportFileName }
        if (-not $d.ContainsKey('ELENCO_RILEVAZIONI') -and $Scan.Findings) {
            $d['ELENCO_RILEVAZIONI'] = (@($Scan.Findings) | ForEach-Object { "  - $_" }) -join "`r`n"
        }
        if (-not $d.ContainsKey('PRIVILEGI') -and $null -ne $Scan.IsElevated) {
            if ($Scan.IsElevated) {
                $d['PRIVILEGI'] = "La verifica e' stata eseguita con privilegi amministrativi."
            } elseif ($Scan.AdminGroupMember -ne 'No') {
                # Non elevato, ma non risulta accertato che l'utente sia privo di privilegi:
                # la lettera NON lo afferma. Va dichiarato solo se vero.
                $d['PRIVILEGI'] = "La verifica e' stata eseguita senza elevazione dei privilegi: per alcune categorie di controllo l'esito e' percio' parziale, come dichiarato nel report. [DA COMPLETARE SOLO SE VERO: lo scrivente non dispone di privilegi amministrativi sulla postazione assegnata. Il programma non ha potuto escluderlo perche' l'account risulta " + $(if ($Scan.AdminGroupMember -eq 'Si') { 'membro del gruppo Amministratori' } else { 'di appartenenza non determinabile' }) + ']'
            } else {
                # L'assenza di privilegi non e' solo un limite della verifica: esclude che
                # installazione e configurazione siano riconducibili allo scrivente e colloca
                # i registri degli accessi nella disponibilita' esclusiva dell'Ente.
                $d['PRIVILEGI'] = "La verifica e' stata eseguita con i soli privilegi di utente standard di cui dispongo: per alcune categorie di controllo l'esito e' percio' parziale, come dichiarato nel report. Segnalo inoltre che, non disponendo di privilegi amministrativi sulla postazione assegnatami, non ho la possibilita' tecnica di installare, configurare, modificare o disattivare i software sopra indicati, ne' di consultare il registro di sicurezza del sistema che documenta gli accessi effettuati: tale documentazione risulta nella disponibilita' esclusiva dell'Ente."
            }
        }
        if (-not $d.ContainsKey('REGISTRO_STRUMENTO') -and $Scan.LogOutcome) {
            $d['REGISTRO_STRUMENTO'] = [string]$Scan.LogOutcome
        }
        if (-not $d.ContainsKey('CONFIGURAZIONE_CONSENSO') -and $Scan.ConsentOutcome) {
            $d['CONFIGURAZIONE_CONSENSO'] = "Dalla lettura del file di configurazione dello strumento risulta, quanto alla richiesta di consenso all'utente prima di una connessione remota: $($Scan.ConsentOutcome). Motivazione tecnica: $($Scan.ConsentReason)"
        }
    }
    if (-not $d.ContainsKey('PERIODO_LOG'))  { $d['PERIODO_LOG'] = 'degli ultimi 12 mesi' }
    # Facoltativi: se la scansione non li ha prodotti, la lettera non deve affermare nulla
    # (restano stringhe vuote invece di "[DA COMPILARE: ...]").
    if (-not $d.ContainsKey('PRIVILEGI'))               { $d['PRIVILEGI'] = '' }
    if (-not $d.ContainsKey('CONFIGURAZIONE_CONSENSO')) { $d['CONFIGURAZIONE_CONSENSO'] = '' }
    if (-not $d.ContainsKey('REGISTRO_STRUMENTO'))      { $d['REGISTRO_STRUMENTO'] = '' }
    if (-not $d.ContainsKey('GIORNI'))       { $d['GIORNI'] = '10' }
    if (-not $d.ContainsKey('ALLEGATI'))     {
        $d['ALLEGATI'] = switch ($Type) {
            'DPO-ISTANZA'     { "report {0} con impronta SHA-256; copia del documento di identita'" -f $(if ($d['FILE_REPORT']) { $d['FILE_REPORT'] } else { 'di scansione' }) }
            'GARANTE-RECLAMO' { "1) copia del documento di identita'; 2) richiesta al DPO e ricevuta di consegna PEC; 3) eventuali solleciti e ricevute; 4) eventuale riscontro ricevuto; 5) report di scansione con impronta SHA-256 e, se disponibile, pacchetto prova con marca temporale" }
            default           { "report {0} con impronta SHA-256" -f $(if ($d['FILE_REPORT']) { $d['FILE_REPORT'] } else { 'di scansione' }) }
        }
    }
    if (-not $d.ContainsKey('INFORMATIVA_SCELTA')) {
        $d['INFORMATIVA_SCELTA'] = "[SCEGLIERE UNA SOLA FRASE, COMPILARLA IN MODO VERITIERO E CANCELLARE L'ALTRA E QUESTA NOTA] (A) Non risulta che mi sia stata consegnata alcuna informativa sull'uso di tali strumenti. OPPURE (B) In data ____ ho ricevuto l'informativa ____, che tuttavia non chiarisce ____."
    }
    $defaults = @{
        'NOTA_DISPOSIZIONI'   = "(Le disposizioni indicate sono quelle che l'interessato ritiene potenzialmente rilevanti: da verificare con un legale o con il sindacato prima dell'invio.)"
        'STATO_PRECEDENTI'    = "[INDICARE se ti sei gia' rivolto/a al DPO, alla RSU o all'Ente e con quale esito, oppure cancellare questa riga]"
        'STATO_RISCONTRO'     = "non ho ricevuto alcun riscontro [OPPURE: ho ricevuto un riscontro incompleto con riferimento ai punti ____: SCEGLIERE E CANCELLARE L'ALTRA OPZIONE]"
        'CRONOLOGIA_SOLLECITI' = "[INDICARE data e riferimento di eventuali solleciti, oppure cancellare questa riga]"
        'ESITO_RISCONTRO'     = "[INDICARE: alla data odierna non ho ricevuto riscontro OPPURE ho ricevuto un riscontro insufficiente perche' ____]"
    }
    foreach ($k in $defaults.Keys) { if (-not $d.ContainsKey($k)) { $d[$k] = $defaults[$k] } }
    if ($Type -eq 'DPO-ISTANZA' -and -not $d.ContainsKey('SCADENZA')) {
        $sent = if ($d.ContainsKey('DATA_INVIO_PREVISTA')) { [datetime]::ParseExact($d['DATA_INVIO_PREVISTA'], 'dd/MM/yyyy', $null) } else { $Today }
        $d['SCADENZA'] = (Get-DVResponseDeadline -ReceivedDate $sent -Months 1).ToString('dd/MM/yyyy')
    }
    return (Expand-DVTemplate -Template (Get-DVRequestTemplateText -Type $Type) -Data $d)
}

# --------------------------------------------------------------------------
# REGISTRO A CATENA DI HASH (stesso schema di ChainOfCustody: tamper-evident,
# non e' una marca temporale di terza parte)
# --------------------------------------------------------------------------

function Get-DVRequestHash {
    param([Parameter(Mandatory)][string]$Content)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Content))) -replace '-', '').ToLower()
    } finally { $sha.Dispose() }
}

function Get-DVRequestLedgerPath {
    param([Parameter(Mandatory)][string]$ReportDir)
    return Join-Path $ReportDir 'richieste_registro.jsonl'
}

function Get-DVRequestEvents {
    param([Parameter(Mandatory)][string]$LedgerPath)
    if (-not (Test-Path $LedgerPath)) { return @() }
    $out = @()
    foreach ($line in (Get-Content -Path $LedgerPath -Encoding UTF8 -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $out += ($line.TrimStart([char]0xFEFF) | ConvertFrom-Json) } catch { Write-Verbose 'Riga registro non valida' }
    }
    return $out
}

function New-DVRequestId {
    param([datetime]$Now = (Get-Date))
    return 'RQ-' + $Now.ToString('yyyyMMdd-HHmmss')
}

function Add-DVRequestEvent {
    <#
    .SYNOPSIS
        Aggiunge un evento al registro delle richieste (append-only, con hash concatenati).
    .PARAMETER Event
        PREPARATA, INVIATA, RISPOSTA_RICEVUTA, CHIUSA o NOTA.
    .PARAMETER EventDate
        Data dell'evento (per INVIATA: data di invio/consegna; da qui parte la scadenza).
    #>
    param(
        [Parameter(Mandatory)][string]$LedgerPath,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('PREPARATA', 'INVIATA', 'RISPOSTA_RICEVUTA', 'CHIUSA', 'NOTA')][string]$Event,
        [Parameter(Mandatory)][ValidateSet('DPO-ISTANZA', 'DPO-SOLLECITO', 'RSU', 'INL', 'GARANTE-RECLAMO')][string]$Type,
        [datetime]$EventDate = (Get-Date),
        [string]$Recipient = '',
        [string]$Channel = '',
        [string]$Reference = '',
        [string]$DocumentFile = '',
        [string]$DocumentHash = '',
        [string]$Note = ''
    )
    $previous = 'GENESIS'
    $existing = @(Get-DVRequestEvents -LedgerPath $LedgerPath)
    if ($existing.Count -gt 0) { $previous = [string]$existing[-1].EntryHash }

    $deadline = ''
    if ($Event -eq 'INVIATA') {
        $t = $script:RequestTypes[$Type]
        $dl = Get-DVResponseDeadline -ReceivedDate $EventDate -Months $t.Mesi -Days $t.Giorni
        if ($dl) { $deadline = $dl.ToString('yyyy-MM-dd') }
    }

    $record = [ordered]@{
        Id           = $Id
        Event        = $Event
        Type         = $Type
        EventDate    = $EventDate.ToString('yyyy-MM-dd')
        Timestamp    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff'Z'")
        Recipient    = $Recipient
        Channel      = $Channel
        Reference    = $Reference
        Deadline     = $deadline
        DocumentFile = $DocumentFile
        DocumentHash = $DocumentHash
        Note         = $Note
        PreviousHash = $previous
    }
    $json = $record | ConvertTo-Json -Compress -Depth 5
    $record['EntryHash'] = Get-DVRequestHash -Content ($previous + $json)
    $line = $record | ConvertTo-Json -Compress -Depth 5
    Add-Content -Path $LedgerPath -Value $line -Encoding UTF8
    return [PSCustomObject]$record
}

function Test-DVRequestChain {
    <#
    .SYNOPSIS
        Verifica l'integrita' del registro delle richieste (ricalcola ogni hash).
    #>
    param([Parameter(Mandatory)][string]$LedgerPath)
    if (-not (Test-Path $LedgerPath)) {
        return [PSCustomObject]@{ Valid = $true; TotalEntries = 0; Message = 'Nessun registro delle richieste presente.' }
    }
    $lines = @(Get-Content -Path $LedgerPath -Encoding UTF8 | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $expected = 'GENESIS'
    $i = 0
    foreach ($line in $lines) {
        $i++
        try { $entry = $line.TrimStart([char]0xFEFF) | ConvertFrom-Json } catch {
            return [PSCustomObject]@{ Valid = $false; TotalEntries = $i; Message = "Riga ${i}: non e' JSON valido, registro corrotto o manomesso." }
        }
        if ($entry.PreviousHash -ne $expected) {
            return [PSCustomObject]@{ Valid = $false; TotalEntries = $i; Message = "Riga ${i}: la catena non corrisponde. Possibile rimozione o riordino di record." }
        }
        $src = [ordered]@{}
        foreach ($p in $entry.PSObject.Properties) { if ($p.Name -ne 'EntryHash') { $src[$p.Name] = $p.Value } }
        $calc = Get-DVRequestHash -Content ($entry.PreviousHash + ($src | ConvertTo-Json -Compress -Depth 5))
        if ($calc -ne $entry.EntryHash) {
            return [PSCustomObject]@{ Valid = $false; TotalEntries = $i; Message = "Riga ${i}: il contenuto e' stato modificato dopo la scrittura." }
        }
        $expected = [string]$entry.EntryHash
    }
    return [PSCustomObject]@{ Valid = $true; TotalEntries = $i; Message = "Registro integro: $i eventi verificati, nessuna manomissione rilevata." }
}

# --------------------------------------------------------------------------
# STATO E PASSO SUCCESSIVO (funzioni pure, testabili)
# --------------------------------------------------------------------------

function Get-DVRequestSummary {
    <#
    .SYNOPSIS
        Riassume lo stato di ogni richiesta a una certa data: PREPARATA, INVIATA, SCADUTA,
        RISPOSTA_RICEVUTA, CHIUSA, con giorni residui o di ritardo e passo successivo.
    #>
    param(
        [AllowEmptyCollection()][object[]]$Events = @(),
        [datetime]$Today = (Get-Date)
    )
    $out = @()
    $groups = @($Events | Where-Object { $_ } | Group-Object -Property Id)
    foreach ($g in $groups) {
        $ev = @($g.Group)
        $type = [string]$ev[0].Type
        $sent = @($ev | Where-Object { $_.Event -eq 'INVIATA' }) | Select-Object -Last 1
        $answered = @($ev | Where-Object { $_.Event -eq 'RISPOSTA_RICEVUTA' }) | Select-Object -Last 1
        $closed = @($ev | Where-Object { $_.Event -eq 'CHIUSA' }) | Select-Object -Last 1

        $status = 'PREPARATA'
        $days = $null
        $deadline = $null
        if ($sent -and $sent.Deadline) { $deadline = [datetime]::ParseExact([string]$sent.Deadline, 'yyyy-MM-dd', $null) }

        if ($closed) { $status = 'CHIUSA' }
        elseif ($answered) { $status = 'RISPOSTA_RICEVUTA' }
        elseif ($sent) {
            $status = 'INVIATA'
            if ($deadline) {
                $days = [int]($deadline.Date - $Today.Date).TotalDays
                if ($days -lt 0) { $status = 'SCADUTA' }
            }
        }

        $next = ''
        switch ($status) {
            'PREPARATA'         { $next = "Rileggi, completa i campi [DA COMPILARE], falla rivedere a un legale/sindacato, poi inviala tu (PEC) e registra l'invio." }
            'INVIATA'           { $next = if ($deadline) { "In attesa di riscontro: scadenza il $($deadline.ToString('dd/MM/yyyy')) ($days giorni)." } else { 'Inviata: questo tipo non ha una scadenza di legge calcolata; valuta un sollecito dopo un tempo ragionevole.' } }
            'SCADUTA' {
                $next = switch ($type) {
                    'DPO-ISTANZA'    { "Termine scaduto da $([math]::Abs($days)) giorni: prepara un DPO-SOLLECITO." }
                    'DPO-SOLLECITO'  { "Sollecito scaduto da $([math]::Abs($days)) giorni senza riscontro: valuta il GARANTE-RECLAMO (allega istanza, sollecito e ricevute)." }
                    default          { 'Termine scaduto: valuta il passo successivo con legale/sindacato.' }
                }
            }
            'RISPOSTA_RICEVUTA' { $next = 'Verifica che il riscontro risponda a tutti i punti; se incompleto, registra una NOTA e valuta un sollecito mirato o il reclamo.' }
            'CHIUSA'            { $next = 'Pratica chiusa.' }
        }
        $out += [PSCustomObject]@{
            Id         = [string]$g.Name
            Tipo       = $type
            Stato      = $status
            Scadenza   = if ($deadline) { $deadline.ToString('dd/MM/yyyy') } else { '' }
            GiorniResidui = $days
            Destinatario = [string](($ev | Where-Object { $_.Recipient } | Select-Object -Last 1).Recipient)
            ProssimoPasso = $next
        }
    }
    return $out
}

Export-ModuleMember -Function Get-DVRequestTypes, Get-DVResponseDeadline, ConvertTo-DVNeutralFinding,
    Get-DVLatestScanSummary, Expand-DVTemplate, Get-DVRequestTemplateText, New-DVRequestText,
    Get-DVRequestHash, Get-DVRequestLedgerPath, Get-DVRequestEvents, New-DVRequestId,
    Add-DVRequestEvent, Test-DVRequestChain, Get-DVRequestSummary, Get-DVRequestOpenPoints
