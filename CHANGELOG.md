# Changelog

Tutte le modifiche rilevanti a questo progetto sono documentate in questo file.

Il formato si ispira a [Keep a Changelog](https://keepachangelog.com/it/1.1.0/)
e il progetto adotta il [Versionamento Semantico](https://semver.org/lang/it/).

## [5.0.0] — 2026-08-11

Versione dedicata a un unico obiettivo: rendere il materiale prodotto
**utilizzabile davanti a un professionista**. Non trasforma lo strumento in una
perizia forense — quella la redige un perito iscritto all'albo — ma colma le tre
lacune che rendevano il materiale precedente facilmente contestabile: la data
non attestata, la fotografia istantanea, e la verifica affidata allo stesso
programma che aveva creato i file.

### Aggiunto

- **Modalità Sentinella** (`SentinelMonitor.psm1`, `AVVIA_SENTINELLA.bat`):
  monitoraggio continuo che registra le sessioni di controllo remoto **mentre
  accadono**, con orario di inizio, fine e durata, e l'uso di microfono e webcam.
  - Deduplicazione a sessioni: una connessione continuativa genera due soli
    eventi (apertura e chiusura), non una riga per ciclo di campionamento.
  - Registro append-only con hash concatenati: cancellare o modificare un evento
    passato rompe la catena ed è rilevabile.
  - I periodi non coperti dalla sorveglianza sono dichiarati esplicitamente:
    l'assenza di eventi non viene spacciata per assenza di fatti.
- **Marca temporale RFC 3161** (`TimestampAuthority.psm1`): richiesta a
  un'autorità terza che certifica crittograficamente la data di esistenza del
  materiale. Implementazione completa in PowerShell puro — costruzione della
  richiesta DER/ASN.1, invio, verifica della firma CMS ed estrazione della data
  certificata — senza alcuna dipendenza esterna.
  - **Privacy**: viene inviato esclusivamente l'hash SHA-256 (32 byte), mai i
    dati. È l'unica funzione dello strumento che si collega a Internet ed è
    **opt-in esplicita**.
  - Tre autorità gratuite preconfigurate, con possibilità di indicarne una
    propria (es. una TSA qualificata eIDAS).
- **Pacchetto prova sigillato** (`EvidencePackage.psm1`,
  `CREA_PACCHETTO_PROVA.bat`): un unico `.zip` da consegnare a un avvocato, con
  manifesto degli hash di ogni file, marca temporale e istruzioni per il
  destinatario.
- **Verificatore autonomo** (`VERIFICA_PROVA.ps1` / `.bat`): incluso nel
  pacchetto, **non importa alcun modulo del progetto** e non richiede
  installazioni. Chiunque riceva il materiale può verificarne integrità e data
  senza riporre fiducia in chi lo ha prodotto. Risolve il problema strutturale
  per cui la verifica era finora affidata allo stesso programma che aveva
  generato i file.
- **Conservazione dei dati grezzi** (`RawEvidence.psm1`): salva l'output non
  interpretato di dieci comandi di sistema (connessioni, processi, servizi,
  chiavi di avvio, task pianificati, stato RDP…), ciascuno accompagnato dal
  comando esatto che lo ha prodotto, perché un perito possa rifare l'analisi da
  zero senza fidarsi delle conclusioni dello strumento.
- **[`GUIDA_PROVE.md`](GUIDA_PROVE.md)**: guida pratica in tre livelli per chi
  deve documentare una situazione seria.
- Nuova sezione nel report dedicata agli eventi registrati dalla Sentinella.
- 54 nuovi test automatici (da 93 a **147 totali**), inclusa la verifica che il
  verificatore autonomo rilevi effettivamente una manomissione e che non dipenda
  da moduli del progetto.

### Corretto

- `Read-DVDerTlv` sollevava un'eccezione di binding su un array di byte vuoto
  anziché restituire `$null` come previsto per un parser difensivo. Corretto
  anche nella copia inclusa nel verificatore autonomo.
- Il parametro `MaxMinutes` della Sentinella era tipizzato come intero, quindi
  qualunque durata inferiore al minuto veniva troncata a 0 e interpretata come
  "esegui senza limite". Ora è un valore decimale.
- L'attesa tra i cicli della Sentinella era un unico `Start-Sleep` lungo: una
  richiesta di arresto poteva restare inascoltata per l'intero intervallo. Ora
  l'attesa è suddivisa in intervalli di un secondo.

### Sicurezza

- La CI verifica sintassi e lint anche di `VERIFICA_PROVA.ps1`: è lo script che
  eseguiranno terze parti, quindi non può mai essere rotto.

## [4.2.0] — 2026-08-06

### Aggiunto

- **Motore di regole esterne**: le firme di rilevamento non vivono più dentro il
  codice PowerShell ma in file `.json` nella cartella `core/rules/`. Chiunque
  può aggiungere i propri rilevamenti creando un file, senza saper programmare,
  senza modificare il codice sorgente e senza dover coinvolgere l'autore del
  progetto. Nuovo modulo `RuleEngine.psm1`, guida in [`RULES.md`](RULES.md).
  - Le regole sono **solo dati dichiarativi**, mai codice eseguibile: un file di
    regole di terze parti non può eseguire comandi sul PC. Scelta di sicurezza
    deliberata.
  - Una regola malformata viene **ignorata senza bloccare la scansione**, con il
    motivo dello scarto riportato nel report.
  - Se la cartella regole manca o è danneggiata si usa il **database interno di
    riserva**: nessuna regressione rispetto alle versioni precedenti.
  - Le 75 firme esistenti (25 porte + 50 processi) sono state migrate in 7 file
    di regole, con conversione verificata identica all'originale.
- **Rilevamento di DLL caricate da percorsi anomali** (`ModuleAnalyzer.psm1`):
  molti strumenti di monitoraggio non girano come processo autonomo ma si
  iniettano come libreria dentro processi legittimi. Vengono segnalate le DLL
  caricate da cartelle temporanee o pubbliche, con verifica della firma digitale
  e soppressione dei falsi positivi dei vendor noti (Chrome, Teams, Discord,
  Zoom e altri installano legittimamente in AppData).
- **Analisi storica dei registri eventi di Windows** (`EventLogAnalyzer.psm1`):
  tutti gli altri controlli fotografano il presente; questo guarda indietro nel
  tempo. Servizi installati di recente (evento 7045), cancellazioni del registro
  di sicurezza (1102), accessi remoti RDP (4624 tipo 10). Degrada con grazia
  senza privilegi amministrativi, dichiarando apertamente nel report cosa non è
  stato possibile verificare.
- Nuove sezioni nel report: DLL sospette, analisi storica, regole caricate
  (con elenco degli scarti e istruzioni per aggiungerne di proprie).
- 48 nuovi test automatici (da 45 a **93 totali**), inclusa la verifica che le
  regole ufficiali del progetto siano tutte valide e senza id duplicati.

### Modificato

- Rimossi gli spazi a fine riga da tutti i file PowerShell del progetto.

## [4.1.1] — 2026-08-06

### Modificato

- **`AVVIA_CONTROLLO.bat` non chiede più nulla**: eseguiva un menu interattivo
  (`choice /c 1234`) che restava in attesa di un tasto prima di iniziare
  qualunque cosa. Un utente che si aspettava "doppio clic e via" restava
  bloccato senza capire perché. Ora il doppio clic avvia direttamente la
  scansione completa, senza alcuna scelta richiesta.
- Il menu con le opzioni (rapida/completa/verifica catena di custodia) non è
  sparito: è stato spostato nel nuovo `AVVIA_AVANZATO.bat`, per chi lo vuole
  esplicitamente.

### Verificato

- Testato il download reale da GitHub Releases con il blocco "proveniente da
  Internet" (Mark-of-the-Web) applicato come farebbe un vero browser:
  **Windows SmartScreen non blocca l'esecuzione** di `AVVIA_CONTROLLO.bat`
  (nessuna finestra di blocco osservata); l'unico vero ostacolo trovato era
  il menu interattivo, ora rimosso.
- Confermato con un'esecuzione reale, senza premere alcun tasto, che il
  report viene generato e aperto automaticamente.

## [4.1.0] — 2026-08-06

### Aggiunto

- **Verifica firma digitale (Authenticode)** di ogni processo sospetto rilevato:
  nuovo modulo `AuthenticodeChecker.psm1`, colonna "Firma" nella tabella
  processi del report, elemento aggiuntivo (non decisivo da solo) nel
  punteggio di rischio.
- **Rilevamento persistenza avanzata**: nuovo modulo `PersistenceAnalyzer.psm1`
  — sottoscrizioni WMI permanenti non riconosciute, `AppInit_DLLs`, debugger
  IFEO (hijacking di eseguibili), task pianificati con pattern sospetti
  (comandi codificati, download remoti). Nuova sezione dedicata nel report.
- **Confronto con la scansione precedente**: nuove funzioni
  `Get-DVLastLedgerEntry` e `Compare-DVScanFindings` in `ChainOfCustody.psm1`;
  il report mostra nuovi riscontri e riscontri risolti rispetto all'ultima
  scansione registrata nella catena di custodia.
- **Spiegazione in linguaggio semplice generata da AI locale (opzionale)**:
  nuovo modulo `OllamaAssistant.psm1`. Comunica esclusivamente con
  `127.0.0.1` (loopback): nessun dato lascia mai il dispositivo. Se Ollama
  non è installato la funzionalità è no-op, senza dipendenze obbligatorie né
  rallentamenti. Disattivabile con il parametro `-DisableAI`.
- **Suite di test automatici** (Pester): 45 test su hash/catena di custodia,
  calcolo del punteggio di rischio, persistenza avanzata, firma digitale,
  modulo AI locale — cartella [`tests/`](tests/).
- **CI su GitHub Actions**: sintassi, lint (PSScriptAnalyzer) e test eseguiti
  automaticamente a ogni push/PR — [`​.github/workflows/ci.yml`](.github/workflows/ci.yml).
- **`PSScriptAnalyzerSettings.psd1`**: configurazione lint con le esclusioni
  documentate e motivate per le convenzioni intenzionali del progetto.
- **`scripts/New-ReleasePackage.ps1`**: genera il pacchetto ZIP di release e
  il relativo `SHA256SUMS.txt` per la verifica di integrità del download.

### Corretto

- **Bug nel calcolo del livello di rischio**: il blocco `switch` che
  determinava il livello testuale (SICURO/BASSO/MEDIO/ALTO/CRITICO) non
  utilizzava `break`, quindi per qualunque punteggio tra 1 e 99 venivano
  eseguite **più clausole contemporaneamente**, producendo un livello
  ambiguo (es. array `BASSO, MEDIO, ALTO` invece del solo livello corretto).
  Individuato dai nuovi test automatici (`tests/ThreatScore.Tests.ps1`) e
  corretto sostituendo lo switch con una catena if/elseif esplicita.
- Variabile automatica di PowerShell `$profile` usata come nome di variabile
  in `SecurityChecker.psm1` (rinominata in `$fwProfile` per evitare
  l'ombreggiamento non voluto della variabile di sistema).
- Confronti con `$null` riordinati secondo le best practice PowerShell in
  `SurveillanceDetector.psm1` (`$null -eq $x` anziché `$x -eq $null`, per
  evitare il comportamento a sorpresa se `$x` fosse un array).
- Encoding UTF-8 con BOM ripristinato su `ReportGenerator.psm1` e
  `SurveillanceDetector.psm1`, per una lettura corretta dei caratteri
  accentati su Windows PowerShell 5.1 in assenza di BOM.

## [4.0.1] — 2026-08-06

### Modificato

- **Riformulate le affermazioni sul valore probatorio dei report.** Il report
  non è più descritto come "prova documentale con valore legale" ma come
  segnalazione tecnica di primo livello. La modifica interessa il report
  generato, la guida completa, il file LEGGIMI e l'intestazione dello script.
- **Documentati esplicitamente i limiti della catena di custodia**: meccanismo
  tamper-evident locale, privo di marcatura temporale certificata di terza
  parte (RFC 3161) e rigenerabile da un soggetto tecnicamente competente.
- Attenuate le conclusioni giuridiche perentorie nella sezione normativa del
  report: l'illegittimità di un trattamento può essere accertata solo caso per
  caso, e possono esistere accordi o autorizzazioni non noti all'utente.
- Le sanzioni indicate sono ora qualificate come massimi edittali astratti.

### Aggiunto

- [`DISCLAIMER.md`](DISCLAIMER.md): avvertenze, limiti tecnici e probatori
  dichiarati, esclusione di responsabilità, obblighi dell'utente.
- Riquadro di avvertenza sui limiti, incluso in ogni report generato.
- [`SECURITY.md`](SECURITY.md): politica di divulgazione delle vulnerabilità.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): linee guida per i contributi.
- Questo changelog.

## [4.0.0] — 2026-08-06

### Aggiunto

- Prima pubblicazione open source sotto licenza **GNU GPL v3.0**.
- Rilevamento di connessioni remote attive (VNC, TeamViewer, RDP, AnyDesk) con
  indicazione di chi è collegato e delle capacità di controllo.
- Modulo **SurveillanceDetector**: uso di microfono e webcam, dispositivi audio
  virtuali, permessi privacy di Windows, indicatori di spyware audio.
- Analisi di porte in ascolto, connessioni esterne, processi e servizi sospetti.
- Verifica di software installato, programmi in avvio automatico, stato di
  firewall e antivirus.
- Punteggio di rischio aggregato (SICURO → CRITICO).
- Report HTML e JSON con riferimenti normativi e fac-simile di richiesta al DPO.
- Modulo **ChainOfCustody**: hash SHA-256 dei report e registro append-only con
  hash concatenati, verificabile tramite il parametro `-VerifyChain`.
- Modalità `-QuickScan` per un controllo rapido.
- Funzionamento portabile: nessuna installazione, nessuna connessione di rete.

[5.0.0]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v5.0.0
[4.2.0]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.2.0
[4.1.1]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.1.1
[4.1.0]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.1.0
[4.0.1]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.0.1
[4.0.0]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.0.0
