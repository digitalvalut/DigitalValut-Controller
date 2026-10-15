# Changelog

Tutte le modifiche rilevanti a questo progetto sono documentate in questo file.

Il formato si ispira a [Keep a Changelog](https://keepachangelog.com/it/1.1.0/)
e il progetto adotta il [Versionamento Semantico](https://semver.org/lang/it/).

## [5.4.1] — 2026-10-15

### Aggiunto

- `DISCLAIMER.md`: sezioni 11-16 (enti e PA, dati personali non raccolti, software e servizi di
  terzi, nome e marchio, sicurezza e aggiornamenti, rapporto con la Licenza). Corretto il
  rinvio alle sezioni della licenza (ora Apache 2.0, sezioni 7-9).

## [5.4.0] — 2026-10-15

### Cambiato

- **Licenza: da GNU GPL v3 a Apache 2.0.** Il titolare dei diritti e' Digital Valut APS
  (CF 90036980846). Aggiunti `LICENSE` (testo Apache 2.0) e `NOTICE` (titolare e
  sedi); intestazioni dei file con identificatore SPDX; report, avvisi e lettere
  aggiornati. Le versioni fino alla 5.3.1 restano disponibili anche sotto GPLv3 per
  chi le ha gia' ricevute.
- Denominazione unificata: "Digital Valut APS" al posto di "DigitalValut Association".
- Contributi: dichiarati sotto Apache 2.0 (sezione 5 della Licenza).

### Aggiunto

- `docs/PUBBLICA_AMMINISTRAZIONE.md`: guida per DPO, uffici del personale, RSU e
  sindacati (autoverifica, risposta a una richiesta di un dipendente, buone pratiche,
  limiti).

## [5.3.1] — 2026-10-13

Correzioni emerse dal primo report reale con la lettura del registro (326 "connessioni").

### Corretto

- **Sessioni, non righe.** In `mslogon.log` una sola connessione genera piu' righe
  ("Connection received from" ripetuta). La 5.3.0 contava le righe e le chiamava
  connessioni, gonfiando il numero di circa tre volte. Ora si contano le sessioni
  (righe consecutive dello stesso indirizzo, senza disconnessione in mezzo, a meno
  di 5 minuti l'una dall'altra) e il numero di righe e' indicato a parte.
- **Stesso file letto due volte.** Percorsi uguali a meno delle maiuscole venivano
  letti due volte; ora sono riconosciuti come lo stesso file (Windows non distingue
  le maiuscole).
- **Peso del solo storico: 20 -> 10 punti.** Connessioni passate da indirizzi interni,
  brevi e saltuarie sono compatibili con l'assistenza tecnica: pesano come il solo
  software installato, non come un'esposizione attiva. Resta un evento da attribuire.

## [5.3.0] — 2026-10-13

### Aggiunto

- **Lettura del registro locale di UltraVNC (accessi passati).** La presenza di un
  software di accesso remoto dice che l'accesso e' *possibile*; il suo registro
  (`winvnc.log`, `mslogon.log`, e gli eventi UltraVNC nel registro Applicazione di
  Windows) puo' dire se e' *avvenuto*. Nuovo modulo `UltraVncLogAnalyzer`.
  - Sola lettura: apertura con condivisione completa, nessun blocco, nessuna
    modifica, nessuna cancellazione. File grandi: letta solo la parte finale (8 MB).
  - Da ogni riga si estraggono solo ora, tipo di evento e indirizzo di origine; la
    riga non viene conservata (potrebbe contenere nomi di persone).
  - Loopback escluso; la stessa connessione in piu' fonti non e' sommata (massimo).
  - Impronta SHA-256 dei byte effettivamente letti, per la verifica da parte di terzi.
  - Punteggio: +20 ("PastRemoteAccessLog") solo se risultano connessioni non locali.
  - Report: nuova sezione con tre esiti distinti (connessioni trovate / file letto
    senza connessioni, che non prova l'assenza / file non leggibile / non trovato).
  - Lettere (`AVVIA_RICHIESTE`): nuovo segnaposto `{{REGISTRO_STRUMENTO}}`, con
    conteggio, indirizzi (max 10) e periodo, e richiesta di attribuzione.

### Limiti dichiarati

- I formati di riga sono verificati dal sorgente di UltraVNC e dalle indicazioni
  dell'autore; il formato dell'ora e il nome del provider nel registro eventi non
  sono verificati: l'ora e' riportata come scritta e interpretata solo se certa.
- Un registro vuoto, assente o ruotato non prova l'assenza di accessi; il file e'
  modificabile, quindi la sua integrita' non e' garantita.
- Non ancora provato su un PC Windows reale.

## [5.2.1] — 2026-10-13

Due correzioni emerse dal primo report reale della v5.2.0. Entrambe riguardavano
affermazioni che, in una richiesta formale, sarebbero state contestabili o false.

### Corretto

- **Le sessioni locali non sono accessi remoti.** I registri dei Servizi Desktop
  remoto (eventi 21/24/25 del LocalSessionManager) registrano anche gli accessi
  dell'utente alla console del proprio PC, con origine "LOCAL" (in italiano
  "LOCALE"). La v5.2.0 li contava come accessi remoti: sul PC di prova segnalava
  "9 accessi remoti negli ultimi 30 giorni", che erano invece i normali accessi
  quotidiani dell'utente, e attribuiva 15 punti. Ora le sessioni con origine
  locale (LOCAL/LOCALE, loopback) sono escluse dal conteggio e dal punteggio e
  riportate a parte come sessioni locali. Un indirizzo di origine vuoto NON e'
  considerato locale, per non nascondere un possibile accesso remoto.
- **Il report non afferma piu' che l'utente non ha privilegi amministrativi se non
  e' accertato.** "Non elevato" non significa "senza diritti di amministratore":
  con il Controllo account utente un amministratore gira con un token ridotto.
  La lettera al DPO dichiarava comunque di non disporre di privilegi, e questo
  sarebbe stato falso per chi e' membro del gruppo Amministratori. Ora il
  programma verifica l'appartenenza al gruppo (SID S-1-5-32-544, presente nel
  token anche se ridotto): la dichiarazione compare solo quando l'appartenenza e'
  esclusa; altrimenti la lettera riporta un segnaposto "DA COMPLETARE SOLO SE
  VERO". Vale per il modello nel report e per `AVVIA_RICHIESTE`.
- Date degli eventi in formato ISO (prima in formato statunitense).
- 12 nuovi test automatici.

## [5.2.0] — 2026-10-13

Versione dedicata a chi **non ha privilegi di amministratore** sulla postazione,
cioè la condizione normale di un dipendente. L'assenza di privilegi non viene
più trattata soltanto come un limite della scansione: diventa un elemento di
fatto da dichiarare, e si recupera il massimo dei dati ottenibili senza di essi.

### Aggiunto

- **Nuovo modulo `RemoteToolConfig.psm1`**: legge la configurazione degli
  strumenti di accesso remoto senza privilegi elevati e risponde in chiaro alla
  domanda *quando qualcuno si collega, ti viene chiesto il consenso?* Per
  UltraVNC le impostazioni sono interpretate secondo la documentazione ufficiale
  del produttore (QuerySetting, QueryAccept, QueryIfNoLogon, AuthHosts,
  DisableTrayIcon, InputsEnabled, LocalInputsDisabled, BlankMonitorEnabled,
  FileTransferEnabled, MSLogonRequired, LoopbackOnly, IdleTimeout,
  AllowProperties, AllowShutdown, DebugLevel, PortNumber, UseRegistry,
  service_commandline). Rilevata la **connessione inversa** (`-connect`): il PC
  configurato per contattare attivamente un indirizzo prestabilito. Per
  TightVNC, RealVNC, TeamViewer e AnyDesk i valori sono riportati senza
  interpretazione.
- **Nuova sezione di report "Come è configurato l'accesso remoto"**: valore
  grezzo di ogni impostazione, funzione secondo la documentazione del produttore
  e conseguenza pratica, perché l'interpretazione sia verificabile e non da
  accettare.
- **Cronologia degli accessi Desktop remoto senza privilegi di amministratore**
  (`Get-DVRdpOperationalEvents`): letti i registri operativi dei Servizi Desktop
  remoto (1149 di RemoteConnectionManager; 21, 24, 25 di LocalSessionManager),
  che in molte configurazioni sono accessibili da utente standard a differenza
  del registro di sicurezza. Distinti i tre casi — canale vuoto, canale con
  eventi, canale inaccessibile — perché hanno significati opposti.
- **Nuova sezione "Verifica eseguita senza privilegi di amministratore"**: spiega
  perché l'assenza di privilegi esclude che l'utente possa aver installato lo
  strumento, colloca i registri nella disponibilità esclusiva del titolare ed
  esclude che la configurazione sia imputabile all'utente.
- Il **modello di richiesta al DPO** riporta l'esito della configurazione del
  consenso, l'assenza di privilegi amministrativi dello scrivente e due nuove
  richieste: se la configurazione preveda un avviso all'utente e, in caso
  negativo, per quali ragioni; chi detiene i privilegi amministrativi sulla
  postazione e con quale atto.
- 24 nuovi test automatici (`tests/RemoteToolConfig.Tests.ps1`).

### Sicurezza

- **Le credenziali degli strumenti di accesso remoto non vengono mai riportate.**
  I file di configurazione (`ultravnc.ini`, chiavi di registro di TightVNC e
  RealVNC, `service.conf` di AnyDesk) contengono le password di accesso, spesso
  con cifrature reversibili (DES con chiave fissa e nota). Un report destinato a
  essere allegato a una PEC o consegnato a terzi non deve divulgarle. Per ogni
  impostazione il cui nome indica una credenziale (`passwd`, `Password`,
  `Pwd`, `secret`, `token`, ...) il report dichiara soltanto se e' valorizzata,
  mai il valore. Vale anche per il JSON incorporato. 8 test dedicati, tra cui
  la verifica che una password finta non compaia nel JSON esportato.

### Modificato

- Il punteggio considera la configurazione dell'accesso remoto, ma **solo** per
  le impostazioni che indicano assenza di consenso od occultamento (15 punti
  ciascuna; 25 per la connessione inversa). Un'installazione con impostazioni
  predefinite aggiunge zero punti: le altre caratteristiche descrivono quanto è
  invasivo uno strumento già conteggiato e sono riportate senza punteggio.
- Gli accessi letti dai registri operativi non si sommano a quelli del registro
  di sicurezza quando entrambi sono disponibili: è il medesimo fatto.

## [5.1.3] — 2026-10-13

Correzioni di due inesattezze nella sezione "Metodo e perimetro", emerse dal
primo report reale prodotto dalla v5.1.2. Erano errori di dato dichiarato: in un
documento che chiede di essere verificato da un terzo, un numero sbagliato costa
piu' di una funzione mancante.

- **Corretto**: il numero di versione dello strumento non compariva (la sezione
  veniva costruita prima che la configurazione fosse disponibile).
- **Corretto**: il numero di regole di rilevamento indicava 4 invece di 75,
  perche' leggeva `.Count` su una hashtable (numero di chiavi) anziche' i campi
  `Loaded` e `SourceCount`. Dichiarato anche il caso del database interno di
  riserva.
- 3 nuovi test automatici a copertura di entrambi i casi.

## [5.1.2] — 2026-10-13

Versione dedicata alla **difendibilità tecnica del report**: l'obiettivo non è
alzare il punteggio, ma togliere all'altra parte ogni appiglio per liquidare il
documento come allarmistico o approssimativo.

### Aggiunto

- **Sezione "Come è stato calcolato il punteggio"**: una riga per ogni punto
  attribuito, con regola applicata, fonte tecnica del dato, stato del fatto
  (presenza / esposizione in rete / sessione attiva / storico) e ciò che il
  rilievo non dimostra. La somma della colonna corrisponde esattamente al
  punteggio in testa al report.
- **Sezione "Metodo e perimetro della verifica"**: catalogo dei 16 controlli
  previsti con la fonte tecnica di ciascuno, l'esito (eseguito / parziale) e il
  limite dichiarato. I controlli non eseguibili senza privilegi elevati sono
  elencati come parziali, non omessi.
- **Attribuzione delle porte al processo che le detiene** (`OwningProcess` →
  nome, PID e percorso dell'eseguibile): è il collegamento che rende il rilievo
  verificabile. Nuova funzione `Resolve-DVPortOwner`.
- Rilevazione delle **sessioni di accesso remoto attive** come voce di punteggio
  a sé (40 punti): un evento, non una possibilità.
- Il livello di rischio è accompagnato dal suo significato esplicito.
- 31 nuovi test automatici (`tests/ThreatScore.Tests.ps1`, `tests/NetworkAnalyzer.Tests.ps1`).

### Modificato

- **Nuovo modello di calcolo DV-SCORE-2.** Un medesimo fatto non viene più
  conteggiato più volte: la porta di un software già rilevato vale solo
  l'esposizione in rete (10 punti) invece di sommarsi per intero; il software
  installato che corrisponde a un processo già conteggiato vale 0 punti ed è
  riportato come conferma documentale. Quando la correlazione non è verificabile
  (percorso non leggibile senza privilegi elevati) la voce non attribuisce punti
  e lo dichiara, per non gonfiare il risultato.
- **Soglie riviste**: ALTO da 50, CRITICO da 80. CRITICO è ora riservato a una
  sessione attiva o a indicatori di sorveglianza, non alla semplice presenza di
  uno strumento di assistenza remota.
- **Modello di richiesta al DPO riscritto**: elenca i fatti effettivamente
  rilevati con il riferimento della riga nella tabella di calcolo, dichiara se la
  scansione era parziale e lascia come segnaposto da compilare ciò che il
  programma non può verificare (categorie di dati trattati, strumenti in uso).
  Aggiunte le richieste su valutazione d'impatto (Art. 35) e tempi di
  conservazione; aggiunta la precisazione che l'istanza non contiene addebiti.
- L'intestazione del report riporta la versione effettiva (prima era fissa a v5.0).

## [5.1.1] — 2026-10-13

Correzioni emerse dalla prima esecuzione reale su Windows.

- **Corretto**: il controllo "Processi con librerie video" risultava FALLITO sui PC senza webcam.
- **Corretto**: le porte in ascolto non venivano mai riconosciute (porta UInt16 contro chiavi Int32); ora 3389, 5900 ecc. sono segnalate, le porte standard di Windows (135/139/445) no.
- **Corretto**: piu' processi dello stesso software (es. due winvnc) contavano piu' volte nel punteggio.
- **Modificato**: testi del report resi neutri (niente affermazioni di illegalita'); la lettera al DPO usa "un mese" (Art. 12 par. 3) e rimanda ad AVVIA_RICHIESTE.bat.

## [5.1.0] — 2026-10-13

Versione dedicata a due cose: **correggere difetti che rendevano vuoti i controlli
audio/video e gonfiavano il punteggio**, e dare all'utente il passo che segue una
segnalazione, cioè **chiedere chiarimenti formali con un termine di legge**.

### Corretto

- **Controlli audio/video mai eseguiti.** `Invoke-WithTimeout` usava `Start-Job`,
  che avvia un processo separato nel quale le funzioni del modulo non esistono:
  ogni controllo falliva in silenzio e il report mostrava dati vuoti (permessi
  `null`, nessuna cronologia). Sostituito da `Invoke-DVCheck` (runspace nello
  stesso processo, con ripiego sull'esecuzione diretta).
- **Rilevamento di dispositivi audio/video virtuali.** `($x -or '').ToLower()`
  in PowerShell restituisce un booleano: l'errore veniva ignorato e l'elenco
  risultava sempre vuoto.
- **Durata d'uso del microfono** calcolata con un `TrimEnd` su un'espressione
  regolare (non valida): ora formattata correttamente.
- **Falsi allarmi sulle porte Windows.** RPC (135), NetBIOS (139) e SMB (445)
  non sono più conteggiate come "pronto per il controllo remoto" (rischio LOW).
  Una connessione stabilita non dice più in modo assoluto "possono vedere il tuo
  schermo": ora distingue servizio standard, porta in ascolto e sessione su un
  canale di accesso remoto, sempre con la formula "da verificare".
- **Nessun "pulito" per un controllo fallito.** Ogni controllo audio/video ha un
  esito esplicito (OK / TIMEOUT / FALLITO), riportato nel report e nel JSON; un
  controllo non completato non viene mai letto come "nessun problema".
- **Microfono e webcam.** Il rilevamento "in uso adesso" usa il registro
  ConsentStore (`LastUsedTimeStop = 0`); caricare librerie audio non è più
  considerato prova di registrazione.
- **Testi legali** resi non assoluti: rimosso il riferimento a un provvedimento
  del Garante non verificabile ("sempre accordo sindacale") e l'affermazione che
  i dati siano "inutilizzabili"; la qualificazione come strumento di lavoro
  (art. 4, comma 2) dipende da funzioni e uso, da valutare caso per caso.
- Lettera al DPO nel report: segnaposto generico `[Nome dell'Ente]`.

### Aggiunto

- **Modulo Richieste** (`RequestManager.psm1`, `Richieste.ps1`,
  `AVVIA_RICHIESTE.bat`): prepara il testo di istanza al DPO (artt. 12, 13, 15
  GDPR; art. 4 L. 300/1970), sollecito, richiesta alla RSU, segnalazione
  all'Ispettorato, reclamo al Garante (art. 77 GDPR); calcola la scadenza
  (un mese di calendario per l'istanza, art. 12 par. 3), tiene un registro a hash
  concatenati e suggerisce il passo successivo. **Non invia nulla.**
- Segnalazione, a fine scansione, della possibilità di preparare le richieste.
- 55 nuovi test Pester (`SurveillanceDetector`, `NetworkAnalyzer`,
  `RequestManager`), tra cui test di regressione sui due bug sopra e un test che
  garantisce l'assenza di chiamate di rete nel modulo Richieste.

### Note

- I test nuovi sono scritti in sintassi Pester 5; la verifica locale è stata
  fatta con un esecutore minimo (Pester non era disponibile nell'ambiente di
  sviluppo): eseguire la suite completa in CI/Windows prima di pubblicare.
- Le funzioni specifiche di Windows (registro, `Get-PnpDevice`) vanno provate su
  una macchina Windows reale.

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

[5.1.0]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v5.1.0
[5.0.0]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v5.0.0
[4.2.0]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.2.0
[4.1.1]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.1.1
[4.1.0]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.1.0
[4.0.1]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.0.1
[4.0.0]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.0.0
