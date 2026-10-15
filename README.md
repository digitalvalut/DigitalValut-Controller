# DigitalValut Controller v5.4.0

[![CI](https://github.com/digitalvalut/DigitalValut-Controller/actions/workflows/ci.yml/badge.svg)](https://github.com/digitalvalut/DigitalValut-Controller/actions/workflows/ci.yml)
[![Licenza: Apache 2.0](https://img.shields.io/badge/Licenza-Apache%202.0-blue.svg)](LICENSE)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE.svg)](https://learn.microsoft.com/powershell/)
[![Piattaforma: Windows](https://img.shields.io/badge/Piattaforma-Windows%2010%2F11-0078D6.svg)](#requisiti)
[![Nessuna telemetria](https://img.shields.io/badge/Telemetria-nessuna-success.svg)](#privacy-e-trasparenza)

> **Gratuito per sempre.** Un dono di [DigitalValut](https://www.digitalvalut.it)
> a tutti gli uffici pubblici e privati, ai lavoratori e a chiunque voglia
> tutelare la propria privacy digitale. Libero da scaricare e usare, per
> neofiti e professionisti.

Strumento portabile per la verifica di software di controllo remoto, spyware,
keylogger e sorveglianza audio/video non autorizzati su PC Windows.

Progettato per la **tutela dei lavoratori** secondo il GDPR (Reg. UE 2016/679)
e lo Statuto dei Lavoratori (Art. 4, L. 300/1970). Non installa nulla, non
modifica il sistema, non invia dati in rete: funziona anche da chiavetta USB.

> [!IMPORTANT]
> **Leggi prima di usarlo.** Il report prodotto è una **segnalazione tecnica di
> primo livello**, non una perizia informatica forense e non una prova legale.
> Può generare falsi positivi e falsi negativi. Prima di qualsiasi azione
> disciplinare, sindacale o giudiziaria, rivolgiti a un avvocato e a un perito
> informatico forense. Avvertenza integrale: **[DISCLAIMER.md](DISCLAIMER.md)**.

> [!TIP]
> **Devi documentare una situazione seria?** Leggi la
> **[Guida alla raccolta di documentazione](GUIDA_PROVE.md)**: spiega in tre
> livelli come passare da "ho un sospetto" a materiale datato da un'autorità
> terza e verificabile da chiunque.

## Cosa rileva

- Connessioni remote attive (RDP, VNC, TeamViewer, AnyDesk, ecc.)
- Porte in ascolto sospette e connessioni esterne attive
- Processi e servizi di controllo remoto o monitoraggio
- Programmi in avvio automatico
- Stato di antivirus e firewall
- **Sorveglianza audio/video**: uso di microfono e webcam, dispositivi audio
  virtuali (Virtual Audio Cable, VB-Audio, Voicemeeter, Stereo Mix), permessi
  privacy di Windows, indicatori di spyware audio
- **Firma digitale (Authenticode)** di ogni processo sospetto rilevato: distingue
  un eseguibile firmato da uno stesso nome ma non firmato o con firma non
  attendibile (elemento a supporto, non prova da solo — vedi DISCLAIMER.md)
- **Persistenza avanzata**: sottoscrizioni WMI permanenti non riconosciute,
  `AppInit_DLLs`, debugger IFEO (hijacking di eseguibili), task pianificati con
  pattern sospetti (comandi codificati, download remoti, percorsi temporanei)
- **DLL iniettate in processi legittimi**: molti strumenti di monitoraggio non
  girano come processo autonomo (visibile in Gestione attività) ma si iniettano
  come libreria dentro browser, Explorer o client di posta. Vengono segnalate le
  DLL caricate da cartelle temporanee o pubbliche, con verifica della firma
- **Analisi storica**: cosa è *successo* su questo PC, non solo cosa c'è adesso —
  servizi installati di recente, cancellazioni del registro di sicurezza, accessi
  remoti RDP. Un software di controllo può essere stato installato, usato e
  rimosso
- **Confronto con la scansione precedente**: cosa è cambiato — nuovi riscontri
  e riscontri risolti — rispetto all'ultima volta, letto dalla catena di custodia
- **Spiegazione in linguaggio semplice generata da AI locale** (opzionale): se
  hai [Ollama](https://ollama.com) installato sulla stessa macchina, il report
  include una spiegazione discorsiva dei risultati. Comunica solo con
  `127.0.0.1` (loopback): nessun dato lascia mai il PC. Se Ollama non è
  installato questa sezione è semplicemente assente — nessuna dipendenza
  obbligatoria. Disattivabile con `-DisableAI`.

Il risultato è un report HTML/JSON con punteggio di rischio (SICURO → CRITICO),
riferimenti normativi e un fac-simile di richiesta al DPO.

## 🛡️ Sentinella: registra gli eventi mentre accadono

Una scansione è una fotografia: se la connessione remota avviene alle 3 di
notte, una fotografia scattata di giorno non la vedrà mai.

**`AVVIA_SENTINELLA.bat`** resta in ascolto e registra le sessioni di controllo
remoto nel momento in cui si verificano, con orario di inizio, di fine e durata.

Si passa così da *"sul PC è installato un software di controllo remoto"*
(circostanza che ammette molte spiegazioni) a *"il 14 marzo, dalle 03:12 alle
03:59, sessione attiva dall'indirizzo 10.x.x.x, durata 47 minuti"* — un fatto
circostanziato.

Il registro usa hash concatenati: cancellare o modificare un evento passato
rompe la catena e viene rilevato.

## 📨 Richieste di chiarimento e scadenzario

Un report che segnala qualcosa è un punto di partenza, non una conclusione: il
passo corretto è **chiedere per iscritto spiegazioni a chi di dovere**. Il
titolare del trattamento ha l'obbligo di rispondere alle richieste
dell'interessato senza ingiustificato ritardo e al più tardi entro **un mese**
(art. 12, par. 3, GDPR; prorogabile solo con comunicazione motivata).

**`AVVIA_RICHIESTE.bat`** prepara il *testo* delle lettere a partire dall'ultimo
report e tiene il conto dei termini:

| Tipo | A chi | Base |
|---|---|---|
| `DPO-ISTANZA` | DPO dell'Ente | artt. 12, 13, 15 GDPR; art. 4 L. 300/1970 |
| `DPO-SOLLECITO` | DPO dell'Ente (10 giorni) | art. 12 GDPR |
| `RSU` | RSU / organizzazioni sindacali | art. 4 L. 300/1970 |
| `INL` | Ispettorato territoriale del lavoro | art. 4 L. 300/1970 (competenza da verificare per il pubblico impiego) |
| `GARANTE-RECLAMO` | Garante privacy | art. 77 GDPR; artt. 140-bis e 142 D.Lgs. 196/2003 |

Lo scadenzario ti dice cosa è **scaduto** e qual è il passo successivo
(istanza scaduta → sollecito → reclamo), con un registro a hash concatenati.

Scelte di progetto, volute:

- **Non invia nulla.** PEC e raccomandata le invii tu: il programma resta
  "offline" e nessuno può definirlo uno strumento di controllo.
- **Non accusa nessuno.** I testi sono richieste di chiarimento e dichiarano che
  il report è un segnale tecnico di primo livello, non una perizia.
- **Non è consulenza legale.** I modelli vanno fatti rivedere da un avvocato
  giuslavorista o dal sindacato. I punti da completare restano segnalati nel
  testo (`[DA COMPILARE]`, `[SCEGLIERE]`) per non spedire lettere incomplete.

## 🔒 Pacchetto prova con data certificata da terzi

**`CREA_PACCHETTO_PROVA.bat`** produce **un solo file .zip** da consegnare a un
avvocato o a un perito, contenente report, dati grezzi di sistema, registro
della Sentinella, catena di custodia — e due elementi che cambiano il peso del
materiale:

**Marca temporale RFC 3161.** Un'autorità terza certifica crittograficamente che
quel materiale esisteva già a quella data. Serve perché l'orologio del computer
è modificabile: senza certificazione esterna, la data vale quanto la parola di
chi la presenta. Il Regolamento eIDAS (UE 910/2014, art. 41) attribuisce alle
marche temporali *qualificate* una presunzione legale di accuratezza della data.

> **Privacy:** alla marcatrice temporale viene inviato **solo un hash SHA-256 di
> 32 byte**, da cui è computazionalmente impossibile risalire al contenuto.
> Nessun nome, nessun IP, nessun processo lascia il dispositivo. È l'unica
> funzione dello strumento che si collega a Internet, ed è **opt-in esplicita**.

**Verificatore autonomo.** Nel pacchetto c'è `VERIFICA_PROVA.bat`: chiunque lo
riceva — il legale della controparte, il consulente tecnico d'ufficio — può
verificare integrità e data **senza installare nulla e senza fidarsi di chi ha
prodotto il materiale**. Finora la verifica la faceva lo stesso programma che
aveva creato i file: un cerchio che si chiude su sé stesso e che in
contraddittorio non regge.

📖 Guida pratica completa: **[GUIDA_PROVE.md](GUIDA_PROVE.md)**

## Estendibile da chiunque, senza toccare il codice

Le firme di rilevamento **non sono scritte dentro il programma**: sono file
`.json` nella cartella `core/rules/`. Chiunque può aggiungere i propri
rilevamenti creando un file — senza saper programmare, senza modificare il
codice, senza dover chiedere niente a nessuno.

```json
{
  "id": "MIO-0001",
  "name": "Software da rilevare",
  "type": "process",
  "risk": "HIGH",
  "match": { "nameContains": ["nomeprocesso"] }
}
```

Metti il file in `core/rules/custom/`, rilancia la scansione, funziona.
Guida completa con esempi: **[RULES.md](RULES.md)**.

Tre garanzie di progetto su questo meccanismo:

- **Le regole sono solo dati, mai codice eseguibile.** Un file di regole
  scaricato da terzi non può eseguire comandi sul tuo PC. È una scelta di
  sicurezza deliberata.
- **Una regola scritta male non rompe niente**: viene ignorata, la scansione
  prosegue, e il report indica quale file e perché.
- **Se la cartella regole manca o è danneggiata**, lo strumento continua a
  funzionare con il database interno di riserva.

## Cosa NON fa (limiti dichiarati)

La trasparenza sui limiti fa parte dello strumento. Il Software **non** rileva
in modo affidabile: rootkit in kernel mode, bootkit, impianti a livello
firmware/UEFI, hypervisor malevoli, dispositivi hardware di intercettazione,
monitoraggio effettuato a livello di rete o su infrastruttura esterna al
dispositivo, né strumenti progettati specificamente per eludere l'analisi.

Sul rilevamento delle DLL iniettate: non vede le tecniche avanzate (*reflective
loading*, *manual mapping*), che non lasciano un modulo elencabile. Sull'analisi
storica: i registri eventi di Windows ruotano, quindi eventi più vecchi possono
essere già stati sovrascritti legittimamente, e senza privilegi di
amministratore il registro di sicurezza non è leggibile affatto (il report lo
dichiara apertamente quando succede).

Sulla **Sentinella**: campiona a intervalli, quindi una sessione più breve
dell'intervallo può non essere osservata; registra l'esistenza, l'origine e la
durata delle connessioni, **non il loro contenuto**; e quando non è in
esecuzione non vede nulla — i periodi scoperti sono dichiarati esplicitamente
nel report, senza fingere una copertura continua.

Sul **pacchetto prova**: non è un'acquisizione forense. I dati sono raccolti
dall'interno del sistema tramite le API di Windows; se il sistema fosse
compromesso a livello kernel, quelle stesse API potrebbero restituire dati
falsati. Un'acquisizione forense vera si esegue a sistema spento, con
write-blocker, da un perito qualificato.

**Un esito "SICURO" non dimostra l'assenza di sorveglianza**, così come la
segnalazione di un software non dimostra un uso illecito: gli strumenti di
assistenza remota possono essere legittimi, autorizzati e regolarmente
concordati. Il report è un punto di partenza per porre domande, non un verdetto.

## Requisiti

- Windows 10 (build 19042+) o Windows 11
- PowerShell 5.1 (incluso in Windows)
- Nessuna installazione richiesta; opzionale esecuzione come amministratore
  per analisi più complete

## Download e uso

Nessuna registrazione, nessun account, nessun costo: chiunque può scaricarlo
e usarlo, sia chi non ha mai usato GitHub sia chi lavora con Git ogni giorno.

### Se non conosci GitHub / Git (metodo più semplice)

1. Vai alla pagina **[Release](../../releases/latest)** di questo repository
   e scarica il file `.zip` in cima alla pagina (oppure in alto su questa
   pagina clicca il pulsante verde **"Code" → "Download ZIP"**).
2. Estrai lo ZIP su una chiavetta USB o sul Desktop.
3. Doppio clic su `AVVIA_CONTROLLO.bat`. **Non c'è nessuna scelta da fare**: la
   scansione parte da sola.
4. Attendi 30–90 secondi: il report si apre automaticamente nel browser.

### I pulsanti, in ordine di potenza

| File | Cosa fa | Quando usarlo |
|---|---|---|
| **`AVVIA_CONTROLLO.bat`** | Scansione completa, nessuna scelta da fare | Sempre, per iniziare |
| **`AVVIA_SENTINELLA.bat`** | Registra le connessioni remote **mentre accadono** | Se sospetti qualcosa: lascialo attivo per giorni |
| **`CREA_PACCHETTO_PROVA.bat`** | Un solo .zip sigillato e datato da terzi, da consegnare a un avvocato | Quando hai raccolto abbastanza |
| **`AVVIA_RICHIESTE.bat`** | Prepara le lettere di chiarimento (DPO, RSU, Ispettorato, Garante) e tiene le scadenze | Dopo una segnalazione del report |
| **`VERIFICA_PROVA.bat`** | Verifica un pacchetto ricevuto, senza fidarsi di chi l'ha creato | Lo usa il destinatario |

Restano disponibili `AVVIA_SCANSIONE.bat` (rapida, un click) e
`AVVIA_AVANZATO.bat` (menu con opzioni) per chi vuole più controllo.

📖 Non sai da dove partire in una situazione seria? **[GUIDA_PROVE.md](GUIDA_PROVE.md)**

### Se usi Git (metodo per professionisti/IT)

```bash
git clone https://github.com/digitalvalut/DigitalValut-Controller.git
```

Poi come sopra: doppio clic su `AVVIA_CONTROLLO.bat`.

I report generati vengono salvati in `Desktop\DigitalValut_Reports`.

### Verifica dell'integrità del download (consigliata per ambienti PA/aziendali)

Ogni [release](../../releases) pubblica, insieme allo ZIP, un file `SHA256SUMS.txt`
con l'hash SHA-256 del pacchetto. Per verificare che il file scaricato sia
integro e non alterato:

```powershell
Get-FileHash -Algorithm SHA256 -Path .\DigitalValut-Controller-vX.Y.Z.zip
```

Confronta l'hash ottenuto con quello indicato in `SHA256SUMS.txt` nella stessa
release: devono coincidere esattamente.

### Per uffici pubblici e privati

Lo strumento è pensato anche per un utilizzo su larga scala (PA, aziende,
RSU/sindacati, DPO): può essere distribuito su USB o rete interna a più
postazioni senza bisogno di installazione né privilegi particolari, e senza
alcun costo di licenza.

> [!WARNING]
> **Se esegui il Software su una postazione aziendale o della PA**, verifica
> prima la conformità ai regolamenti informatici interni della tua
> organizzazione. L'esecuzione di software non autorizzato può costituire
> violazione delle policy interne, con possibili conseguenze disciplinari.
> È una responsabilità dell'utente, non dell'autore.

### Per la Pubblica Amministrazione

Una guida pensata per DPO, responsabili dei sistemi informativi, RSU e uffici
del personale è in [`docs/PUBBLICA_AMMINISTRAZIONE.md`](docs/PUBBLICA_AMMINISTRAZIONE.md):
come usare lo strumento per l'autoverifica dell'ente, come rispondere a una
richiesta di un dipendente e quali documenti preparare.

## Verifica della catena di custodia

Ogni report viene registrato in `chain_of_custody.jsonl` con hash SHA-256 e
concatenamento al record precedente. Per verificare che i report non siano
stati alterati dopo la generazione:

```bash
powershell -ExecutionPolicy Bypass -File core\DVController.ps1 -VerifyChain
```

(oppure, senza riga di comando: doppio clic su `AVVIA_AVANZATO.bat` → opzione 3)

Il meccanismo è **tamper-evident**: rende rilevabile un'alterazione accidentale
o non esperta. Non è una marca temporale certificata di terza parte (RFC 3161),
si basa sull'orologio locale ed è rigenerabile da un soggetto tecnicamente
competente. Non va presentato come garanzia di autenticità opponibile a terzi
(vedi [DISCLAIMER.md](DISCLAIMER.md), sezione 4).

## AI locale (opzionale) via Ollama

Se hai [Ollama](https://ollama.com) installato e in esecuzione sulla stessa
macchina, il report include automaticamente una spiegazione in linguaggio
semplice dei risultati, generata da un modello che gira **in locale**.

- L'unico endpoint contattato è `http://127.0.0.1:11434` (loopback): il
  traffico non esce mai dal dispositivo, non è una connessione Internet.
- Se Ollama non è installato o non è in esecuzione, questa sezione è
  semplicemente assente: nessun errore, nessuna dipendenza obbligatoria,
  nessun rallentamento oltre un controllo di disponibilità di 2 secondi.
- Per disattivarla esplicitamente anche quando Ollama è presente:
  ```bash
  powershell -ExecutionPolicy Bypass -File core\DVController.ps1 -DisableAI
  ```
- Il testo generato dall'AI è dichiarato come tale nel report e non sostituisce
  le sezioni tecniche né un parere legale: può contenere imprecisioni.

## Qualità e affidabilità del codice

- **93 test automatici** (Pester): motore delle regole, hash e catena di
  custodia, calcolo del punteggio di rischio, persistenza, firma digitale,
  DLL iniettate, analisi eventi — vedi [`tests/`](tests/).
- **Lint automatico** (PSScriptAnalyzer) su ogni push/PR, configurazione in
  [`PSScriptAnalyzerSettings.psd1`](PSScriptAnalyzerSettings.psd1).
- **CI su GitHub Actions**: sintassi, lint e test eseguiti automaticamente a
  ogni modifica — vedi il badge in cima a questa pagina o la scheda
  [Actions](../../actions) del repository.
- Codice sorgente interamente leggibile, nessun binario precompilato nel
  repository ufficiale.

## Struttura del progetto

```
DigitalValut-Controller/
├── AVVIA_CONTROLLO.bat       # Avvio principale: doppio clic, nessuna scelta
├── AVVIA_SENTINELLA.bat      # ⭐ Monitoraggio continuo: registra gli eventi
├── CREA_PACCHETTO_PROVA.bat  # ⭐ Pacchetto sigillato + marca temporale
├── AVVIA_RICHIESTE.bat       # ⭐ Lettere di chiarimento + scadenzario (non invia nulla)
├── VERIFICA_PROVA.bat/.ps1   # ⭐ Verificatore autonomo (per chi riceve)
├── AVVIA_SCANSIONE.bat       # Scansione rapida, un solo click
├── AVVIA_AVANZATO.bat        # Menu con opzioni (per chi vuole scegliere)
├── core/
│   ├── DVController.ps1      # Script principale
│   ├── config/settings.json  # Lingua, apertura automatica del report
│   ├── rules/                # ⭐ Regole di rilevamento (file .json)
│   │   └── custom/           #    Le TUE regole: vedi RULES.md
│   └── modules/              # Rete, processi, sorveglianza, persistenza,
│                             # firma digitale, DLL, eventi, AI locale,
│                             # motore regole, report, catena di custodia
├── tests/                    # Suite di test Pester (93 test)
├── scripts/                  # Strumenti di release (pacchetto + checksum)
├── .github/workflows/        # CI (lint + test automatici)
├── docs/                     # Guida completa, riferimenti legali, quick guide
├── templates/                # Template HTML/CSS del report
├── DISCLAIMER.md             # Avvertenze e limiti (da leggere)
├── GUIDA_PROVE.md            # Come raccogliere documentazione utilizzabile
├── RULES.md                  # Come scrivere le tue regole di rilevamento
├── SECURITY.md               # Segnalazione vulnerabilità
├── CONTRIBUTING.md           # Linee guida per i contributi
├── CHANGELOG.md              # Cronologia delle versioni
├── CREDITS.txt
├── RIFERIMENTI_LEGALI.txt
└── LICENSE / LICENZA.txt
```

Guida dettagliata: [`docs/GUIDA_COMPLETA.txt`](docs/GUIDA_COMPLETA.txt).

## Interpretare il report

Modello di calcolo: **DV-SCORE-2** (dalla v5.1.2).

| Punteggio | Livello  | Significato                                                                 |
|-----------|----------|------------------------------------------------------------------------------|
| 0         | SICURO   | Nessun indicatore rilevato dai controlli eseguiti                            |
| 1–24      | BASSO    | Indicatori marginali, in genere configurazioni ordinarie                     |
| 25–49     | MEDIO    | Elementi da verificare, nessun segno di accesso in corso                     |
| 50–79     | ALTO     | Strumenti di accesso remoto presenti e/o esposti in rete, nessuna sessione attiva |
| 80+       | CRITICO  | Sessione di accesso remoto attiva, oppure indicatori di sorveglianza         |

Il punteggio è un **indicatore euristico**, non una misura oggettiva del rischio
reale: va interpretato leggendo il dettaglio delle voci segnalate.

### Perché il punteggio è verificabile

Ogni report contiene la sezione **"Come è stato calcolato il punteggio"**: una riga
per ogni punto attribuito, con la regola applicata, la fonte tecnica del dato
(quale comando lo ha prodotto), lo stato del fatto e ciò che il rilievo **non**
dimostra. La somma della colonna dei punti è esattamente il punteggio mostrato in
testa al report, così un terzo (DPO, perito, giudice) può rifare il conto e
contestare una singola riga invece del risultato nel suo complesso.

Due principi del modello DV-SCORE-2:

1. **Un fatto non si conta due volte.** Se la porta 5900 è tenuta aperta dallo
   stesso software di controllo remoto già rilevato come processo, non è un
   secondo fatto: è la conferma del primo e pesa solo per l'esposizione in rete
   che aggiunge. Il doppio conteggio gonfia il risultato senza aggiungere prove
   ed è il difetto più facile da contestare in un report tecnico.
2. **La possibilità pesa meno dell'evento.** Un software installato pesa meno di
   un processo in esecuzione, che pesa meno di una porta esposta, che pesa meno
   di una sessione di accesso remoto in corso. Il livello CRITICO è riservato a
   ciò che è avvenuto, non a ciò che potrebbe avvenire.

Pesi e soglie sono definiti nel codice (`core/modules/ReportGenerator.psm1`,
`$script:DVScoreWeights` e `$script:DVScoreThresholds`), riportati per esteso in
fondo alla sezione del report e modificabili da chiunque (Apache 2.0).

### Come è configurato l'accesso remoto (dalla v5.2.0)

Sapere che un software di accesso remoto è installato dice poco. Cambia tutto
sapere **come è configurato**: se all'utente compare una richiesta di consenso
prima che qualcuno entri, se l'icona che segnala il server attivo è nascosta, se
è possibile prelevare file, se il PC è configurato per contattare attivamente un
indirizzo prestabilito (connessione inversa). Un'assistenza tecnica richiesta
dall'utente e un accesso silenzioso sono due fatti giuridicamente diversi anche
quando il programma è lo stesso.

Questa lettura **non richiede privilegi di amministratore**, perché i file di
configurazione in `Program Files` sono leggibili da qualunque utente. È quindi
l'informazione più rilevante a cui un dipendente senza privilegi può arrivare da
solo.

Il report risponde alla domanda in chiaro — *quando qualcuno si collega, ti viene
chiesto il consenso?* — con tre esiti possibili: previsto, non previsto, non
determinabile. L'ultimo non è una resa: quando il file non consente di stabilirlo
con certezza, il report lo dichiara e indica il punto da chiedere al servizio
informatico, invece di affermare ciò che non può dimostrare.

Ogni impostazione è riportata con il valore grezzo letto dal file, la sua
funzione secondo la documentazione ufficiale del produttore e la conseguenza
pratica. Pesano sul punteggio **solo** le impostazioni che indicano assenza di
consenso od occultamento (nessuna richiesta all'utente, icona nascosta,
connessione inversa): le altre caratteristiche sono riportate senza attribuire
punti, perché descrivono quanto è invasivo uno strumento già conteggiato e non
sono un fatto ulteriore. Un'installazione con impostazioni predefinite aggiunge
**zero punti**.

Attualmente interpretato: UltraVNC (semantiche da
[uvnc.com](https://uvnc.com/docs/ultravnc-server/69-ultravnc-ini.html)). Per
TightVNC, RealVNC, TeamViewer e AnyDesk i valori di configurazione sono riportati
**senza interpretazione**, perché il significato di ciascuna chiave va verificato
nella documentazione del rispettivo produttore.

### Se non hai privilegi di amministratore

Molti dipendenti non sono amministratori della postazione assegnata. Il registro
di sicurezza di Windows, che documenta gli accessi remoti, richiede quei
privilegi. Dalla v5.2.0 il programma tenta comunque i **registri operativi dei
Servizi Desktop remoto**, che in molte configurazioni sono leggibili da utente
standard e contengono lo stesso dato essenziale: chi si è collegato, quando e da
quale indirizzo.

| Canale | Eventi |
|--------|--------|
| `TerminalServices-RemoteConnectionManager/Operational` | 1149 (autenticazione riuscita, con indirizzo di origine) |
| `TerminalServices-LocalSessionManager/Operational` | 21, 24, 25 (accesso, disconnessione, riconnessione) |

Il report distingue tre casi, perché hanno significati opposti: canale letto e
vuoto (dato positivo verificato), canale letto con eventi (cronologia degli
accessi), canale non accessibile (il dato esiste ma è nella disponibilità
esclusiva del titolare, e può essere richiesto formalmente).

Il report include inoltre una sezione che spiega perché l'assenza di privilegi è
**essa stessa un elemento di fatto rilevante**: esclude che l'utente possa aver
installato lo strumento, colloca i log nella disponibilità esclusiva del
titolare, ed esclude che la configurazione sia imputabile all'utente. Le stesse
circostanze sono riportate nel modello di richiesta al DPO.

### Metodo e perimetro

Ogni report contiene la sezione **"Metodo e perimetro della verifica"**, che
elenca tutti i controlli previsti con la fonte tecnica di ciascuno, l'esito
(eseguito o parziale) e il limite dichiarato. Un controllo che non è stato
possibile eseguire — tipicamente perché richiede privilegi di amministratore —
viene **elencato come parziale, non omesso**: dichiarare per primi i limiti di
una verifica è ciò che le toglie l'argomento più comodo per liquidarla.

## Privacy e trasparenza

- **Nessun invio di dati in rete**: tutto resta sul PC dell'utente, il Software
  non effettua alcuna connessione in uscita e funziona anche offline.
- Nessun account, registrazione o attivazione richiesti.
- Codice sorgente interamente leggibile (PowerShell non offuscato, nessun
  binario precompilato nel repository ufficiale): chiunque può verificare cosa
  fa il Software prima di eseguirlo.
- I report restano in locale. **Contengono dati identificativi** (nome macchina,
  nome utente, dominio, IP, elenco processi): valutane la natura prima di
  condividerli con terzi.

## Riferimenti normativi

Vedi [`RIFERIMENTI_LEGALI.txt`](RIFERIMENTI_LEGALI.txt): Art. 4 Statuto dei
Lavoratori (L. 300/1970), GDPR, Codice Privacy (D.Lgs. 196/2003), Linee guida
del Garante Privacy su posta elettronica e Internet (1 marzo 2007).

Le informazioni sono riportate a fine **esclusivamente informativo e
divulgativo**, possono non essere aggiornate e **non costituiscono consulenza
legale**. L'autore non è un avvocato. Per il caso concreto rivolgersi a un
professionista qualificato.

## Contribuire

Le contribuzioni sono benvenute: bug, falsi positivi/negativi, traduzioni,
documentazione. Vedi [`CONTRIBUTING.md`](CONTRIBUTING.md).

Per le vulnerabilità di sicurezza **non aprire una issue pubblica**: segui la
procedura in [`SECURITY.md`](SECURITY.md).

Le versioni modificate e ridistribuite devono conservare licenza e file
`NOTICE` e indicare chiaramente le modifiche apportate (Apache 2.0, sezione 4).

## Licenza

Distribuito sotto **Licenza Apache, Versione 2.0** — vedi [`LICENSE`](LICENSE)
per il testo integrale, [`NOTICE`](NOTICE) per titolare e sedi e
[`LICENZA.txt`](LICENZA.txt) per una sintesi in italiano.

Copyright © 2024–2026 **Digital Valut APS** (CF 90036980846). Uso, copia,
modifica e ridistribuzione sono liberi, anche in uffici pubblici e aziende,
senza costi di licenza. La licenza è permissiva: non obbliga a pubblicare le
modifiche, ma richiede di conservare licenza e `NOTICE` e di indicare le
modifiche. Le versioni fino alla 5.3.1 restano disponibili anche sotto GPLv3
per chi le ha già ricevute.

## Autore

**Digital Valut APS** — [www.digitalvalut.it](https://www.digitalvalut.it) · CF 90036980846
Presidente e sviluppatore: **Dott. Giuseppe Falsone**
Sedi: Gardone Val Trompia (BS), via G. Matteotti · Canicattì (AG), Piazza Palermo 4 ·
Caltanissetta, Via della Regione 4 (sede commerciale)
info@digitalvalut.com

## Disclaimer

Questo software è fornito **"COSÌ COM'È" ("AS IS")**, a titolo gratuito e senza
garanzie di alcun tipo, esplicite o implicite (vedi [`LICENSE`](LICENSE),
sezioni 15–17).

Nella misura massima consentita dalla legge, l'autore non risponde di alcun
danno diretto o indiretto derivante dall'uso del Software o dei suoi report, né
di conseguenze disciplinari, amministrative, civili o penali di azioni
intraprese sulla base di essi. Restano ferme le responsabilità inderogabili per
dolo o colpa grave (art. 1229 c.c.) e i diritti inderogabili dei consumatori.

L'utente è unico responsabile dell'uso che fa dello strumento ed è tenuto a
utilizzarlo **solo su dispositivi di cui abbia la proprietà o un legittimo
diritto di accesso**, nel rispetto delle policy della propria organizzazione.

📄 **Avvertenza integrale e vincolante: [`DISCLAIMER.md`](DISCLAIMER.md)** —
parte integrante delle condizioni d'uso del Software.
