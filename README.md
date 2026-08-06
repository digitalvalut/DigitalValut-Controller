# DigitalValut Controller v4.2

[![CI](https://github.com/digitalvalut/DigitalValut-Controller/actions/workflows/ci.yml/badge.svg)](https://github.com/digitalvalut/DigitalValut-Controller/actions/workflows/ci.yml)
[![Licenza: GPL v3](https://img.shields.io/badge/Licenza-GPLv3-blue.svg)](LICENSE)
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

Vuoi solo un controllo veloce, o vuoi scegliere tu tra scansione rapida,
completa e verifica della catena di custodia? Usa rispettivamente
`AVVIA_SCANSIONE.bat` o `AVVIA_AVANZATO.bat` — entrambi opzionali, per chi
vuole più controllo.

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

| Punteggio | Livello  | Significato                                     |
|-----------|----------|--------------------------------------------------|
| 0         | SICURO   | Nessun elemento sospetto rilevato                 |
| 1–29      | BASSO    | Situazione normale                                |
| 30–59     | MEDIO    | Elementi da verificare                            |
| 60–99     | ALTO     | Rilevato software di controllo remoto/monitoraggio|
| 100+      | CRITICO  | Indicatori multipli di controllo o sorveglianza   |

Il punteggio è un **indicatore euristico**, non una misura oggettiva del rischio
reale: va interpretato leggendo il dettaglio delle voci segnalate.

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
Lavoratori (L. 300/1970), GDPR, Codice Privacy (D.Lgs. 196/2003), Provvedimento
del Garante Privacy 13/07/2016.

Le informazioni sono riportate a fine **esclusivamente informativo e
divulgativo**, possono non essere aggiornate e **non costituiscono consulenza
legale**. L'autore non è un avvocato. Per il caso concreto rivolgersi a un
professionista qualificato.

## Contribuire

Le contribuzioni sono benvenute: bug, falsi positivi/negativi, traduzioni,
documentazione. Vedi [`CONTRIBUTING.md`](CONTRIBUTING.md).

Per le vulnerabilità di sicurezza **non aprire una issue pubblica**: segui la
procedura in [`SECURITY.md`](SECURITY.md).

Le versioni modificate e ridistribuite devono restare open source sotto la
stessa licenza (GPLv3) e devono indicare chiaramente di essere state
modificate.

## Licenza

Distribuito sotto **GNU General Public License v3.0 (o successiva)** — vedi
[`LICENSE`](LICENSE) per il testo integrale e [`LICENZA.txt`](LICENZA.txt)
per una sintesi in italiano.

Copyright © 2024–2026 DigitalValut. Tutti i diritti d'autore e la paternità
dell'opera restano sempre in capo all'autore originale, come previsto dalla
licenza GPLv3: il software è donato all'uso libero di tutti, non ceduto.

## Autore

**DigitalValut** — [www.digitalvalut.it](https://www.digitalvalut.it)
Sviluppatore: **Dott. Giuseppe Falsone** e il team DigitalValut
Crypto-Forensics & Blockchain Security
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
