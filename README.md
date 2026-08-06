# DigitalValut Controller v4.0

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

Il risultato è un report HTML/JSON con punteggio di rischio (SICURO → CRITICO),
riferimenti normativi e un fac-simile di richiesta al DPO.

## Cosa NON fa (limiti dichiarati)

La trasparenza sui limiti fa parte dello strumento. Il Software **non** rileva
in modo affidabile: rootkit in kernel mode, bootkit, impianti a livello
firmware/UEFI, hypervisor malevoli, dispositivi hardware di intercettazione,
monitoraggio effettuato a livello di rete o su infrastruttura esterna al
dispositivo, né strumenti progettati specificamente per eludere l'analisi.

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
3. Doppio clic su `AVVIA_CONTROLLO.bat` (consigliato) o `AVVIA_SCANSIONE.bat`.
4. Attendi 30–90 secondi: il report si apre automaticamente nel browser.

### Se usi Git (metodo per professionisti/IT)

```bash
git clone https://github.com/digitalvalut/DigitalValut-Controller.git
```

Poi come sopra: doppio clic su `AVVIA_CONTROLLO.bat`.

I report generati vengono salvati in `Desktop\DigitalValut_Reports`.

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

Il meccanismo è **tamper-evident**: rende rilevabile un'alterazione accidentale
o non esperta. Non è una marca temporale certificata di terza parte (RFC 3161),
si basa sull'orologio locale ed è rigenerabile da un soggetto tecnicamente
competente. Non va presentato come garanzia di autenticità opponibile a terzi
(vedi [DISCLAIMER.md](DISCLAIMER.md), sezione 4).

## Struttura del progetto

```
DigitalValut-Controller/
├── AVVIA_CONTROLLO.bat       # Avvio principale
├── AVVIA_SCANSIONE.bat       # Avvio alternativo
├── core/
│   ├── DVController.ps1      # Script principale
│   ├── config/settings.json  # Lingua, apertura automatica del report
│   └── modules/              # Rete, processi, sorveglianza, report, custodia
├── docs/                     # Guida completa, riferimenti legali, quick guide
├── templates/                # Template HTML/CSS del report
├── DISCLAIMER.md             # Avvertenze e limiti (da leggere)
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
