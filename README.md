# DigitalValut Controller v4.0

> **Gratuito per sempre.** Un dono di [DigitalValut](https://www.digitalvalut.it)
> a tutti gli uffici pubblici e privati, ai lavoratori e a chiunque voglia
> tutelare la propria privacy digitale. Libero da scaricare e usare, per
> neofiti e professionisti.

Strumento portabile per la verifica di software di controllo remoto, spyware,
keylogger e sorveglianza audio/video non autorizzati su PC Windows.

Progettato per la **tutela dei lavoratori** secondo il GDPR (Reg. UE 2016/679)
e lo Statuto dei Lavoratori (Art. 4, L. 300/1970). Non installa nulla, non
modifica il sistema, non invia dati in rete: funziona anche da chiavetta USB.

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
riferimenti normativi e un modello di lettera per il DPO.

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

## Struttura del progetto

```
DigitalValut-Controller/
├── AVVIA_CONTROLLO.bat      # Avvio principale
├── AVVIA_SCANSIONE.bat      # Avvio alternativo
├── core/
│   ├── DVController.ps1     # Script principale
│   ├── config/settings.json # Lingua, percorso report, apertura automatica
│   └── modules/              # Moduli (rete, processi, report, sorveglianza...)
├── docs/                     # Guida completa, riferimenti legali, quick guide
├── templates/                 # Template HTML/CSS del report
├── CREDITS.txt
├── RIFERIMENTI_LEGALI.txt
└── LICENSE / LICENZA.txt
```

Guida dettagliata: [`docs/GUIDA_COMPLETA.txt`](docs/GUIDA_COMPLETA.txt).

## Interpretare il report

| Punteggio | Livello  | Significato                                   |
|-----------|----------|------------------------------------------------|
| 0         | SICURO   | Nessun elemento sospetto                        |
| 1–29      | BASSO    | Situazione normale                              |
| 30–59     | MEDIO    | Verificare i componenti segnalati               |
| 60–99     | ALTO     | Software di controllo remoto o monitoraggio     |
| 100+      | CRITICO  | Rischio elevato: spyware o sorveglianza attiva  |

## Privacy e trasparenza

- Nessun invio di dati in rete: tutto resta sul PC dell'utente.
- Nessun account o registrazione richiesti.
- Codice sorgente interamente leggibile (PowerShell puro, nessun binario
  precompilato oscurato).

## Riferimenti normativi

Vedi [`RIFERIMENTI_LEGALI.txt`](RIFERIMENTI_LEGALI.txt): Art. 4 Statuto dei
Lavoratori (L. 300/1970), GDPR, Codice Privacy (D.Lgs. 196/2003), Provvedimento
del Garante Privacy 13/07/2016. Le informazioni sono a scopo informativo e non
costituiscono consulenza legale.

## Contribuire

Le contribuzioni sono benvenute tramite issue e pull request. Le modifiche
distribuite devono restare open source con la stessa licenza (GPLv3), come
previsto dai termini della licenza.

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

Questo software è fornito "così com'è", senza garanzie di alcun tipo (vedi
LICENSE, sezioni 15–16). L'autore non è responsabile per interpretazioni dei
risultati o conseguenze legali derivanti dall'uso. Utilizzare solo su
dispositivi di cui si ha legittimo accesso o proprietà.
