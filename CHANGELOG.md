# Changelog

Tutte le modifiche rilevanti a questo progetto sono documentate in questo file.

Il formato si ispira a [Keep a Changelog](https://keepachangelog.com/it/1.1.0/)
e il progetto adotta il [Versionamento Semantico](https://semver.org/lang/it/).

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

[4.0.1]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.0.1
[4.0.0]: https://github.com/digitalvalut/DigitalValut-Controller/releases/tag/v4.0.0
