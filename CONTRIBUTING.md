# Come contribuire

Grazie per l'interesse verso DigitalValut Controller. I contributi sono
benvenuti: segnalazioni di bug, nuove firme di rilevamento, traduzioni,
miglioramenti alla documentazione.

## Prima di iniziare

Leggi [`DISCLAIMER.md`](DISCLAIMER.md) e [`LICENSE`](LICENSE). Contribuendo,
accetti che il tuo contributo sia distribuito sotto **GNU GPL v3.0 o
successiva**, alle stesse condizioni del resto del progetto.

Il progetto è mantenuto su base volontaria: le revisioni possono richiedere
tempo e non c'è garanzia che ogni proposta venga accolta.

## Segnalare un bug

Apri una [issue](https://github.com/digitalvalut/DigitalValut-Controller/issues)
includendo:

- versione di Windows e di PowerShell (`$PSVersionTable.PSVersion`);
- se l'esecuzione era con privilegi amministrativi;
- comportamento atteso e comportamento osservato;
- eventuali messaggi di errore.

> ⚠️ **Non allegare mai report generati contenenti dati reali.** I report
> includono nome macchina, nome utente, dominio, indirizzi IP ed elenco dei
> processi. Anonimizza sempre prima di condividere qualsiasi output.

## Segnalare un falso positivo o un falso negativo

Sono i contributi più utili. Indica il nome esatto del processo, servizio o
software, il produttore e il motivo per cui la classificazione è errata.
Le firme si trovano in [`core/modules/ThreatDatabase.psm1`](core/modules/ThreatDatabase.psm1).

## Vulnerabilità di sicurezza

**Non aprire una issue pubblica.** Segui la procedura descritta in
[`SECURITY.md`](SECURITY.md).

## Pull request

1. Fai un fork del repository e crea un branch descrittivo
   (`fix/rilevamento-anydesk`, `feat/traduzione-en`).
2. Mantieni lo stile del codice esistente: PowerShell 5.1 compatibile,
   nessuna dipendenza esterna, commenti in italiano.
3. **Non introdurre connessioni di rete in uscita.** Il funzionamento
   totalmente offline è un requisito architetturale non negoziabile del
   progetto: è ciò che ne rende verificabile la neutralità.
4. Non aggiungere binari precompilati, né file di report o dati reali.
5. Verifica che lo script si esegua correttamente sia con sia senza
   privilegi amministrativi.
6. Descrivi nella PR cosa cambia e perché.

## Principi del progetto

Ogni contributo deve rispettare la natura dello strumento:

- **Sola lettura**: il Software non modifica il sistema analizzato, non
  rimuove né disattiva alcun componente.
- **Nessuna telemetria**: nessun dato lascia la macchina dell'utente.
- **Difensivo, mai offensivo**: non saranno accettati contributi che
  aggiungano funzionalità di sorveglianza, di raccolta dati su terzi, di
  attacco o di elusione di controlli legittimi.
- **Onestà nelle affermazioni**: non saranno accettate modifiche che
  presentino i risultati come prova legale o perizia forense, o che
  sopravvalutino le capacità di rilevamento. Vedi la sezione 4 del
  [`DISCLAIMER.md`](DISCLAIMER.md).

## Traduzioni

La documentazione è in italiano, con una guida rapida in inglese
([`docs/README.txt`](docs/README.txt)). Traduzioni in altre lingue sono
benvenute; i riferimenti normativi sono specifici dell'ordinamento italiano
e vanno adattati o chiaramente contestualizzati.
