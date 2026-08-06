# Security Policy

## Versioni supportate

| Versione | Supportata |
|----------|------------|
| 4.0.x    | ✅          |
| < 4.0    | ❌          |

Il progetto è mantenuto su base volontaria e gratuita: non è previsto alcun
SLA né alcun impegno vincolante sui tempi di risposta o di correzione.

## Segnalare una vulnerabilità

Se individui una vulnerabilità di sicurezza nel Software, ti chiediamo di
**non aprire una issue pubblica**.

Scrivi invece a **info@digitalvalut.com**, indicando:

- una descrizione della vulnerabilità e del suo impatto;
- i passaggi per riprodurla;
- la versione del Software e del sistema operativo;
- eventuali proposte di correzione.

Cercheremo di riscontrare le segnalazioni entro un tempo ragionevole,
compatibilmente con la natura volontaria del progetto. Ti chiediamo di
attendere la pubblicazione di una correzione prima di divulgare pubblicamente
i dettagli (*coordinated disclosure*).

## Ambito

**Rientrano** nell'ambito: esecuzione di codice non voluta, escalation di
privilegi, lettura o scrittura di file al di fuori delle cartelle previste,
esfiltrazione di dati, injection nei report generati.

**Non rientrano** nell'ambito, in quanto limiti noti e dichiarati in
[`DISCLAIMER.md`](DISCLAIMER.md): falsi positivi, falsi negativi, mancato
rilevamento di rootkit/bootkit/impianti firmware, aggirabilità della catena
di custodia locale, assenza di marcatura temporale certificata di terza parte.

## Verificabilità del codice

Il Software è interamente open source e scritto in PowerShell non offuscato:
chiunque può ispezionare il codice prima di eseguirlo. Non esistono binari
precompilati nel repository ufficiale.

Il Software **non effettua alcuna connessione di rete in uscita**. Se osservi
un comportamento difforme, segnalalo immediatamente all'indirizzo indicato
sopra: potrebbe indicare una copia manomessa, non proveniente dal repository
ufficiale.

**Repository ufficiale:** https://github.com/digitalvalut/DigitalValut-Controller

Diffida di copie distribuite tramite canali diversi: verifica sempre di aver
scaricato dal repository ufficiale.
