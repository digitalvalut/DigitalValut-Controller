# Guida per la Pubblica Amministrazione

Per DPO, responsabili dei sistemi informativi, uffici del personale, RSU e
sindacati. Questo strumento è offerto da **Digital Valut APS** (CF 90036980846)
con **Licenza Apache 2.0**: uso libero, senza costi, senza telemetria.

> Non è consulenza legale e non è una perizia. È una segnalazione tecnica di
> primo livello: va letta con il DPO e, se serve, con un legale e un perito
> informatico forense.

## A cosa serve a un ente

1. **Autoverifica delle postazioni.** Mostra quali software di accesso remoto
   o di monitoraggio sono presenti su un PC, se le porte di accesso sono
   aperte, chi le tiene aperte, come sono configurati (richiesta di consenso,
   icona visibile, trasferimento file) e, se il registro del programma è
   leggibile, quante sessioni remote risultano passate.
2. **Prepararsi a una richiesta di un dipendente.** Un dipendente può usare lo
   strumento sul proprio PC e chiedere chiarimenti al DPO (art. 15 GDPR). Se
   l'ente ha già fatto la verifica, la risposta è pronta e documentata.
3. **Documentare la conformità.** L'esito può alimentare il registro dei
   trattamenti (art. 30 GDPR), la valutazione d'impatto (art. 35) e le misure
   di sicurezza (art. 32). Non li sostituisce.

## Perché conta (in breve)

I lavoratori della PA sono soggetti anche alla disciplina dei controlli a
distanza (art. 4 L. 300/1970; per il pubblico impiego vedi l'art. 2, comma 2,
D.Lgs. 165/2001). Un software di assistenza remota è lecito e utile; diventa
un problema se manca l'informativa, la base giuridica o, quando richiesto,
l'accordo sindacale o l'autorizzazione dell'Ispettorato. La domanda non è
"c'è un programma?", ma **"chi, perché, con quale autorizzazione, con quale
informativa"**.

## Come usarlo in ufficio

- **Una postazione:** `AVVIA_CONTROLLO.bat` (nessuna installazione). Senza
  diritti di amministratore alcune verifiche sono parziali: il report lo
  dichiara. Con i diritti, il perimetro è completo.
- **Più postazioni:** copia la cartella su chiavetta o su rete interna e
  lancia il controllo su ciascun PC; raccogli i report HTML. Verifica prima
  il regolamento informatico interno: eseguire software non autorizzato può
  violare le policy dell'ente.
- **Integrità del download:** confronta l'hash SHA-256 con `SHA256SUMS.txt`
  della release.
- **Nessun dato esce dal PC.** Il programma non invia nulla in rete: l'invio
  di richieste resta un atto della persona.

## Se un dipendente ti scrive: cosa preparare

Una risposta completa documenta, per ciascun strumento di accesso remoto:

| Domanda del dipendente | Cosa deve poter produrre l'ente |
|---|---|
| Esiste un'informativa? | Copia dell'informativa (art. 13 GDPR) con finalità e destinatari |
| Su quale base? | Base giuridica (art. 6 GDPR) e finalità |
| Serve un accordo? | Accordo collettivo o autorizzazione INL (art. 4, c. 1), oppure le ragioni per cui lo strumento rientra tra quelli di lavoro (art. 4, c. 2) |
| Chi può collegarsi? | Elenco dei soggetti autorizzati e atto di designazione (art. 29 GDPR) |
| Chi si è collegato? | Registro degli accessi: data, ora, operatore, finalità; **attribuzione degli indirizzi** che compaiono nei registri |
| Per quanto tempo si conservano i dati? | Tempi di conservazione |
| Il dipendente viene avvisato? | Se è prevista una richiesta di consenso o un avviso prima della sessione, e in caso contrario le ragioni |
| C'è stata una DPIA? | Esito della valutazione d'impatto (art. 35), se svolta |

Il termine di risposta è **un mese** dal ricevimento, prorogabile di due mesi
con comunicazione motivata (art. 12, par. 3 GDPR).

## Buone pratiche tecniche suggerite

Sono indicazioni generali, da adattare al contesto dell'ente:

- fare in modo che l'utente **veda sempre** un avviso o chieda il consenso
  quando qualcuno si collega, salvo casi motivati e documentati;
- non nascondere l'icona del programma;
- registrare gli accessi (data, ora, operatore) e conservare i registri con
  un tempo definito, in un luogo non modificabile dagli operatori;
- limitare il trasferimento file e l'oscuramento dello schermo a chi ne ha
  bisogno;
- chiudere le porte di accesso remoto non necessarie e limitarle alla rete
  interna;
- documentare tutto in informativa e, se serve, in accordo sindacale.

## Per RSU e sindacati

Il report indica **fatti verificabili** (software, porte, configurazione,
registro) con la fonte tecnica di ogni dato e dichiara che cosa non ha potuto
controllare. Non accerta violazioni: serve a fare domande precise.
Le richieste preimpostate (DPO, RSU, INL, Garante) si generano con
`AVVIA_RICHIESTE.bat`, con le scadenze di legge.

## Limiti

- Segnalazione tecnica di primo livello, **non perizia forense** (nessuna
  acquisizione con valore probatorio pieno).
- Non rileva tutto: può dare falsi positivi e falsi negativi.
- I registri dei programmi sono file modificabili: la loro integrità non è
  garantita; un registro vuoto non prova l'assenza di accessi.
- Provato in ambienti di sviluppo e di test; l'esecuzione dei test su Windows
  è affidata alla CI del progetto.

## Contatti e licenza

Digital Valut APS — CF 90036980846 — info@digitalvalut.com
Gardone Val Trompia (BS), via G. Matteotti · Canicattì (AG), Piazza Palermo 4 ·
Caltanissetta, Via della Regione 4 (sede commerciale)

Licenza Apache 2.0: vedi `LICENSE` e `NOTICE`. Avvertenze: `DISCLAIMER.md`.
