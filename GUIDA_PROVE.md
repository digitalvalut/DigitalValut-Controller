# Come raccogliere documentazione utilizzabile

Guida pratica per chi sospetta di essere sotto controllo e vuole raccogliere
materiale serio da portare a un avvocato o a un perito.

> [!IMPORTANT]
> **Leggi prima questo.** Questo strumento produce *documentazione tecnica*, non
> prove legali. Una prova la stabilisce un giudice; una perizia la redige un
> perito iscritto all'albo. Quello che puoi ottenere qui è il materiale migliore
> possibile **su cui un professionista poi lavora**. Chi ti promette "prove
> schiaccianti" con un programma gratuito ti sta ingannando.

## Il problema, spiegato in due righe

Un file creato dal tuo computer, con una data messa dal tuo computer, vale
quanto la tua parola: l'orologio si cambia in dieci secondi. In un contenziosio,
la controparte lo farà notare subito.

Le tre cose che risolvono questo problema sono già dentro lo strumento.

## I tre livelli, dal più debole al più forte

### Livello 1 — La fotografia (base)

Doppio clic su `AVVIA_CONTROLLO.bat`.

Ottieni un report di ciò che c'è **adesso** sul computer. Utile per capire la
situazione, debole come documentazione: mostra che *esiste* un software di
controllo remoto, circostanza che ammette molte spiegazioni legittime.

### Livello 2 — Il registratore (molto più forte)

Doppio clic su `AVVIA_SENTINELLA.bat` e **lascialo aperto per giorni**.

Qui cambia tutto. La Sentinella registra le connessioni **mentre accadono**:
non più "c'è VNC installato", ma **"il 14 marzo, dalle 03:12 alle 03:59, il tuo
computer ha avuto una sessione di controllo remoto attiva dall'indirizzo
10.x.x.x, durata 47 minuti"**.

Un fatto datato e circostanziato è molto più difficile da spiegare via di una
configurazione statica.

Consigli pratici:
- Lasciala attiva il più a lungo possibile: giorni, non ore.
- Riavviala dopo ogni riavvio del computer (i periodi non coperti sono
  dichiarati apertamente nel report: non si finge di aver visto tutto).
- Non serve fare nient'altro: usa il computer normalmente.

### Livello 3 — Il sigillo con data certificata (il massimo ottenibile)

Doppio clic su `CREA_PACCHETTO_PROVA.bat` e rispondi **S** alla domanda sulla
marca temporale.

Ottieni **un solo file .zip** che contiene:

| Contenuto | A cosa serve |
|---|---|
| Il report | La lettura d'insieme |
| I dati grezzi di sistema | Perché il perito possa **rifare l'analisi da zero** senza fidarsi delle nostre conclusioni |
| Il registro della Sentinella | I fatti datati |
| La catena di custodia | Rende evidente ogni alterazione successiva |
| **La marca temporale RFC 3161** | Un'**autorità terza** certifica che quel materiale esisteva già a quella data |
| Il verificatore autonomo | Permette a **chiunque** di controllare tutto, senza fidarsi di te |

**La marca temporale è il pezzo che conta di più.** Senza, le date le mette il
tuo computer. Con, le certifica un soggetto indipendente, con firma
crittografica. Il Regolamento eIDAS (UE 910/2014, art. 41) attribuisce alle
marche temporali *qualificate* una presunzione legale di accuratezza della data.

> **Cosa esce dal tuo computer con la marca temporale:** soltanto un'impronta di
> 32 byte (hash SHA-256). Nessun nome, nessun indirizzo IP, nessun processo,
> nessun contenuto del report. È matematicamente impossibile risalire ai dati
> partendo dall'impronta. È l'unica funzione dello strumento che si collega a
> Internet, ed è per questo che devi attivarla tu esplicitamente.

## Cosa fare, in ordine

1. **Fai partire subito la Sentinella** (`AVVIA_SENTINELLA.bat`) e lasciala
   lavorare per giorni. È il materiale che conta di più e si accumula solo col
   tempo: prima cominci, meglio è.
2. **Non modificare nulla** sul computer: non disinstallare, non "sistemare",
   non cancellare. Alterare lo stato del sistema danneggia il valore di
   qualunque analisi successiva.
3. Quando hai raccolto abbastanza, **crea il pacchetto prova con marca
   temporale** (`CREA_PACCHETTO_PROVA.bat`).
4. **Fai una copia del file .zip** su una chiavetta USB o su un altro
   dispositivo, subito.
5. **Consegna quel file a un avvocato.** È tutto lì dentro, incluse le
   istruzioni per lui e per il suo consulente tecnico.
6. Se l'avvocato lo ritiene opportuno, sarà lui a coinvolgere un **perito
   informatico forense** per un'acquisizione vera e propria.

## Cosa può fare chi riceve il pacchetto

Non deve installare niente e non deve fidarsi di te: estrae lo .zip e fa doppio
clic su `VERIFICA_PROVA.bat`. Il verificatore ricalcola l'impronta di ogni file
e la confronta con il manifesto, poi controlla la marca temporale.

Se anche un solo byte fosse stato modificato dopo la sigillatura, lo dice.

Il tecnico può anche verificare la marca temporale con strumenti standard,
senza usare alcun software di DigitalValut:

```bash
openssl ts -reply -in MARCA_TEMPORALE.tsr -text
```

## Prima di agire: due avvertenze serie

**Sul piano del lavoro.** Su una postazione aziendale o della PA, verifica il
regolamento informatico interno prima di eseguire questi strumenti. Non è un
reato, ma in molte organizzazioni l'esecuzione di software non approvato è una
violazione disciplinare. È una tua responsabilità, non dell'autore.

**Sul piano delle conclusioni.** La presenza di software di controllo remoto
**non dimostra** un uso illecito: potrebbe esistere un accordo sindacale, un
provvedimento dell'Ispettorato del lavoro o un'informativa che non ti sono stati
notificati. Il materiale che raccogli serve a **fare domande documentate**, non
a emettere una sentenza. Fatti assistere prima di muoverti.

---

**DigitalValut** — [www.digitalvalut.it](https://www.digitalvalut.it)
Sviluppatore: Dott. Giuseppe Falsone e il team DigitalValut
Licenza GNU GPL v3.0 · Limiti completi: [`DISCLAIMER.md`](DISCLAIMER.md)
