# AVVERTENZE, LIMITAZIONI E ESCLUSIONE DI RESPONSABILITÀ

**Leggere integralmente prima di scaricare, eseguire o utilizzare DigitalValut Controller (di seguito "il Software").**

Scaricando, installando, eseguendo o utilizzando il Software, l'utente dichiara di aver letto, compreso e accettato integralmente il presente documento e i termini della licenza GNU General Public License v3.0 (file `LICENSE`), con particolare riferimento alle **Sezioni 15, 16 e 17** ivi contenute.

Se non si accettano tali condizioni, **non utilizzare il Software**.

---

## 1. Natura del Software

Il Software è uno strumento **diagnostico e di verifica tecnica** che analizza in modalità di sola lettura lo stato del sistema operativo Windows sul quale viene eseguito (processi, servizi, porte di rete, software installato, periferiche audio/video, impostazioni di sicurezza) e produce un report descrittivo.

Il Software:

- **non** installa componenti permanenti sul sistema;
- **non** modifica configurazioni, file o impostazioni di sistema;
- **non** trasmette dati a server remoti né all'autore;
- **non** rimuove, disattiva o neutralizza alcun software rilevato;
- **non** costituisce un antivirus, un EDR, un sistema di protezione attiva né un sostituto di essi.

## 2. ASSENZA DI GARANZIE

Il Software è fornito **"COSÌ COM'È" ("AS IS")**, senza garanzie di alcun tipo, esplicite o implicite, incluse — a titolo esemplificativo e non esaustivo — le garanzie di commerciabilità, idoneità per uno scopo specifico, accuratezza, completezza, continuità di funzionamento e assenza di errori o di violazione di diritti di terzi.

L'intero rischio derivante dalla qualità e dalle prestazioni del Software è a carico dell'utente. Qualora il Software risultasse difettoso, l'utente si assume integralmente il costo di ogni necessaria manutenzione, riparazione o correzione.

## 3. LIMITI TECNICI DICHIARATI

L'utente riconosce espressamente di essere stato informato che:

**a) Falsi positivi.** Il Software può segnalare come sospetto software legittimo, regolarmente installato e autorizzato (ad esempio strumenti di assistenza remota IT concordati, soluzioni di gestione aziendale, applicativi di videoconferenza). **La comparsa di un elemento nel report non dimostra in alcun modo l'esistenza di un illecito, di un abuso o di un controllo non autorizzato.**

**b) Falsi negativi.** Il Software **non è in grado di garantire il rilevamento** di ogni forma di monitoraggio, controllo remoto o sorveglianza. In particolare non rileva, se non incidentalmente: strumenti progettati specificamente per eludere l'analisi, impianti a livello firmware, bootkit, rootkit in kernel mode, hypervisor malevoli, dispositivi hardware di intercettazione, monitoraggio effettuato a livello di rete o di infrastruttura esterna al dispositivo. **L'esito "SICURO" o un punteggio di rischio basso NON dimostra e NON garantisce l'assenza di controllo o di sorveglianza.**

**c) Analisi automatizzata.** I risultati derivano da euristiche e da un elenco di firme note, per loro natura incompleti e soggetti a obsolescenza. Non sostituiscono in alcun modo l'analisi di un tecnico qualificato.

**d) Ambito di esecuzione.** Eseguito senza privilegi amministrativi, il Software produce risultati parziali. Alcuni controlli possono fallire silenziosamente per restrizioni di sistema, policy aziendali o configurazioni particolari.

## 4. LIMITI PROBATORI DEL REPORT

Il report generato dal Software è una **segnalazione tecnica di primo livello**. Esso **NON costituisce**:

- una perizia informatica forense;
- un'acquisizione forense conforme alle best practice di cui alla **Legge 48/2008** (ratifica della Convenzione di Budapest) e agli standard ISO/IEC 27037;
- una prova legale, un atto pubblico, una certificazione o un documento avente fede privilegiata;
- un accertamento della liceità o illiceità di un trattamento di dati personali.

Il meccanismo di catena di custodia integrato (`chain_of_custody.jsonl`) è **tamper-evident**: rende rilevabile un'alterazione accidentale o non esperta dei report. Esso **non** è una marcatura temporale certificata da terza parte (RFC 3161), **non** è notarizzato esternamente, si fonda sull'orologio di sistema locale e risiede sulla medesima macchina scrivibile dall'utente. Poiché il Software è open source, l'algoritmo è pubblico e un soggetto tecnicamente competente è in grado di rigenerare integralmente la catena. **Non deve pertanto essere presentato come garanzia di autenticità opponibile a terzi.**

**Per far valere in qualsiasi sede quanto rilevato è necessario rivolgersi a un perito informatico forense e a un avvocato.**

## 5. ASSENZA DI CONSULENZA LEGALE

I riferimenti normativi contenuti nel Software, nella documentazione e nei report (GDPR, Art. 4 L. 300/1970, D.Lgs. 196/2003, provvedimenti del Garante Privacy) sono riportati a **fine meramente informativo e divulgativo**, possono non essere aggiornati e non tengono conto delle circostanze del caso concreto.

Essi **non costituiscono** consulenza legale, parere professionale, assistenza giudiziale o stragiudiziale. Il modello di lettera al DPO incluso nel report è un **fac-simile esemplificativo** da adattare con l'assistenza di un professionista.

L'autore **non è un avvocato** e non fornisce, tramite il Software, alcuna prestazione professionale legale.

## 6. ESCLUSIONE DI RESPONSABILITÀ

Nella misura massima consentita dalla legge applicabile, l'autore, i collaboratori e DigitalValut Association **non potranno in alcun caso essere ritenuti responsabili** per danni di qualsiasi natura — diretti, indiretti, incidentali, speciali, punitivi o consequenziali — inclusi a titolo esemplificativo:

- perdita di dati, mancato guadagno, perdita di chance, danno reputazionale o d'immagine;
- interruzione dell'attività lavorativa o di servizio;
- **conseguenze di natura disciplinare, contrattuale, amministrativa, civile o penale** derivanti da azioni intraprese o omesse sulla base del Software o dei suoi report;
- esiti sfavorevoli di procedimenti giudiziari, arbitrali, disciplinari o di contenziosi di qualsiasi genere;
- danni derivanti da interpretazione errata dei risultati, da falsi positivi o da falsi negativi;
- danni derivanti da un utilizzo del Software non conforme alla legge o ai regolamenti interni dell'organizzazione dell'utente;
- malfunzionamenti, incompatibilità o effetti indesiderati sul sistema dell'utente.

Ciò vale anche qualora l'autore sia stato avvisato della possibilità di tali danni.

**Riserva imperativa.** Le limitazioni di cui alla presente sezione operano nei limiti consentiti dalla normativa inderogabile applicabile. Nulla nel presente documento esclude o limita la responsabilità per **dolo o colpa grave** (art. 1229 c.c.), per morte o lesioni personali imputabili all'autore, né i diritti inderogabili riconosciuti ai consumatori dalla normativa vigente.

## 7. OBBLIGHI E RESPONSABILITÀ DELL'UTENTE

L'utente è **unico ed esclusivo responsabile** dell'uso che fa del Software e si obbliga a:

**a)** eseguire il Software **esclusivamente** su dispositivi di cui abbia la proprietà o un legittimo diritto d'uso e di accesso. L'esecuzione su sistemi altrui senza autorizzazione può integrare illecito, anche penale (cfr. art. 615-ter c.p.);

**b)** verificare preventivamente la conformità dell'esecuzione ai **regolamenti informatici interni**, alle policy di sicurezza e al codice disciplinare della propria organizzazione. Su postazioni aziendali o della Pubblica Amministrazione, l'esecuzione di software non autorizzato può costituire violazione delle policy interne con possibili conseguenze disciplinari, **delle quali l'autore non risponde in alcun modo**;

**c)** trattare i dati contenuti nei report — che possono includere nome utente, nome macchina, dominio, indirizzi IP ed elenco processi — nel rispetto della normativa sulla protezione dei dati personali, valutandone la natura prima di qualsiasi diffusione o comunicazione a terzi;

**d)** non presentare il report come perizia forense, prova legale o accertamento di illecito;

**e)** non utilizzare il Software per finalità di sorveglianza, spionaggio, profilazione di terzi o per qualsiasi scopo illecito.

L'utente si impegna a **manlevare e tenere indenne** l'autore, i collaboratori e DigitalValut Association da ogni pretesa, richiesta risarcitoria, azione, contestazione, sanzione o spesa (incluse le spese legali) avanzata da terzi e derivante da un uso del Software difforme dal presente documento, dalla licenza o dalla legge.

## 8. GRATUITÀ E ASSENZA DI OBBLIGHI DI ASSISTENZA

Il Software è distribuito **a titolo gratuito**, senza corrispettivo di alcun genere, come contributo liberale alla collettività.

Non sussiste alcun rapporto contrattuale, di consulenza, di prestazione d'opera o di servizio tra l'autore e l'utente. L'autore **non è tenuto** a fornire assistenza, manutenzione, aggiornamenti, correzioni di errori o continuità del progetto, e può interromperne lo sviluppo o la distribuzione in qualsiasi momento senza preavviso né responsabilità.

Trattandosi di donazione di bene senza corrispettivo, la responsabilità dell'autore è ulteriormente circoscritta ai sensi dell'art. 798 c.c. per i vizi della cosa donata.

## 9. PROPRIETÀ INTELLETTUALE

Il Software è protetto dal diritto d'autore. La titolarità dei diritti e la paternità dell'opera restano in capo a **DigitalValut** (sviluppo a cura del Dott. Giuseppe Falsone e del team DigitalValut).

La concessione in licenza GNU GPLv3 attribuisce agli utenti ampie libertà d'uso, copia, modifica e ridistribuzione, **non comporta alcuna cessione di titolarità** e non fa sorgere in capo all'autore alcun obbligo o garanzia ulteriore rispetto a quanto previsto dalla licenza medesima.

Chi ridistribuisce versioni modificate del Software è tenuto a **indicarlo chiaramente** e ne assume la piena responsabilità: l'autore originale non risponde di modifiche, fork o derivati realizzati da terzi.

## 10. LEGGE APPLICABILE

Il presente documento è regolato dalla **legge italiana**. Per le controversie che dovessero insorgere, e nei limiti in cui ciò sia derogabile dalla normativa applicabile, è competente il foro del luogo di residenza dell'autore; restano impregiudicati i fori inderogabili previsti dalla legge a tutela del consumatore.

L'eventuale invalidità o inefficacia di una singola clausola non pregiudica la validità delle restanti disposizioni, che continueranno ad applicarsi nella massima misura consentita dalla legge.

---

**DigitalValut** — [www.digitalvalut.it](https://www.digitalvalut.it)
Sviluppatore: Dott. Giuseppe Falsone e il team DigitalValut
© 2024–2026 — Licenza GNU GPL v3.0 o successiva

*Documento aggiornato al 6 agosto 2026.*
