# AVVERTENZE, LIMITAZIONI E ESCLUSIONE DI RESPONSABILITÀ

**Leggere integralmente prima di scaricare, eseguire o utilizzare DigitalValut Controller (di seguito "il Software").**

Scaricando, installando, eseguendo o utilizzando il Software, l'utente dichiara di aver letto, compreso e accettato integralmente il presente documento e i termini della Licenza Apache, Versione 2.0 (file `LICENSE`), con particolare riferimento alle **Sezioni 7 (esclusione di garanzia), 8 (limitazione di responsabilità) e 9** ivi contenute.

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

**e) Firma digitale (Authenticode).** L'assenza di firma digitale su un eseguibile **non dimostra** malevolenza: molto software legittimo, in particolare interno o aziendale, non è firmato. Allo stesso modo, la presenza di una firma valida **non dimostra** un uso autorizzato: un software commerciale regolarmente firmato (es. TeamViewer) può comunque essere installato senza autorizzazione. È un elemento a supporto della valutazione, non una prova.

**f) Persistenza avanzata.** Le tecniche rilevate (sottoscrizioni WMI, `AppInit_DLLs`, debugger IFEO, task pianificati) sono usate sia da malware sia, più raramente, da strumenti di gestione IT legittimi. Ogni riscontro va valutato nel contesto: la presenza non dimostra da sola una compromissione.

**g) Regole di rilevamento di terze parti.** Il Software carica le regole di
rilevamento da file esterni, che possono essere stati scritti da soggetti diversi
dall'autore. Tali regole sono **soltanto dati dichiarativi** e non possono
eseguire codice sul sistema; tuttavia una regola scritta male o in malafede può
produrre **segnalazioni errate o fuorvianti**. L'autore non risponde in alcun
modo del contenuto, dell'accuratezza o degli effetti di regole non incluse nella
distribuzione ufficiale. Nel report è sempre indicato il file di provenienza di
ogni rilevamento.

**h) Rilevamento di DLL caricate da percorsi anomali.** Il controllo è basato sul
**percorso** del file, non sul comportamento: non stabilisce se una libreria sia
malevola. Non rileva le tecniche di iniezione avanzate (*reflective loading*,
*manual mapping*), che non lasciano un modulo elencabile con questo metodo. Senza
privilegi amministrativi molti processi non sono ispezionabili: **l'assenza di
segnalazioni non dimostra l'assenza di iniezione**.

**i) Analisi storica dei registri eventi.** I registri eventi di Windows hanno
dimensione limitata e ruotano: eventi più vecchi possono essere già stati
sovrascritti in modo del tutto legittimo. Il registro di sicurezza richiede
privilegi amministrativi e, in loro assenza, quella parte dell'analisi viene
saltata (il report lo dichiara). L'installazione di un servizio è inoltre
un'operazione ordinaria — driver, aggiornamenti e software aziendale ne
installano di continuo — e **non costituisce di per sé indice di un problema**.

**j) Modalità Sentinella (monitoraggio continuo).** La Sentinella campiona lo
stato del sistema a intervalli: **una sessione di durata inferiore all'intervallo
di campionamento può non essere osservata affatto**. Quando non è in esecuzione
(computer spento, programma chiuso, riavvio) non registra nulla: i periodi
scoperti sono dichiarati nel report e **l'assenza di eventi in un dato momento
non significa che non sia accaduto nulla**. Registra l'esistenza, l'origine e la
durata delle connessioni, **mai il loro contenuto**: non è uno strumento di
intercettazione. Gli orari provengono dall'orologio del computer analizzato.

**k) Marca temporale RFC 3161.** Le autorità di marcatura temporale gratuite
preconfigurate **non sono necessariamente qualificate** ai sensi del Regolamento
eIDAS (UE 910/2014): producono una prova crittografica solida e verificabile da
chiunque, ma la **presunzione legale** di accuratezza della data prevista
dall'art. 41 eIDAS opera solo per le validazioni temporali *qualificate*, che
richiedono un prestatore qualificato (di norma a pagamento, elenco consultabile
sui registri di fiducia europei). La marca temporale attesta che un determinato
hash esisteva a una certa data: **non attesta in alcun modo la veridicità, la
correttezza o il significato dei dati sottostanti**. Lo strumento verifica la
firma del token ma **non** valida la catena di certificazione fino a una CA
radice attendibile: quella verifica va eseguita con strumenti standard (OpenSSL),
come indicato nelle istruzioni incluse nel pacchetto.

**l) Pacchetto prova e verificatore.** Il pacchetto **non è un'acquisizione
forense** e il verificatore incluso accerta esclusivamente **integrità e data**
del materiale: non esprime alcuna valutazione di merito, non attesta che i
riscontri siano corretti e non ne certifica il significato. I dati sono raccolti
dall'interno del sistema in esame tramite le API di Windows: qualora il sistema
fosse compromesso a livello di kernel, tali API potrebbero restituire
informazioni falsate senza che ciò sia rilevabile.

**m) Spiegazione generata da intelligenza artificiale (opzionale).** Se disponibile in locale tramite Ollama, il report può includere una spiegazione dei risultati generata da un modello linguistico. Questo testo è generato automaticamente, **può contenere imprecisioni o omissioni** (fenomeno noto come "allucinazione" nei modelli linguistici), non è stato validato da una persona e **non sostituisce in alcun modo** le sezioni tecniche del report né un parere legale. È fornito unicamente a scopo di leggibilità.

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

Nella misura massima consentita dalla legge applicabile, l'autore, i collaboratori e Digital Valut APS **non potranno in alcun caso essere ritenuti responsabili** per danni di qualsiasi natura — diretti, indiretti, incidentali, speciali, punitivi o consequenziali — inclusi a titolo esemplificativo:

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

L'utente si impegna a **manlevare e tenere indenne** l'autore, i collaboratori e Digital Valut APS da ogni pretesa, richiesta risarcitoria, azione, contestazione, sanzione o spesa (incluse le spese legali) avanzata da terzi e derivante da un uso del Software difforme dal presente documento, dalla licenza o dalla legge.

## 8. GRATUITÀ E ASSENZA DI OBBLIGHI DI ASSISTENZA

Il Software è distribuito **a titolo gratuito**, senza corrispettivo di alcun genere, come contributo liberale alla collettività.

Non sussiste alcun rapporto contrattuale, di consulenza, di prestazione d'opera o di servizio tra l'autore e l'utente. L'autore **non è tenuto** a fornire assistenza, manutenzione, aggiornamenti, correzioni di errori o continuità del progetto, e può interromperne lo sviluppo o la distribuzione in qualsiasi momento senza preavviso né responsabilità.

Trattandosi di donazione di bene senza corrispettivo, la responsabilità dell'autore è ulteriormente circoscritta ai sensi dell'art. 798 c.c. per i vizi della cosa donata.

## 9. PROPRIETÀ INTELLETTUALE

Il Software è protetto dal diritto d'autore. La titolarità dei diritti e la paternità dell'opera restano in capo a **Digital Valut APS** (CF 90036980846; sviluppo a cura del Dott. Giuseppe Falsone e del team DigitalValut).

La concessione in licenza Apache 2.0 attribuisce agli utenti ampie libertà d'uso, copia, modifica e ridistribuzione, **non comporta alcuna cessione di titolarità** e non fa sorgere in capo all'autore alcun obbligo o garanzia ulteriore rispetto a quanto previsto dalla licenza medesima.

Chi ridistribuisce versioni modificate del Software è tenuto a **indicarlo chiaramente** e ne assume la piena responsabilità: l'autore originale non risponde di modifiche, fork o derivati realizzati da terzi.

## 9-bis. RICHIESTE DI CHIARIMENTO (AVVIA_RICHIESTE.bat)

Le lettere generate dal modulo *Richieste* sono **modelli di testo** che l'utente completa, rivede e invia sotto la propria responsabilità. Il Software **non invia nulla** e **non sostituisce un avvocato**: i riferimenti normativi e la competenza degli enti destinatari (ad esempio dell'Ispettorato del lavoro per il pubblico impiego) vanno verificati con un legale o con il proprio sindacato prima dell'uso. I termini calcolati dallo scadenzario sono indicativi; il registro delle richieste è tamper-evident ma **non è una marca temporale di terza parte**: conserva sempre le ricevute di consegna (PEC o raccomandata). L'invio di richieste contenenti affermazioni inesatte può avere conseguenze per chi le firma.

## 10. LEGGE APPLICABILE

Il presente documento è regolato dalla **legge italiana**. Per le controversie che dovessero insorgere, e nei limiti in cui ciò sia derogabile dalla normativa applicabile, è competente il foro del luogo di residenza dell'autore; restano impregiudicati i fori inderogabili previsti dalla legge a tutela del consumatore.

L'eventuale invalidità o inefficacia di una singola clausola non pregiudica la validità delle restanti disposizioni, che continueranno ad applicarsi nella massima misura consentita dalla legge.


## 11. ENTI, PUBBLICHE AMMINISTRAZIONI E TITOLARI DEL TRATTAMENTO

Chi usa il Software all'interno di un ente pubblico o privato lo fa **sotto la responsabilità dell'ente e dei propri responsabili**. Digital Valut APS non è fornitore, appaltatore, consulente né responsabile del trattamento dell'ente, non assume obblighi di conformità (GDPR, L. 300/1970, norme sulla sicurezza informatica) e non garantisce che l'uso del Software sia sufficiente a rispettarli. Le valutazioni su informative, basi giuridiche, accordi sindacali, autorizzazioni, nomine e misure di sicurezza spettano esclusivamente all'ente, al suo DPO e ai suoi consulenti. La guida `docs/PUBBLICA_AMMINISTRAZIONE.md` è un'indicazione generale e non un parere.

## 12. DATI PERSONALI: IL SOFTWARE NON LI RACCOGLIE

Il Software funziona in locale e **non trasmette dati** a Digital Valut APS né ad altri; non contiene telemetria. Di conseguenza Digital Valut APS **non riceve, non conserva e non tratta** i dati contenuti nei report, e non agisce né come titolare né come responsabile del trattamento rispetto all'uso che ne fa l'utente. L'utente è titolare di ciò che genera, conserva, invia o pubblica (inclusi report, pacchetti prova e lettere) e risponde della loro riservatezza. Se un funzionamento opzionale prevede il contatto con servizi esterni (ad esempio una marca temporale RFC 3161 o un assistente locale), ciò avviene solo per scelta dell'utente e secondo i termini di quei servizi.

## 13. SOFTWARE, SERVIZI E CONTENUTI DI TERZI

Il Software legge e descrive programmi e servizi di terzi (ad esempio UltraVNC, Windows, antivirus) e può far riferimento a servizi di terzi (autorità di marcatura temporale, assistenti locali). Digital Valut APS **non è responsabile** del funzionamento, della sicurezza, della disponibilità, dei termini d'uso o dell'accuratezza della documentazione di tali terzi; le descrizioni delle impostazioni riportano la documentazione del produttore alla data di redazione e possono essere cambiate o inesatte. Marchi e nomi citati appartengono ai rispettivi titolari e sono usati solo per identificare i programmi analizzati.

## 14. NOME E MARCHIO

La Licenza Apache 2.0 non concede diritti sul nome, sul marchio e sui loghi di Digital Valut APS (sezione 6 della Licenza). Le versioni modificate non possono presentarsi come prodotto o come posizione ufficiale di Digital Valut APS.

## 15. SICUREZZA, AGGIORNAMENTI E MODIFICHE DI QUESTO DOCUMENTO

Il Software può contenere errori o vulnerabilità. Per le segnalazioni di sicurezza vedi `SECURITY.md`. Prima di eseguirlo su sistemi importanti, l'utente è invitato a verificare l'integrità del download (`SHA256SUMS.txt`), a leggere il codice sorgente e a disporre di copie di sicurezza. Digital Valut APS può modificare questo documento in qualsiasi momento; fa fede la versione allegata alla copia del Software che si utilizza.

## 16. RAPPORTO CON LA LICENZA E INTERPRETAZIONE

Il presente documento integra la Licenza Apache 2.0 e non la restringe. In caso di contrasto prevale la Licenza per quanto riguarda i diritti di uso, copia, modifica e ridistribuzione. Le esclusioni di responsabilità valgono per l'autore, i collaboratori, i volontari, i soci e gli amministratori di Digital Valut APS, **nella massima misura consentita dalla legge**; restano ferme le riserve imperative indicate alla sezione 6 (dolo, colpa grave, danni alla persona, diritti inderogabili). Le versioni del Software fino alla 5.3.1, distribuite sotto GPLv3, restano regolate da quella licenza per chi le ha ricevute.

---

**DigitalValut** — [www.digitalvalut.it](https://www.digitalvalut.it)
Sviluppatore: Dott. Giuseppe Falsone e il team DigitalValut
© 2024–2026 Digital Valut APS — Licenza Apache 2.0

*Documento aggiornato al 15 ottobre 2026.*
