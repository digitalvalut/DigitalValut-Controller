# Come aggiungere le tue regole di rilevamento

DigitalValut Controller non tiene le firme dentro il codice: le legge da file
`.json` nella cartella `core/rules/`.

**Questo significa che puoi aggiungere i tuoi rilevamenti senza saper
programmare, senza modificare il codice e senza chiedere il permesso a
nessuno.** Crei un file, lo metti nella cartella, funziona alla scansione
successiva.

> [!NOTE]
> Le regole sono **solo dati**: non contengono codice eseguibile. Un file di
> regole non può eseguire comandi sul tuo PC. È una scelta di sicurezza
> deliberata: puoi usare regole scritte da altri senza il rischio di eseguire
> qualcosa di malevolo. Resta comunque buona pratica leggere ciò che scarichi.

## In 30 secondi

1. Apri la cartella `core/rules/custom/`
2. Crea un file, per esempio `mie-regole.json`
3. Incollaci dentro questo:

```json
[
  {
    "id": "MIO-0001",
    "name": "Nome del software da rilevare",
    "description": "A cosa serve questa regola",
    "author": "Il tuo nome",
    "type": "process",
    "category": "Remote Control",
    "risk": "HIGH",
    "alert": true,
    "match": {
      "nameContains": ["nomeprocesso"]
    },
    "falsePositiveNote": "Quando questo rilevamento potrebbe essere un falso allarme"
  }
]
```

4. Sostituisci i valori con i tuoi, salva, rilancia la scansione. Fatto.

## I campi

| Campo | Obbligatorio | Cosa ci va |
|-------|--------------|------------|
| `id` | ✅ | Identificativo univoco. Usa un tuo prefisso (es. `ACME-0001`) per non collidere con le regole ufficiali `DV-*` |
| `name` | ✅ | Nome leggibile, compare nel report |
| `type` | ✅ | `process`, `port`, `service`, `software` o `module` |
| `risk` | ✅ | `LOW`, `MEDIUM`, `HIGH` o `CRITICAL` |
| `match` | ✅ | I criteri di ricerca (vedi sotto) |
| `description` | — | Descrizione estesa |
| `author` | — | Chi ha scritto la regola |
| `category` | — | Raggruppamento libero (es. `Remote Control`, `Spyware`) |
| `alert` | — | `true`/`false`: se `false` la voce viene mostrata ma non allarma |
| `falsePositiveNote` | — | **Scrivilo sempre**: aiuta chi legge il report a non trarre conclusioni sbagliate |

### La sezione `match`

| Criterio | Vale per | Esempio |
|----------|----------|---------|
| `nameContains` | process, service, software, module | `["teamviewer", "tvnserver"]` |
| `pathContains` | process, module | `["\\appdata\\local\\temp\\"]` |
| `ports` | port | `[5900, 5901]` |
| `excludeIfPathContains` | tutti | `["c:\\program files\\azienda\\"]` |

Il confronto è **sempre per sottostringa e non distingue maiuscole/minuscole**:
`"vnc"` trova `WinVNC.exe`, `tvnserver`, `UltraVNC`. Non servono espressioni
regolari — è voluto, perché deve poter scrivere una regola anche chi non è un
programmatore.

`excludeIfPathContains` ha **sempre la precedenza**: serve a spegnere i falsi
positivi. Esempio pratico — vuoi rilevare AnyDesk, ma nella tua azienda c'è
un'installazione autorizzata in una cartella precisa:

```json
{
  "id": "ACME-0002",
  "name": "AnyDesk non autorizzato",
  "type": "process",
  "risk": "HIGH",
  "match": {
    "nameContains": ["anydesk"],
    "excludeIfPathContains": ["c:\\program files (x86)\\anydesk-aziendale\\"]
  },
  "falsePositiveNote": "L'installazione aziendale ufficiale e' esclusa da questa regola."
}
```

## Altri esempi pronti

**Una porta di rete:**

```json
{
  "id": "MIO-0010",
  "name": "Servizio interno sospetto",
  "type": "port",
  "category": "Remote Control",
  "risk": "MEDIUM",
  "match": { "ports": [4444, 4445] }
}
```

**Una DLL caricata da un percorso anomalo:**

```json
{
  "id": "MIO-0020",
  "name": "DLL da cartella temporanea",
  "type": "module",
  "risk": "HIGH",
  "match": { "pathContains": ["\\appdata\\local\\temp\\"] }
}
```

## Se sbagli qualcosa

Non succede niente di grave: **una regola scritta male viene semplicemente
ignorata e la scansione prosegue**. Nel report, nella sezione "Regole di
rilevamento", trovi l'elenco degli scarti con il motivo (`JSON non valido`,
`campo obbligatorio mancante: risk`, e così via), così capisci subito cosa
correggere.

Lo strumento non si blocca mai per colpa di una regola difettosa — nemmeno se
proviene da terzi.

## Dove mettere i file

- `core/rules/` — le regole ufficiali del progetto. Se aggiorni DigitalValut
  Controller a una versione nuova, questi file vengono sostituiti.
- `core/rules/custom/` — **le tue regole**. Mettile qui: è la cartella pensata
  per non essere toccata dagli aggiornamenti.

Entrambe le cartelle vengono lette allo stesso modo, anche le sottocartelle.

## Vuoi proporre una regola al progetto?

Puoi aprire una [issue](https://github.com/digitalvalut/DigitalValut-Controller/issues)
o una pull request su GitHub. Non è però necessario: le tue regole funzionano
perfettamente in locale, senza che nessuno debba approvarle.

---

**DigitalValut** — [www.digitalvalut.it](https://www.digitalvalut.it)
Licenza GNU GPL v3.0 · Vedi [`DISCLAIMER.md`](DISCLAIMER.md) per i limiti dello strumento
