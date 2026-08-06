@{
    # Configurazione PSScriptAnalyzer per DigitalValut Controller.
    # La CI fallisce solo sulla severita' "Error". Le regole escluse qui sotto sono
    # scelte architetturali intenzionali del progetto, non sviste: escluderle evita
    # rumore senza nascondere problemi reali.
    ExcludeRules = @(
        # Lo strumento e' un tool CLI interattivo: l'output colorato con Write-Host
        # e' la scelta corretta per il feedback utente, non un log da redirigere.
        'PSAvoidUsingWriteHost',

        # Pattern difensivo deliberato: molti controlli (registro, WMI, CIM) sono
        # "best effort" e devono fallire in silenzio senza bloccare la scansione,
        # come dichiarato in piu' punti nei commenti del codice.
        'PSAvoidUsingEmptyCatchBlock',

        # Nomi di funzione pubblici e stabili (es. Get-DVSuspiciousProcessesDatabase):
        # rinominarli per la regola "nomi singolari" romperebbe la compatibilita'
        # con versioni precedenti senza alcun beneficio reale.
        'PSUseSingularNouns',

        # $Global:DVConfig e' condiviso deliberatamente tra i moduli per evitare di
        # propagare configurazione (autore, licenza, percorso report) in decine di
        # firme di funzione.
        'PSAvoidGlobalVars',

        # Genera falsi positivi su variabili con default difensivo riassegnate in un
        # ramo condizionale piu' sotto nella stessa funzione (pattern usato in tutto
        # SurveillanceDetector.psm1 per garantire un valore anche se una chiamata
        # con timeout non restituisce nulla).
        'PSUseDeclaredVarsMoreThanAssignments',

        # New-DVReportHTML scrive il report HTML che e' lo scopo stesso dello strumento:
        # non e' un'operazione distruttiva su cui abbia senso chiedere conferma con
        # -WhatIf/-Confirm ad ogni scansione.
        'PSUseShouldProcessForStateChangingFunctions',

        # Falso positivo verificato: ReportGenerator.psm1 e SurveillanceDetector.psm1
        # hanno correttamente il BOM UTF-8 (byte EF BB BF verificati manualmente), ma
        # questa regola continua a segnalarli in alcune versioni di PSScriptAnalyzer.
        'PSUseBOMForUnicodeEncodedFile'
    )
}
