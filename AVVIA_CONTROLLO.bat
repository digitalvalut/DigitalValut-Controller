@echo off
chcp 65001 >nul 2>&1
setlocal EnableExtensions EnableDelayedExpansion
title DigitalValut Controller v4.0 - Tutela Privacy Lavoratori
cd /d "%~dp0"

set "LOGDIR=%~dp0DigitalValut_Reports"
if not exist "%LOGDIR%" mkdir "%LOGDIR%" >nul 2>&1
set "LOGFILE=%LOGDIR%\launcher_log.txt"

echo.
echo  ╔══════════════════════════════════════════════════════════════════╗
echo  ║                                                                  ║
echo  ║     ██████╗ ██╗ ██████╗ ██╗████████╗ █████╗ ██╗                  ║
echo  ║     ██╔══██╗██║██╔════╝ ██║╚══██╔══╝██╔══██╗██║                  ║
echo  ║     ██║  ██║██║██║  ███╗██║   ██║   ███████║██║                  ║
echo  ║     ██║  ██║██║██║   ██║██║   ██║   ██╔══██║██║                  ║
echo  ║     ██████╔╝██║╚██████╔╝██║   ██║   ██║  ██║███████╗             ║
echo  ║     ╚═════╝ ╚═╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝             ║
echo  ║                                                                  ║
echo  ║              CONTROLLER v4.0 - TUTELA PRIVACY                    ║
echo  ║         Strumento di Difesa per Lavoratori PA                    ║
echo  ║                                                                  ║
echo  ║   Autore: DigitalValut - www.digitalvalut.it                     ║
echo  ║   Sviluppo: Dott. Giuseppe Falsone e il team DigitalValut        ║
echo  ║   Licenza: GNU GPL v3.0 - Software libero e gratuito             ║
echo  ╚══════════════════════════════════════════════════════════════════╝
echo.
echo  ------------------------------------------------------------------
echo   AVVERTENZA - Leggere prima dell'uso
echo  ------------------------------------------------------------------
echo   Software fornito COSI' COM'E', senza garanzie, a titolo gratuito.
echo   Il report prodotto e' una SEGNALAZIONE TECNICA di primo livello:
echo   NON e' una perizia forense e NON e' una prova legale. Puo'
echo   contenere falsi positivi e falsi negativi.
echo   Usalo solo su dispositivi tuoi o su cui hai legittimo accesso, e
echo   verifica i regolamenti informatici della tua organizzazione.
echo   Prima di azioni legali o disciplinari: consulta un avvocato e un
echo   perito informatico forense.
echo   Avvertenza completa: file DISCLAIMER.md
echo  ------------------------------------------------------------------
echo.

:: Verifica presenza PowerShell
where powershell >nul 2>&1
if errorlevel 1 (
    echo  [!] PowerShell non trovato in PATH. Impossibile continuare.
    echo      Questo strumento richiede Windows PowerShell 5.1 o superiore.
    goto :END
)

:: Verifica privilegi amministrativi correnti (solo informativo, non obbligatorio)
net session >nul 2>&1
if %errorlevel%==0 (
    set "ELEV_STATUS=Amministratore"
) else (
    set "ELEV_STATUS=Utente standard"
)
echo  [i] Privilegi correnti: %ELEV_STATUS%
if not "%ELEV_STATUS%"=="Amministratore" (
    echo  [i] Puoi rilanciare come amministratore per una scansione piu' completa
    echo      ^(tasto destro su questo file - Esegui come amministratore^).
)
echo.

:MENU
echo  Seleziona modalita':
echo   [1] Scansione COMPLETA  ^(consigliata - analisi approfondita^)
echo   [2] Scansione RAPIDA    ^(controlli essenziali, piu' veloce^)
echo   [3] Verifica catena di custodia dei report gia' generati
echo   [4] Esci
echo.
choice /c 1234 /n /m "Scelta: "
set "SEL=%errorlevel%"

echo.
echo %date% %time% - Avvio (scelta %SEL%, privilegi: %ELEV_STATUS%) >> "%LOGFILE%"

if "%SEL%"=="4" goto :END
if "%SEL%"=="3" (
    echo  [*] Verifica catena di custodia in corso... NON CHIUDERE QUESTA FINESTRA
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\DVController.ps1" -VerifyChain
    goto :RESULT
)
if "%SEL%"=="2" (
    echo  [*] Scansione RAPIDA in corso... NON CHIUDERE QUESTA FINESTRA
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\DVController.ps1" -QuickScan
    goto :RESULT
)

echo  [*] Scansione COMPLETA in corso... NON CHIUDERE QUESTA FINESTRA
echo      ^(puo' richiedere fino a un minuto per i controlli audio/video^)
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\DVController.ps1"

:RESULT
set "EXITCODE=%errorlevel%"
echo %date% %time% - Terminato con codice %EXITCODE% >> "%LOGFILE%"

if not "%EXITCODE%"=="0" (
    echo.
    echo  [!] ERRORE ^(codice %EXITCODE%^): controlla il log "%LOGFILE%"
    echo  [!] Se il problema persiste, prova tasto destro - Esegui come amministratore
)

:END
echo.
echo  Premi un tasto per chiudere...
pause >nul
endlocal
