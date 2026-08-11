@echo off
chcp 65001 >nul 2>&1
setlocal EnableExtensions EnableDelayedExpansion
title DigitalValut Controller v5.0 - Modalita' avanzata
cd /d "%~dp0"

set "LOGDIR=%~dp0DigitalValut_Reports"
if not exist "%LOGDIR%" mkdir "%LOGDIR%" >nul 2>&1
set "LOGFILE=%LOGDIR%\launcher_log.txt"

echo.
echo  ╔══════════════════════════════════════════════════════════════════╗
echo  ║   DIGITALVALUT CONTROLLER v5.0 - Modalita' avanzata               ║
echo  ║   Per un controllo semplice e veloce usa invece                   ║
echo  ║   AVVIA_CONTROLLO.bat (nessuna scelta richiesta).                 ║
echo  ╚══════════════════════════════════════════════════════════════════╝
echo.

:: Verifica presenza PowerShell
where powershell >nul 2>&1
if errorlevel 1 (
    echo  [!] PowerShell non trovato in PATH. Impossibile continuare.
    goto :END
)

net session >nul 2>&1
if %errorlevel%==0 (
    set "ELEV_STATUS=Amministratore"
) else (
    set "ELEV_STATUS=Utente standard"
)
echo  [i] Privilegi correnti: %ELEV_STATUS%
echo.

:MENU
echo  Seleziona modalita':
echo   [1] Scansione COMPLETA  ^(analisi approfondita^)
echo   [2] Scansione RAPIDA    ^(controlli essenziali, piu' veloce^)
echo   [3] Verifica catena di custodia dei report gia' generati
echo   [4] Esci
echo.
choice /c 1234 /n /m "Scelta: "
set "SEL=%errorlevel%"

echo.
echo %date% %time% - Avvio avanzato (scelta %SEL%, privilegi: %ELEV_STATUS%) >> "%LOGFILE%"

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
