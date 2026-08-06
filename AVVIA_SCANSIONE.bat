@echo off
chcp 65001 >nul 2>&1
title DigitalValut Controller v4.1 - Scansione Rapida
cd /d "%~dp0"

set "LOGDIR=%~dp0DigitalValut_Reports"
if not exist "%LOGDIR%" mkdir "%LOGDIR%" >nul 2>&1
set "LOGFILE=%LOGDIR%\launcher_log.txt"

echo.
echo  ╔══════════════════════════════════════════════════════════════════╗
echo  ║   DIGITALVALUT CONTROLLER v4.1 - Scansione Rapida                ║
echo  ║   Un solo click: controlli essenziali, nessun menu               ║
echo  ║   Per la scansione completa usa AVVIA_CONTROLLO.bat               ║
echo  ║   Per la catena di custodia e altre opzioni usa                  ║
echo  ║   AVVIA_AVANZATO.bat                                              ║
echo  ╚══════════════════════════════════════════════════════════════════╝
echo.
echo   AVVERTENZA: software fornito COSI' COM'E', senza garanzie. Il report
echo   e' una segnalazione tecnica, NON una perizia forense ne' una prova
echo   legale; puo' contenere falsi positivi e falsi negativi. Usalo solo
echo   su dispositivi tuoi o su cui hai legittimo accesso.
echo   Avvertenza completa: file DISCLAIMER.md - Licenza: GNU GPL v3.0
echo.
echo  [*] Scansione rapida in corso... NON CHIUDERE QUESTA FINESTRA
echo.

echo %date% %time% - Avvio scansione rapida >> "%LOGFILE%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\DVController.ps1" -QuickScan
set "EXITCODE=%errorlevel%"
echo %date% %time% - Terminato con codice %EXITCODE% >> "%LOGFILE%"

if not "%EXITCODE%"=="0" (
    echo.
    echo  [!] ERRORE ^(codice %EXITCODE%^): prova tasto destro - Esegui come amministratore
    echo  [!] Oppure usa AVVIA_CONTROLLO.bat per diagnostica e opzioni complete.
)

echo.
echo  Premi un tasto per chiudere...
pause >nul
