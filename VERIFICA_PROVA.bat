@echo off
chcp 65001 >nul 2>&1
title Verifica Pacchetto Prova - DigitalValut
cd /d "%~dp0"

echo.
echo  ==================================================================
echo    VERIFICA DI UN PACCHETTO PROVA DIGITALVALUT
echo  ==================================================================
echo.
echo   Questo strumento controlla se il materiale contenuto in questa
echo   cartella e' integro e da quando esiste.
echo.
echo   NON serve installare nulla e NON occorre fidarsi di chi ha
echo   prodotto il pacchetto: la verifica e' indipendente.
echo.

where powershell >nul 2>&1
if errorlevel 1 (
    echo   [!] PowerShell non trovato. Impossibile continuare.
    goto :FINE
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0VERIFICA_PROVA.ps1"

:FINE
echo.
echo   Premi un tasto per chiudere...
pause >nul
