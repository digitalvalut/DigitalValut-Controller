@echo off
chcp 65001 >nul 2>&1
setlocal EnableExtensions
title DigitalValut - Richieste di chiarimento e scadenzario
cd /d "%~dp0"

echo.
echo  ╔══════════════════════════════════════════════════════════════════╗
echo  ║        RICHIESTE DI CHIARIMENTO E SCADENZARIO                    ║
echo  ║        DigitalValut Controller v5.1                              ║
echo  ╚══════════════════════════════════════════════════════════════════╝
echo.
echo   A COSA SERVE
echo   ------------------------------------------------------------------
echo   Se il report ha segnalato qualcosa, il passo giusto e' chiedere
echo   chiarimenti per iscritto a chi di dovere (DPO, sindacato, Garante).
echo   Questo strumento prepara il TESTO delle lettere dai dati del report
echo   e tiene il conto delle scadenze di risposta previste dalla legge.
echo.
echo   COSA NON FA
echo   ------------------------------------------------------------------
echo   - NON invia nulla: PEC e raccomandata le invii TU.
echo   - NON e' consulenza legale: fai rivedere i testi a un avvocato
echo     giuslavorista o al tuo sindacato prima di inviarli.
echo   - NON accusa nessuno: sono richieste di chiarimento.
echo   Avvertenza completa: file DISCLAIMER.md
echo  ------------------------------------------------------------------
echo.

where powershell >nul 2>&1
if errorlevel 1 (
    echo   [!] PowerShell non trovato. Impossibile continuare.
    goto :FINE
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\Richieste.ps1"

:FINE
echo.
echo  Premi un tasto per chiudere...
pause >nul
endlocal
