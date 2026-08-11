@echo off
chcp 65001 >nul 2>&1
setlocal EnableExtensions
title DigitalValut Sentinella - Monitoraggio continuo
cd /d "%~dp0"

echo.
echo  ╔══════════════════════════════════════════════════════════════════╗
echo  ║              SENTINELLA - MONITORAGGIO CONTINUO                  ║
echo  ║              DigitalValut Controller v5.0                        ║
echo  ╚══════════════════════════════════════════════════════════════════╝
echo.
echo   A COSA SERVE
echo   ------------------------------------------------------------------
echo   Una scansione normale e' una fotografia: vede solo cosa c'e' ADESSO.
echo   Se qualcuno si collega al tuo PC alle 3 di notte, una fotografia
echo   scattata di giorno non lo vedra' mai.
echo.
echo   La Sentinella resta in ascolto e registra le connessioni remote
echo   MENTRE ACCADONO, con orario di inizio, di fine e durata.
echo.
echo   COME SI USA
echo   ------------------------------------------------------------------
echo   1. Lascia questa finestra aperta (puoi ridurla a icona)
echo   2. Usa il computer normalmente
echo   3. Quando vuoi fermarla: chiudi la finestra oppure premi CTRL+C
echo   4. Poi lancia AVVIA_CONTROLLO.bat: gli eventi registrati finiranno
echo      nel report
echo.
echo   Piu' a lungo la lasci attiva, piu' il quadro sara' completo.
echo.
echo   AVVERTENZA: software fornito COSI' COM'E', senza garanzie. Registra
echo   l'esistenza e la durata delle connessioni, NON il loro contenuto.
echo   Usalo solo su dispositivi tuoi o su cui hai legittimo accesso e
echo   verifica i regolamenti informatici della tua organizzazione.
echo   Avvertenza completa: file DISCLAIMER.md
echo  ------------------------------------------------------------------
echo.

where powershell >nul 2>&1
if errorlevel 1 (
    echo   [!] PowerShell non trovato. Impossibile continuare.
    goto :FINE
)

echo   Avvio in corso...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\DVController.ps1" -Sentinel -SentinelInterval 30 -SentinelMedia

:FINE
echo.
echo   Premi un tasto per chiudere...
pause >nul
endlocal
