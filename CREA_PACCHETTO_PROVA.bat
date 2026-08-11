@echo off
chcp 65001 >nul 2>&1
setlocal EnableExtensions
title DigitalValut - Crea Pacchetto Prova
cd /d "%~dp0"

echo.
echo  ╔══════════════════════════════════════════════════════════════════╗
echo  ║           CREA IL PACCHETTO PROVA DA CONSEGNARE                  ║
echo  ║           DigitalValut Controller v5.0                           ║
echo  ╚══════════════════════════════════════════════════════════════════╝
echo.
echo   COSA FA
echo   ------------------------------------------------------------------
echo   Esegue una scansione completa e prepara UN SOLO FILE .zip da
echo   consegnare al tuo avvocato o a un perito informatico.
echo.
echo   Dentro ci trovano tutto: il report, i dati grezzi del sistema, la
echo   catena di custodia, e un programma di verifica che possono eseguire
echo   LORO per controllare che nulla sia stato alterato - senza doversi
echo   fidare di te e senza installare niente.
echo.
echo   MARCA TEMPORALE
echo   ------------------------------------------------------------------
echo   Verra' richiesta una marca temporale a un'autorita' indipendente,
echo   che certifica la data in cui il materiale e' stato prodotto.
echo   Serve perche' l'orologio del computer si puo' modificare: senza
echo   certificazione di terzi, la data vale quanto la tua parola.
echo.
echo   IMPORTANTE - COSA VIENE INVIATO SU INTERNET
echo   Viene inviata SOLO un'impronta digitale di 32 byte (hash SHA-256).
echo   Nessun dato del report, nessun nome, nessun indirizzo IP, nessun
echo   processo: NULLA di leggibile lascia questo computer.
echo   E' l'unica funzione del programma che si collega a Internet.
echo.
echo   Se non hai connessione, il pacchetto viene creato lo stesso: sara'
echo   valido ma privo di data certificata da terzi.
echo  ------------------------------------------------------------------
echo.

choice /c SN /n /m "  Vuoi procedere e richiedere la marca temporale? [S=si  N=no] "
if errorlevel 2 goto :SENZA_MARCA

echo.
echo   [*] Scansione e pacchetto CON marca temporale in corso...
echo       NON CHIUDERE QUESTA FINESTRA.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\DVController.ps1" -EvidencePackage -Timestamp
goto :FINE

:SENZA_MARCA
echo.
echo   [*] Scansione e pacchetto SENZA marca temporale in corso...
echo       NON CHIUDERE QUESTA FINESTRA.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\DVController.ps1" -EvidencePackage

:FINE
echo.
echo   Il pacchetto .zip si trova nella cartella DigitalValut_Reports,
echo   accanto a questo programma. E' quello il file da consegnare.
echo.
echo   Premi un tasto per chiudere...
pause >nul
endlocal
