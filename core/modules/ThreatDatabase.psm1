# DigitalValut Controller v4.0 - ThreatDatabase Module
# Copyright (C) 2024-2026 DigitalValut - www.digitalvalut.it
# Sviluppatore: Dott. Giuseppe Falsone e il team DigitalValut
#
# Questo file e' parte di DigitalValut Controller.
# Software libero: puoi ridistribuirlo e/o modificarlo secondo i termini della
# GNU General Public License v3.0 o (a tua scelta) qualsiasi versione successiva,
# come pubblicata dalla Free Software Foundation.
# Distribuito SENZA ALCUNA GARANZIA; senza neppure la garanzia implicita di
# COMMERCIABILITA' o IDONEITA' PER UNO SCOPO PARTICOLARE. Vedi la GNU GPL v3.
# Copia della licenza nel file LICENSE. Avvertenze e limiti: DISCLAIMER.md

# === PORTE DI CONTROLLO REMOTO ===
$Global:RemotePorts = @{
    # VNC Family
    5900  = @{Name="VNC"; Risk="CRITICAL"; Category="Remote Control"; Description="Virtual Network Computing - Controllo schermo"}
    5901  = @{Name="VNC-1"; Risk="CRITICAL"; Category="Remote Control"; Description="VNC Display 1"}
    5902  = @{Name="VNC-2"; Risk="CRITICAL"; Category="Remote Control"; Description="VNC Display 2"}
    5500  = @{Name="VNC-Reverse"; Risk="CRITICAL"; Category="Remote Control"; Description="VNC Reverse Connection"}
    
    # RDP
    3389  = @{Name="RDP"; Risk="HIGH"; Category="Remote Desktop"; Description="Microsoft Remote Desktop Protocol"}
    3390  = @{Name="RDP-Alt"; Risk="HIGH"; Category="Remote Desktop"; Description="RDP Porta alternativa"}
    
    # TeamViewer
    5938  = @{Name="TeamViewer"; Risk="CRITICAL"; Category="Commercial RAT"; Description="TeamViewer - Controllo remoto commerciale"}
    
    # AnyDesk
    6568  = @{Name="AnyDesk"; Risk="CRITICAL"; Category="Commercial RAT"; Description="AnyDesk - Controllo remoto"}
    7070  = @{Name="AnyDesk-Alt"; Risk="CRITICAL"; Category="Commercial RAT"; Description="AnyDesk Porta alternativa"}
    
    # Altri
    22    = @{Name="SSH"; Risk="MEDIUM"; Category="Shell Access"; Description="Secure Shell - Accesso remoto cifrato"}
    23    = @{Name="Telnet"; Risk="HIGH"; Category="Legacy"; Description="Telnet - Accesso remoto NON cifrato"}
    4899  = @{Name="Radmin"; Risk="CRITICAL"; Category="Remote Admin"; Description="Radmin Server"}
    8200  = @{Name="GoToMyPC"; Risk="HIGH"; Category="Commercial"; Description="GoToMyPC Cloud"}
    1494  = @{Name="Citrix-ICA"; Risk="MEDIUM"; Category="VDI"; Description="Citrix ICA Protocol"}
    2598  = @{Name="Citrix-CGP"; Risk="MEDIUM"; Category="VDI"; Description="Citrix CGP Protocol"}
    3283  = @{Name="Apple-Remote"; Risk="MEDIUM"; Category="Apple"; Description="Apple Remote Desktop"}
    5631  = @{Name="pcAnywhere"; Risk="HIGH"; Category="Legacy"; Description="Symantec pcAnywhere"}
    5632  = @{Name="pcAnywhere-Data"; Risk="HIGH"; Category="Legacy"; Description="pcAnywhere Data"}
    10000 = @{Name="Webmin"; Risk="HIGH"; Category="Web Admin"; Description="Webmin Server"}
    
    # Nuovi software emergenti
    7788  = @{Name="RustDesk"; Risk="HIGH"; Category="Open Source RAT"; Description="RustDesk Remote"}
    21116 = @{Name="RustDesk-Relay"; Risk="HIGH"; Category="Open Source RAT"; Description="RustDesk Relay"}
    6783  = @{Name="Parsec"; Risk="MEDIUM"; Category="Gaming/Streaming"; Description="Parsec Gaming"}
    
    # Porte enterprise
    135   = @{Name="RPC"; Risk="MEDIUM"; Category="Windows"; Description="Microsoft RPC"}
    139   = @{Name="NetBIOS"; Risk="MEDIUM"; Category="Windows"; Description="NetBIOS Session"}
    445   = @{Name="SMB"; Risk="MEDIUM"; Category="Windows"; Description="Server Message Block"}
}

# === PROCESSI SOSPETTI ===
$Global:SuspiciousProcesses = @{
    # Controllo Remoto
    "teamviewer"      = @{Name="TeamViewer"; Risk="CRITICAL"; Type="Remote Control"; Alert=$true}
    "anydesk"         = @{Name="AnyDesk"; Risk="CRITICAL"; Type="Remote Control"; Alert=$true}
    "winvnc"          = @{Name="WinVNC"; Risk="CRITICAL"; Type="Remote Control"; Alert=$true}
    "tvnserver"       = @{Name="TightVNC"; Risk="CRITICAL"; Type="Remote Control"; Alert=$true}
    "ultravnc"        = @{Name="UltraVNC"; Risk="CRITICAL"; Type="Remote Control"; Alert=$true}
    "realvnc"         = @{Name="RealVNC"; Risk="CRITICAL"; Type="Remote Control"; Alert=$true}
    "tigervnc"        = @{Name="TigerVNC"; Risk="CRITICAL"; Type="Remote Control"; Alert=$true}
    "radmin"          = @{Name="Radmin"; Risk="CRITICAL"; Type="Remote Control"; Alert=$true}
    "ammyy"           = @{Name="Ammyy Admin"; Risk="CRITICAL"; Type="Remote Control"; Alert=$true}
    "logmein"         = @{Name="LogMeIn"; Risk="HIGH"; Type="Remote Control"; Alert=$true}
    "gotomypc"        = @{Name="GoToMyPC"; Risk="HIGH"; Type="Remote Control"; Alert=$true}
    "splashtop"       = @{Name="Splashtop"; Risk="HIGH"; Type="Remote Control"; Alert=$true}
    "remotepc"        = @{Name="RemotePC"; Risk="HIGH"; Type="Remote Control"; Alert=$true}
    "screenconnect"   = @{Name="ScreenConnect/ConnectWise"; Risk="CRITICAL"; Type="Remote Control"; Alert=$true}
    "bomgar"          = @{Name="Bomgar/BeyondTrust"; Risk="HIGH"; Type="Remote Control"; Alert=$true}
    "dameware"        = @{Name="DameWare"; Risk="HIGH"; Type="Remote Control"; Alert=$true}
    "rustdesk"        = @{Name="RustDesk"; Risk="HIGH"; Type="Remote Control"; Alert=$true}
    "parsec"          = @{Name="Parsec"; Risk="MEDIUM"; Type="Gaming/Streaming"; Alert=$false}
    "supremo"         = @{Name="Supremo"; Risk="HIGH"; Type="Remote Control"; Alert=$true}
    "iperius"         = @{Name="Iperius Remote"; Risk="HIGH"; Type="Remote Control"; Alert=$true}
    "atera"           = @{Name="Atera Agent"; Risk="HIGH"; Type="RMM"; Alert=$true}
    "connectwise"     = @{Name="ConnectWise"; Risk="HIGH"; Type="RMM"; Alert=$true}
    "datto"           = @{Name="Datto RMM"; Risk="HIGH"; Type="RMM"; Alert=$true}
    "ninjaone"        = @{Name="NinjaOne/NinjaRMM"; Risk="HIGH"; Type="RMM"; Alert=$true}
    
    # Microsoft
    "mstsc"           = @{Name="RDP Client"; Risk="LOW"; Type="Microsoft"; Alert=$false}
    "msra"            = @{Name="Remote Assistance"; Risk="MEDIUM"; Type="Microsoft"; Alert=$false}
    "rdpclip"         = @{Name="RDP Clipboard"; Risk="LOW"; Type="Microsoft"; Alert=$false}
    
    # Spyware/Keylogger
    "keylogger"       = @{Name="Generic Keylogger"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "spyware"         = @{Name="Generic Spyware"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "ardamax"         = @{Name="Ardamax Keylogger"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "refog"           = @{Name="Refog Monitor"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "spytech"         = @{Name="SpyTech"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "neospy"          = @{Name="NeoSpy"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "realspy"         = @{Name="RealSpy"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "revealer"        = @{Name="Revealer Keylogger"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "spyrix"          = @{Name="Spyrix"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "hoverwatch"      = @{Name="HoverWatch"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "cocospy"         = @{Name="Cocospy"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "mspy"            = @{Name="mSpy"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "flexispy"        = @{Name="FlexiSpy"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "hookexe"         = @{Name="Hook Keyboard"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    "keysniff"        = @{Name="KeySniff"; Risk="CRITICAL"; Type="Spyware"; Alert=$true}
    
    # Software Monitoraggio Enterprise
    "activtrak"       = @{Name="ActivTrak"; Risk="HIGH"; Type="Employee Monitor"; Alert=$true}
    "teramind"        = @{Name="Teramind"; Risk="HIGH"; Type="Employee Monitor"; Alert=$true}
    "hubstaff"        = @{Name="Hubstaff"; Risk="HIGH"; Type="Employee Monitor"; Alert=$true}
    "timedoctor"      = @{Name="Time Doctor"; Risk="HIGH"; Type="Employee Monitor"; Alert=$true}
    "veriato"         = @{Name="Veriato"; Risk="HIGH"; Type="Employee Monitor"; Alert=$true}
    "interguard"      = @{Name="InterGuard"; Risk="HIGH"; Type="Employee Monitor"; Alert=$true}
    "workpuls"        = @{Name="WorkPuls/Insightful"; Risk="HIGH"; Type="Employee Monitor"; Alert=$true}
    "desktime"        = @{Name="DeskTime"; Risk="MEDIUM"; Type="Employee Monitor"; Alert=$true}
}

function Get-RemotePortsDatabase {
    return $Global:RemotePorts
}

function Get-SuspiciousProcessesDatabase {
    return $Global:SuspiciousProcesses
}

Export-ModuleMember -Function Get-RemotePortsDatabase, Get-SuspiciousProcessesDatabase
