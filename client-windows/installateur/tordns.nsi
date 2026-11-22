; Installateur TorDNS pour Windows (service + adaptateur WinTun).
; Compiler avec makensis depuis client-windows/installateur.
; La signature Authenticode se fait après compilation (voir README).

!include "MUI2.nsh"
!include "x64.nsh"

!define PRODUIT "TorDNS"
!define VERSION "0.1.0"
!define SERVICE "TorDNS"
!define REGISTRE_UNINSTALL "Software\Microsoft\Windows\CurrentVersion\Uninstall\TorDNS"

Name "${PRODUIT} ${VERSION}"
OutFile "TorDNS-${VERSION}-setup.exe"
InstallDir "$PROGRAMFILES64\TorDNS"
InstallDirRegKey HKLM "Software\TorDNS" "InstallDir"
RequestExecutionLevel admin
Unicode true
SetCompressor /SOLID lzma

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TEXT "Renseignez l'adresse .onion dans C:\ProgramData\TorDNS\client.conf puis démarrez le service TorDNS."
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "French"

Section "Client TorDNS" SEC_CLIENT
    SetOutPath "$INSTDIR"
    File "..\dist\tordns-client.exe"
    File /nonfatal "..\dist\wintun.dll"

    CreateDirectory "$COMMONPROGRAMDATA\TorDNS"
    IfFileExists "$COMMONPROGRAMDATA\TorDNS\client.conf" config_presente 0
        FileOpen $0 "$COMMONPROGRAMDATA\TorDNS\client.conf" w
        FileWrite $0 "# Configuration TorDNS$\r$\n"
        FileWrite $0 "onion =$\r$\n"
        FileWrite $0 "socks = 127.0.0.1:9050$\r$\n"
        FileWrite $0 "tun = TorDNS$\r$\n"
        FileWrite $0 "cache = 4096$\r$\n"
        FileWrite $0 "anti_fuite = non$\r$\n"
        FileWrite $0 "ttl_max = 3600$\r$\n"
        FileWrite $0 "delai = 15$\r$\n"
        FileClose $0
    config_presente:

    WriteRegStr HKLM "Software\TorDNS" "InstallDir" "$INSTDIR"
    WriteUninstaller "$INSTDIR\desinstaller.exe"
    WriteRegStr HKLM "${REGISTRE_UNINSTALL}" "DisplayName" "${PRODUIT}"
    WriteRegStr HKLM "${REGISTRE_UNINSTALL}" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "${REGISTRE_UNINSTALL}" "Publisher" "TorDNS"
    WriteRegStr HKLM "${REGISTRE_UNINSTALL}" "UninstallString" "$INSTDIR\desinstaller.exe"
    WriteRegDWORD HKLM "${REGISTRE_UNINSTALL}" "NoModify" 1
    WriteRegDWORD HKLM "${REGISTRE_UNINSTALL}" "NoRepair" 1

    ; Service à démarrage manuel : la configuration doit être renseignée avant.
    ExecWait 'sc create ${SERVICE} binPath= "$INSTDIR\tordns-client.exe" start= demand DisplayName= "${PRODUIT}"'
    ExecWait 'sc description ${SERVICE} "Relais DNS local vers le service caché Tor"'
    ExecWait 'sc failure ${SERVICE} reset= 86400 actions= restart/5000/restart/10000/restart/30000'
SectionEnd

Section "Uninstall"
    ExecWait 'sc stop ${SERVICE}'
    ExecWait 'sc delete ${SERVICE}'
    Delete "$INSTDIR\tordns-client.exe"
    Delete "$INSTDIR\wintun.dll"
    Delete "$INSTDIR\desinstaller.exe"
    RMDir "$INSTDIR"
    DeleteRegKey HKLM "Software\TorDNS"
    DeleteRegKey HKLM "${REGISTRE_UNINSTALL}"
    ; La configuration (adresse .onion) n'est pas un secret mais reste propre
    ; à l'utilisateur : elle n'est pas supprimée automatiquement.
SectionEnd
