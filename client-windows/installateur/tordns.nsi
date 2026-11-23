; Installateur TorDNS pour Windows (service + adaptateur WinTun).
; Compiler avec makensis depuis client-windows/installateur.
; La signature Authenticode se fait après compilation (voir README).

!include "MUI2.nsh"
!include "x64.nsh"

!define PRODUIT "TorDNS"
!ifndef VERSION
    !define VERSION "0.1.0"
!endif
!define SERVICE "TorDNS"
!define REGISTRE_UNINSTALL "Software\Microsoft\Windows\CurrentVersion\Uninstall\TorDNS"

; Appelé par scripts/ci/client-windows.sh :
;   makensis /DARCH=x86_64 /DBINAIRE=... /DWINTUN=... /DSORTIE=... tordns.nsi
!ifndef ARCH
    !define ARCH "x86_64"
!endif
!ifndef BINAIRE
    !define BINAIRE "..\dist\client-windows\${ARCH}\tordns-client.exe"
!endif
!ifndef WINTUN
    !define WINTUN "..\dist\client-windows\${ARCH}\wintun.dll"
!endif
!ifndef SORTIE
    !define SORTIE "..\dist\client-windows\${ARCH}\TorDNS-${VERSION}-${ARCH}-setup.exe"
!endif
!if "${ARCH}" == "aarch64"
    !define ATTENDU "Arm64"
!else
    !define ATTENDU "X64"
!endif

Name "${PRODUIT} ${VERSION} (${ARCH})"
OutFile "${SORTIE}"
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
    ; Un installateur aarch64 ne doit pas s'installer sur x64, et inversement.
    ; OSArchitecture décrit le système natif, même sous émulation x64.
    nsExec::ExecToStack 'powershell -NoProfile -NonInteractive -Command "Write-Host -NoNewline ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"'
    Pop $0
    Pop $1
    StrCmp $1 "${ATTENDU}" architecture_ok
    MessageBox MB_ICONSTOP "Cet installateur est prévu pour ${ARCH} ; ce système n'est pas ${ATTENDU}."
    Abort
    architecture_ok:

    ; Une mise à jour lancée par le service doit pouvoir remplacer l'exécutable.
    ExecWait 'sc stop ${SERVICE}'
    Sleep 2000
    SetOutPath "$INSTDIR"
    File "${BINAIRE}"
    File "${WINTUN}"

    CreateDirectory "$COMMONPROGRAMDATA\TorDNS"
    CreateDirectory "$COMMONPROGRAMDATA\TorDNS\maj"
    ; Relecture du 23/11 : ProgramData laisse tout utilisateur CRÉER des fichiers dans ses
    ; sous-dossiers. La tâche de mise à jour tourne en SYSTEM et fait confiance à maj\ (état,
    ; clé de rotation, installateurs) : un utilisateur sans droits pouvait y poser sa propre clé
    ; ou échanger l'installateur vérifié. Propriétaire = Administrateurs, héritage coupé,
    ; écriture réservée à SYSTEM et aux Administrateurs, lecture seule pour les Utilisateurs.
    nsExec::ExecToLog 'icacls "$COMMONPROGRAMDATA\TorDNS" /setowner *S-1-5-32-544 /T /C /Q'
    nsExec::ExecToLog 'icacls "$COMMONPROGRAMDATA\TorDNS" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /Q'
    nsExec::ExecToLog 'icacls "$COMMONPROGRAMDATA\TorDNS\*" /reset /T /C /Q'
    ; L'installateur courant sert de retour arrière à la première mise à jour (sans lui,
    ; maj.rs refusait toute mise à jour : « aucun installateur précédent »).
    StrCmp "$EXEPATH" "$COMMONPROGRAMDATA\TorDNS\maj\TorDNS-setup.exe" installateur_en_place 0
        CopyFiles /SILENT "$EXEPATH" "$COMMONPROGRAMDATA\TorDNS\maj\TorDNS-setup.exe"
    installateur_en_place:
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
        FileWrite $0 "mode_adresse = coeur$\r$\n"
        FileWrite $0 "dnssec = oui$\r$\n"
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
    ExecWait 'sc start ${SERVICE}'

    ; Vérification quotidienne du manifeste signé, par le service (SYSTEM).
    ExecWait 'schtasks /Create /TN TorDNS-Maj /TR "\"$INSTDIR\tordns-client.exe\" --maj" /SC DAILY /ST 04:00 /RU SYSTEM /RL HIGHEST /F'
SectionEnd

Section "Uninstall"
    ExecWait 'sc stop ${SERVICE}'
    ExecWait 'sc delete ${SERVICE}'
    ExecWait 'schtasks /Delete /TN TorDNS-Maj /F'
    Delete "$INSTDIR\tordns-client.exe"
    Delete "$INSTDIR\wintun.dll"
    Delete "$INSTDIR\desinstaller.exe"
    RMDir "$INSTDIR"
    DeleteRegKey HKLM "Software\TorDNS"
    DeleteRegKey HKLM "${REGISTRE_UNINSTALL}"
    ; La configuration (adresse .onion) n'est pas un secret mais reste propre
    ; à l'utilisateur : elle n'est pas supprimée automatiquement.
SectionEnd
