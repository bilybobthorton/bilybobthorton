; SentinelCore Windows Installer
; Built with NSIS (https://nsis.sourceforge.io/)
;
; Prerequisites:
;   1. Install NSIS on your build machine
;   2. Cross-compile the agent:
;        cargo build --release --target x86_64-pc-windows-gnu
;   3. Copy the binary here:
;        cp target/x86_64-pc-windows-gnu/release/sentinel-agent.exe install/windows/
;   4. Build:
;        makensis sentinel.nsi
;
; Output: SentinelCore-Setup-x64.exe

!define APP_NAME      "SentinelCore Agent"
!define APP_VERSION   "0.1.0"
!define PUBLISHER     "SentinelCore"
!define INSTALL_DIR   "$PROGRAMFILES64\SentinelCore"
!define SERVICE_NAME  "SentinelCoreAgent"
!define BINARY        "sentinel-agent.exe"
!define UNINSTALLER   "Uninstall-SentinelCore.exe"
!define REG_KEY       "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelCore"

; ── NSIS metadata ─────────────────────────────────────────────────────────────
Name        "${APP_NAME} ${APP_VERSION}"
OutFile     "SentinelCore-Setup-x64.exe"
InstallDir  "${INSTALL_DIR}"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
Unicode True

; Modern UI
!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "WinVer.nsh"

!define MUI_ABORTWARNING
!define MUI_ICON        "..\..\..\..\assets\shield.ico"
!define MUI_UNICON      "..\..\..\..\assets\shield.ico"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
Page custom ConfigPage ConfigPageLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ── Config page variables ─────────────────────────────────────────────────────
Var ApiUrl
Var ApiKey
Var AutoQuarantine
Var hApiUrl
Var hApiKey
Var hAutoQ

Function ConfigPage
    nsDialogs::Create 1018
    Pop $0

    ${NSD_CreateLabel} 0 0 100% 12u "SentinelCore API URL:"
    ${NSD_CreateText} 0 14u 100% 14u "http://localhost:8000"
    Pop $hApiUrl

    ${NSD_CreateLabel} 0 34u 100% 12u "API Key (leave blank to log locally only):"
    ${NSD_CreateText} 0 48u 100% 14u ""
    Pop $hApiKey

    ${NSD_CreateCheckBox} 0 70u 100% 14u "Enable auto-quarantine on confirmed threats"
    Pop $hAutoQ

    nsDialogs::Show
FunctionEnd

Function ConfigPageLeave
    ${NSD_GetText} $hApiUrl $ApiUrl
    ${NSD_GetText} $hApiKey $ApiKey
    ${NSD_GetState} $hAutoQ $AutoQuarantine
FunctionEnd

; ── Install section ───────────────────────────────────────────────────────────
Section "Install" SecInstall
    SetOutPath "${INSTALL_DIR}"

    ; Stop existing service if running
    ExecWait 'sc stop "${SERVICE_NAME}"' $0
    Sleep 2000

    ; Copy binary
    File "${BINARY}"

    ; Write config file
    FileOpen $0 "${INSTALL_DIR}\agent.env" w
    FileWrite $0 "SENTINEL_API_URL=$ApiUrl$\r$\n"
    FileWrite $0 "SENTINEL_API_KEY=$ApiKey$\r$\n"
    FileClose $0

    ; Register Windows service
    ${If} $AutoQuarantine == ${BST_CHECKED}
        ExecWait 'sc create "${SERVICE_NAME}" \
            binPath= "\"${INSTALL_DIR}\${BINARY}\" run \
                --api-url \"$ApiUrl\" \
                --api-key \"$ApiKey\" \
                --auto-quarantine" \
            DisplayName= "${APP_NAME}" \
            start= auto \
            obj= LocalSystem' $0
    ${Else}
        ExecWait 'sc create "${SERVICE_NAME}" \
            binPath= "\"${INSTALL_DIR}\${BINARY}\" run \
                --api-url \"$ApiUrl\" \
                --api-key \"$ApiKey\"" \
            DisplayName= "${APP_NAME}" \
            start= auto \
            obj= LocalSystem' $0
    ${EndIf}

    ExecWait 'sc description "${SERVICE_NAME}" \
        "SentinelCore real-time malware detection agent"' $0

    ; Set recovery options — restart on failure
    ExecWait 'sc failure "${SERVICE_NAME}" reset= 86400 actions= restart/5000/restart/10000/restart/30000' $0

    ; Start the service
    ExecWait 'sc start "${SERVICE_NAME}"' $0

    ; Write uninstall registry key
    WriteRegStr HKLM "${REG_KEY}" "DisplayName"     "${APP_NAME}"
    WriteRegStr HKLM "${REG_KEY}" "DisplayVersion"  "${APP_VERSION}"
    WriteRegStr HKLM "${REG_KEY}" "Publisher"       "${PUBLISHER}"
    WriteRegStr HKLM "${REG_KEY}" "InstallLocation" "${INSTALL_DIR}"
    WriteRegStr HKLM "${REG_KEY}" "UninstallString" '"${INSTALL_DIR}\${UNINSTALLER}"'
    WriteRegDWORD HKLM "${REG_KEY}" "NoModify" 1
    WriteRegDWORD HKLM "${REG_KEY}" "NoRepair" 1

    ; Write uninstaller
    WriteUninstaller "${INSTALL_DIR}\${UNINSTALLER}"

    ; Start menu shortcut
    CreateDirectory "$SMPROGRAMS\SentinelCore"
    CreateShortcut  "$SMPROGRAMS\SentinelCore\SentinelCore Agent.lnk" \
                    "${INSTALL_DIR}\${BINARY}"
    CreateShortcut  "$SMPROGRAMS\SentinelCore\Uninstall SentinelCore.lnk" \
                    "${INSTALL_DIR}\${UNINSTALLER}"

    MessageBox MB_OK "${APP_NAME} ${APP_VERSION} installed and started as a Windows service.$\n$\nService name: ${SERVICE_NAME}"
SectionEnd

; ── Uninstall section ─────────────────────────────────────────────────────────
Section "Uninstall"
    ExecWait 'sc stop "${SERVICE_NAME}"'
    Sleep 2000
    ExecWait 'sc delete "${SERVICE_NAME}"'
    Sleep 1000

    Delete "${INSTALL_DIR}\${BINARY}"
    Delete "${INSTALL_DIR}\agent.env"
    Delete "${INSTALL_DIR}\${UNINSTALLER}"
    RMDir  "${INSTALL_DIR}"

    Delete "$SMPROGRAMS\SentinelCore\SentinelCore Agent.lnk"
    Delete "$SMPROGRAMS\SentinelCore\Uninstall SentinelCore.lnk"
    RMDir  "$SMPROGRAMS\SentinelCore"

    DeleteRegKey HKLM "${REG_KEY}"

    MessageBox MB_OK "${APP_NAME} has been removed from this computer."
SectionEnd
