; Proton IP Scanner — Windows installer (NSIS 3, Modern UI 2).
;
; Build (Linux or Windows):
;   makensis -DVERSION=1.3.0 -DEXE=path\to\proton-ip-scanner.exe -DOUTDIR=dist packaging/windows/installer.nsi
;
; What it does:
;   * installs to "C:\Program Files\Proton IP Scanner" (per machine, needs admin once)
;   * Start menu shortcut (always) and Desktop shortcut (optional, on by default)
;   * an entry in Settings → Apps / "Add or remove programs", with a proper uninstaller
;   * a Windows Firewall rule that lets the scanner receive answers from devices on
;     PRIVATE and DOMAIN networks only (never Public), so name lookups work and Windows
;     does not pop up its firewall question on first scan
;   * the app itself always runs as a normal user (its manifest says "asInvoker")

; 64-bit installer (the app is 64-bit only, Windows 10/11).
Target amd64-unicode
SetCompressor /SOLID lzma
ManifestDPIAware true

!ifndef VERSION
  !error "Pass -DVERSION=x.y.z"
!endif
!ifndef EXE
  !define EXE "..\..\target\release\proton-ip-scanner.exe"
!endif
!ifndef OUTDIR
  !define OUTDIR "."
!endif

!define APPNAME   "Proton IP Scanner"
!define PUBLISHER "Proton OS"
!define WEBSITE   "https://www.protonos.org"
!define REPO      "https://github.com/ProtonOS-Linux/proton-network-scanner"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\ProtonIPScanner"
!define FWRULE    "Proton IP Scanner"

Name "${APPNAME} ${VERSION}"
OutFile "${OUTDIR}\ProtonIPScanner-${VERSION}-Setup.exe"
InstallDir "$PROGRAMFILES64\${APPNAME}"
InstallDirRegKey HKLM "${UNINSTKEY}" "InstallLocation"
RequestExecutionLevel admin
BrandingText "${PUBLISHER} · ${WEBSITE}"

; Version information of the installer itself (Properties → Details).
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName"     "${APPNAME}"
VIAddVersionKey "CompanyName"     "${PUBLISHER}"
VIAddVersionKey "FileDescription" "${APPNAME} installer"
VIAddVersionKey "FileVersion"     "${VERSION}"
VIAddVersionKey "ProductVersion"  "${VERSION}"
VIAddVersionKey "LegalCopyright"  "Copyright (C) 2026 Proton OS contributors. GPL-3.0-or-later."

!include "MUI2.nsh"
!include "x64.nsh"

!define MUI_ICON   "proton-ip-scanner.ico"
!define MUI_UNICON "proton-ip-scanner.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEFINISHPAGE_BITMAP   "welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "welcome.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "header.bmp"
!define MUI_WELCOMEPAGE_TEXT "This will install ${APPNAME} ${VERSION}: find the devices on your network, their names, manufacturers and open ports, and check them for known vulnerabilities.$\r$\n$\r$\nOnly scan networks you own or have permission to scan.$\r$\n$\r$\nClick Next to continue."
!define MUI_FINISHPAGE_RUN "$INSTDIR\proton-ip-scanner.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start ${APPNAME}"
!define MUI_FINISHPAGE_LINK "Project page and updates"
!define MUI_FINISHPAGE_LINK_LOCATION "${REPO}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "${APPNAME} needs 64-bit Windows 10 or 11."
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

Section "${APPNAME} (required)" SecApp
  SectionIn RO
  SetShellVarContext all
  SetOutPath "$INSTDIR"
  File "/oname=proton-ip-scanner.exe" "${EXE}"
  File "/oname=LICENSE.txt" "..\..\LICENSE"
  File "/oname=README.md" "..\..\README.md"
  File "proton-ip-scanner.ico"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateShortcut "$SMPROGRAMS\${APPNAME}.lnk" "$INSTDIR\proton-ip-scanner.exe" "" "$INSTDIR\proton-ip-scanner.ico" 0 SW_SHOWNORMAL "" "Network and vulnerability scanner"

  ; Settings → Apps / Add or remove programs.
  WriteRegStr   HKLM "${UNINSTKEY}" "DisplayName"          "${APPNAME}"
  WriteRegStr   HKLM "${UNINSTKEY}" "DisplayVersion"       "${VERSION}"
  WriteRegStr   HKLM "${UNINSTKEY}" "Publisher"            "${PUBLISHER}"
  WriteRegStr   HKLM "${UNINSTKEY}" "DisplayIcon"          "$INSTDIR\proton-ip-scanner.ico"
  WriteRegStr   HKLM "${UNINSTKEY}" "InstallLocation"      "$INSTDIR"
  WriteRegStr   HKLM "${UNINSTKEY}" "UninstallString"      '"$INSTDIR\uninstall.exe"'
  WriteRegStr   HKLM "${UNINSTKEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegStr   HKLM "${UNINSTKEY}" "URLInfoAbout"         "${WEBSITE}"
  WriteRegStr   HKLM "${UNINSTKEY}" "URLUpdateInfo"        "${REPO}/releases"
  WriteRegStr   HKLM "${UNINSTKEY}" "HelpLink"             "${REPO}"
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "EstimatedSize" 30000

  ; Firewall: allow answers from devices on private/domain networks only.
  nsExec::Exec 'netsh advfirewall firewall delete rule name="${FWRULE}"'
  nsExec::Exec 'netsh advfirewall firewall add rule name="${FWRULE}" dir=in action=allow program="$INSTDIR\proton-ip-scanner.exe" enable=yes profile=private,domain description="Lets Proton IP Scanner receive replies from devices on your local network (not on public networks)."'
SectionEnd

Section "Desktop shortcut" SecDesktop
  SetShellVarContext all
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\proton-ip-scanner.exe" "" "$INSTDIR\proton-ip-scanner.ico" 0
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecApp}     "The scanner itself, a Start menu shortcut and the uninstaller."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "A shortcut on the desktop."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  SetRegView 64
  SetShellVarContext all
  nsExec::Exec 'netsh advfirewall firewall delete rule name="${FWRULE}"'
  Delete "$SMPROGRAMS\${APPNAME}.lnk"
  Delete "$DESKTOP\${APPNAME}.lnk"
  Delete "$INSTDIR\proton-ip-scanner.exe"
  Delete "$INSTDIR\proton-ip-scanner.ico"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTKEY}"
  ; Your settings and the CVE database (in your user profile) are kept, so a
  ; reinstall picks them up again.
SectionEnd
