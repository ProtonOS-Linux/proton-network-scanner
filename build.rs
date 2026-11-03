//! Build script: for Windows builds, embed the icon, version information
//! (shown in Properties → Details and in the installer/SmartScreen dialogs)
//! and an application manifest into the .exe. Does nothing on Linux.

fn main() {
    println!("cargo:rerun-if-changed=packaging/windows/proton-ip-scanner.ico");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let mut res = winresource::WindowsResource::new();
    // Cross-compiling from Linux uses the MinGW resource compiler.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu") && cfg!(not(windows)) {
        res.set_windres_path("x86_64-w64-mingw32-windres");
        res.set_ar_path("x86_64-w64-mingw32-ar");
    }
    res.set_icon("packaging/windows/proton-ip-scanner.ico")
        .set("ProductName", "Proton IP Scanner")
        .set("FileDescription", "Proton IP Scanner - network and vulnerability scanner")
        .set("CompanyName", "Proton OS")
        .set("LegalCopyright", "Copyright (C) 2026 Proton OS contributors. GPL-3.0-or-later.")
        .set("OriginalFilename", "proton-ip-scanner.exe")
        .set("InternalName", "proton-ip-scanner")
        .set("ProductVersion", &version)
        .set("FileVersion", &version)
        .set("Comments", "https://www.protonos.org")
        .set_manifest(MANIFEST);
    if let Err(e) = res.compile() {
        panic!("could not embed the Windows resources: {e}");
    }
}

/// Runs as the normal user (never asks for admin), declares Windows 10/11
/// support and per-monitor DPI awareness (sharp text on high-DPI screens).
const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="ProtonOS.ProtonIPScanner" version="1.0.0.0" processorArchitecture="amd64"/>
  <description>Proton IP Scanner</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"#;
