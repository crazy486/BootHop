// Capability-audit fixture: these capabilities are forbidden in a GUI or
// arbitrary source location. It is never compiled or shipped.
fn forbidden_symbols() {
    let _ = "SetFirmwareEnvironmentVariableExW";
    let _ = "AdjustTokenPrivileges";
    let _ = "InitiateSystemShutdownExW";
    let _ = "CreateProcessW";
    let _ = "LoadLibraryW";
    let _ = "GetProcAddress";
    let _ = "bcdedit";
}
