// Capability-audit fixture: this symbol is allowed only in the platform
// firmware backend. It is never compiled or shipped.
fn allowed_backend_symbol() {
    let _ = "GetFirmwareEnvironmentVariableExW";
    let _ = "SetFirmwareEnvironmentVariableExW";
}
