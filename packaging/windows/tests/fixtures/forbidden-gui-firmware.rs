// Capability-audit fixture: a GUI firmware symbol must fail the audit.
fn forbidden_gui_symbol() {
    let _ = "SetFirmwareEnvironmentVariableExW";
}
