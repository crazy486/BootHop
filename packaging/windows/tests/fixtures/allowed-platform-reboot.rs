// Capability-audit fixture: reboot APIs belong in the platform reboot backend.
fn allowed_reboot_backend_symbol() {
    let _ = "InitiateSystemShutdownExW";
}
