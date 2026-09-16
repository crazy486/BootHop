// Capability-audit fixture: token privilege APIs belong in the platform
// privilege backend. It is never compiled or shipped.
fn allowed_privilege_backend_symbol() {
    let _ = "OpenProcessToken";
    let _ = "AdjustTokenPrivileges";
}
