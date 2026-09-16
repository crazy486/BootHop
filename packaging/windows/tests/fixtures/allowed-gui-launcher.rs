// Capability-audit fixture: only the fixed GUI launcher may start the helper.
fn allowed_gui_launcher_symbol() {
    let _ = "ShellExecuteExW";
    let _ = "CreateProcessW";
}
