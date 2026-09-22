# BootHop Quick Hop product amendment

Date: 2026-09-23. Status: user-directed product reset; this amendment supersedes conflicting daily-use interaction requirements in the earlier BootHop design while retaining its safety contracts.

## Product contract

BootHop is a small “configure once, then double-click to switch to the other OS” tool. Its ordinary configured startup path is:

1. use the ordinary-user cache only as a hint that configuration may exist;
2. send exactly one `Switch` request for the fixed opposite host OS;
3. let the existing privileged helper/core reload the protected record and live firmware, validate identity, observe BootNext conflict state, write/read back BootNext when safe, and request a normal reboot;
4. show no main window on the accepted success path.

The cache never authorizes a target and never supplies identity to Switch. Missing, unreadable, wrong-OS, or otherwise unusable cache state opens the existing minimal setup/error UI and sends no automatic Switch. Any Switch error or uncertain result opens that UI with bounded diagnostics and is never retried automatically.

`--setup` and `--settings` explicitly open the setup UI without an automatic Switch. Inspect and Configure remain available only for first configuration, target replacement, and recovery. Internal validation remains mandatory but is not a user interaction.

## Retained safety contract

The existing core flow, canonical identity, protected record, operation lock, authenticated helper boundary, BootNext conflict/readback rules, safe rollback limits, normal reboot semantics, and fake-only automated tests remain authoritative. Automated tests must never access real firmware or reboot. This amendment does not authorize real BootNext, BootOrder, Boot####, BCD, reboot, shutdown, or security-policy changes.

## Permission scope

This first Quick Hop increment reuses the existing one-shot `pkexec` and Windows `runas` helpers. Passwordless Linux daily Switch requires a separately reviewed operation-specific polkit authorization boundary; changing the current action to blanket `allow_active=yes` would also relax Configure and is not approved. Reliable Windows no-UAC operation requires an install-time protected broker/service or equivalent larger integration and is deferred. Smart App Control 4551 remains a signing/host blocker, not a Switch/core defect.

## Superseded interaction text

This amendment replaces the older requirement that normal daily use opens the single main window and waits for an explicit Switch click. The existing window remains the setup/settings/error surface. No daemon, service, scheduled task, autostart component, second executable, or new configuration layer is introduced by this increment.
