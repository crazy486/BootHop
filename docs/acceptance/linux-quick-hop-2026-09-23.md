# Linux → Windows Quick Hop acceptance — 2026-09-23

Status: **NOT EXECUTED — PRE-FLIGHT BLOCKED**

This record covers the first attempted real Quick Hop preparation on the
Arch Linux host. No production Switch was launched because the required
preconditions were not satisfied. It is not a firmware or reboot result.

## Git identity

- Branch: `boothop-simple`
- Local HEAD: `bc5d7a9481f1994666ccbcab7c05c7b9d4e64af7`
- `origin/boothop-simple`: the same commit
- Tracked worktree: clean

## Read-only pre-flight observations

- `/etc/os-release`: Arch Linux.
- UEFI variable directory exists.
- `efivarfs` is mounted read-only (`ro`). A BootNext write cannot be
  authorized while this condition remains.
- systemd: 261.3; polkit: 127; graphical session: Wayland.
- `Boot0003`, `BootCurrent`, and `BootOrder` variable names were present.
- No `BootNext` variable name was observed during this pre-flight check; this
  is only an observation and not a Switch result.
- `cargo` and `rustup` were not available in the current environment, so an
  exact-HEAD release build could not be produced.
- Existing installed GUI/helper files were present, but their build identity
  could not be established as the current exact HEAD release artifact.
- `/var/lib/boothop/targets.json` and `/var/lib/boothop/operation.lock` were
  absent. Therefore no authoritative protected Windows target record was
  available for Quick Hop.
- A user cache file existed, but cache is not an authority and cannot replace
  the protected record.

## Execution result

- Quick Hop executable: **not launched**.
- `Request::Switch`: **not sent**.
- pkexec/polkit helper: **not invoked**.
- Protected target validation: **not reached**.
- BootNext write: **not performed**.
- BootNext read-back: **not performed**.
- logind reboot request: **not sent**.
- Reboot: **not performed**.
- Actual arrival in Windows: **not observed**.
- BootOrder/Boot####/BCD mutation: **none performed by this attempt**.

## Blocking conditions and safe next step

The acceptance stops before any mutation. A future separately continued run
must first restore a writable efivarfs mount through the normal system setup,
provide the pinned Rust toolchain, build and install the exact HEAD, and use
the existing Configure flow to establish a protected Windows target record.
Those changes are provisioning steps; they are not claimed here and must be
verified before another single authorized Quick Hop attempt.

No automatic retry was performed. No EFI variable, BootOrder, boot entry,
BCD, security policy, or reboot state was modified.
