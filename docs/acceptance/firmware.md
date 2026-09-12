# Firmware and reboot acceptance record

Status: **NOT ACCEPTED**. This is a run sheet, not evidence that a machine was
changed. The Linux development package and fake tests do not fill any result
below. Windows 11 evidence is blocked by the outstanding 1W real-machine gate;
the Linux package does not provide a Windows implementation.

Run this checklist only after explicit authorization. Record the exact host,
kernel/OS, firmware vendor and version, boot mode, systemd/polkit versions (if
Linux), package checksum, and operator. Do not replace a missing value with
“passed”. Preserve before/after command output and screenshots with the run ID.

| Field | Linux host / UEFI VM | Windows 11 host |
|---|---|---|
| Environment and authorization/run ID | **Not run** | **Not run (1W gate)** |
| Package and binary SHA-256 | **Not measured** | **Not measured** |
| Before BootOrder | **Not read** | **Not read** |
| Before BootNext (including absent vs value) | **Not read** | **Not read** |
| Selected Boot#### and exact description | **Not selected** | **Not selected** |
| Interface and privilege result | **Not run** | **Not run** |
| BootNext write request | **Not run** | **Not run** |
| Independent BootNext read-back | **Not run** | **Not run** |
| Reboot return / reply evidence | **Not run** | **Not run** |
| Manually observed destination OS | **Not observed** | **Not observed** |
| After BootOrder and BootNext | **Not read** | **Not read** |
| Pass/fail and residual-risk notes | **Not assessed** | **Not assessed** |

## Authorized procedure (one host at a time)

1. Confirm UEFI mode, record firmware details, and capture BootOrder,
   BootCurrent, BootNext (or an explicit not-found result), and every selected
   Boot#### identity. Save raw output privately; do not paste firmware payloads
   into ordinary CI logs.
2. Confirm the fixed protected layout and helper checksum. Run `inspect` first.
   A missing trusted record is a configuration state only after the layout and
   persistent lock have passed validation. Missing layout/lock is an environment
   error; it must not be silently repaired.
3. With the operator watching, select the exact target and request one switch.
   Verify the only firmware mutation requested is a six-byte Linux efivarfs
   BootNext value (attributes plus little-endian `u16`), or the corresponding
   Windows API operation. Do not write BootOrder or delete/restore variables.
4. Record the independent read-back and the helper's explicit reboot reply.
   A lost reply is **Unknown**, never success. Observe which OS actually starts
   and record the operator's observation separately from the helper response.
5. After the OS starts, capture BootOrder and BootNext again. Compare all
   values, note external changes, and mark pass/fail only when every required
   field has evidence. Repeat in the opposite direction only after the first
   run is complete and separately authorized.

The ordinary commands below are intentionally not this procedure:

```text
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
packaging/linux/tests/installer_fake.sh
```

They use fake platform calls or a temporary staging directory and must never
invoke efivarfs, BootNext/BootOrder, system D-Bus, a GUI event loop, pkexec, a
production helper, or reboot.
