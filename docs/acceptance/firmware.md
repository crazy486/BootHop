# Firmware and reboot acceptance record

Status: **NOT ACCEPTED**. This is a run sheet, not evidence that a machine was
changed. Development packages, staged Windows artifacts, and fake tests do not
fill any result below. Windows1W research is complete with a limitation, but
Windows production W0/W1 have not started.

## Windows production authorization boundary

Windows production acceptance is **NOT STARTED**. The integrated production
software may
compile, stage, and statically audit a package, but those checks never invoke a
firmware API, UAC/helper, ACL change, BCD operation, shutdown, or reboot.
Windows1W is the separate read-only native-API research record and remains
`PASS_WITH_LIMITATION`; it is not W1 and does not close Linux Stage 5. Linux
Stage 5 is the separate post-boot closure and remains pending.

The detailed Windows runbook is
[windows-real-system.md](windows-real-system.md). W0--W5 require separate,
fresh authorization and private evidence:

0. **W0 install:** exact-artifact fixed layout and protected ProgramData ACL;
   no executable launch, firmware access, configuration, or reboot. It remains
   blocked until an approved installer/provisioner exists.
1. **W1 read-only:** production Inspect reads `GetFirmwareType`, `BootOrder`,
   `BootCurrent`, and the deduplicated union of `Boot####` entries referenced by
   those two controls. It validates shared parsing/canonical identity and
   privilege restoration. It deliberately does not read `BootNext`.
2. **W2 configure:** elevated helper and protected ProgramData record/ACL
   validation only; no firmware write or reboot.
3. **W3 pre-switch:** target identity and BootNext conflict observation only.
4. **W4 mutation:** blocked until an approved mapping distinguishes confirmed
   BootNext absence from unavailable state; then one write/readback with reboot
   interlocked off.
5. **W5 switch:** blocked by the same mapping gate; then one authorized
   Windows-to-Linux switch and reboot with post-boot evidence.

The observed Win32 203 (`ERROR_ENVVAR_NOT_FOUND`) result is retained as a raw
error by the production policy; it is not evidence of absent `BootNext`.
Code-signing, an atomic installer, interrupted-upgrade recovery, and downgrade
prevention are also release requirements and are not supplied by staging.

Run this checklist only for its separately authorized stage. Record the exact
host, kernel/OS, firmware vendor and version, boot mode, systemd/polkit versions
(if Linux), package checksum, and operator. Do not replace a missing value with
“passed”. Preserve before/after command output and screenshots with the run ID.

| Field | Linux host / UEFI VM | Windows 11 host |
|---|---|---|
| Environment and authorization/run ID | **Not run** | **Not run (W0/W1)** |
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

The multi-stage procedure below begins only after W0 and W1. It does not alter
the narrower W1 contract above.

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
cargo test --workspace --locked
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
packaging/linux/tests/installer_fake.sh
```

They use fake platform calls or a temporary staging directory and must never
invoke efivarfs, BootNext/BootOrder, system D-Bus, a GUI event loop, pkexec, a
production helper, or reboot.
