# Task 3 implementer report — one-shot Arch setup

## Status

DONE_WITH_CONCERNS. The fakeable setup runner, failure report, atomic marker save,
distinct root-only CLI, package layout, and maintenance guide are implemented.
The production setup adapter is deliberately **not** enabled. The executable
validates root and exact arguments, then exits with an explicit unavailable
error without touching host preset, ESP, efivarfs, mkinitcpio, GRUB, or reboot.
This is a material integration limit, not a claim that direct Arch setup works.

## Implementation

- Added a linear runner using Task 2's plan and renderer, Task 1's exact
  load-option and firmware primitives, and a SHA-256 marker identity. It checks
  initial absence, packaged publisher, and unused ID before preset mutation;
  then edits the selected preset, installs the hook, clears the stage, builds,
  inspects the artifact, creates and reads back one Boot####, appends to the
  latest BootOrder, and saves the marker. The firmware proof rechecks BootNext
  and the exact new entry immediately before its latest-order append.
- Added injected single-attempt backend operations and read-only failure
  observations. A failed observation is Unknown; it is never interpreted as
  absent. The report includes stage, candidate ID, preset stanza, hook
  exactness, artifact, entry exactness, full order, and BootNext.
- Added a locked, temp-file, fsynced, rename-based identity save at the fixed
  root-owned protected store. Existing markers stop; uncertain directory sync
  returns durability-unknown without retry.
- Added an independent `boothop-arch-setup` executable and strict
  `--kernel FLAVOR --apply` parser. The daily helper IPC and passwordless
  polkit action have no route to it. The package installs this binary
  root-owned at mode 0700 and the Task 2 publisher at fixed
  `/usr/lib/boothop/boothop-uki-publish`, root-owned mode 0755. No setup
  polkit action is installed.
- Added read-only partial-state checks and administrator-controlled cleanup
  guidance. Package uninstall removes package assets only; it does not claim
  to remove setup configuration, firmware objects, or identity.

## TDD evidence

### RED

- `cargo test -p boothop-platform --test arch_setup` failed with unresolved
  `boothop_platform::linux::arch_setup` before runner implementation.
- `cargo test -p boothop-helper --test arch_setup_dispatch` failed with
  unresolved `boothop_helper::arch_setup_cli` before CLI implementation.
- The existing installer fixture first failed when its missing-parent cleanup
  encountered the newly packaged setup and publisher files; the fixture was
  updated to remove those staged files before its intended directory check.

### GREEN

- `cargo test -p boothop-platform --test arch_setup`: 6 passed.
  The fake covers successful linear order, interruption at preset/hook/stage
  clear/build/artifact/entry/readback/order/readback/marker boundaries,
  unknown observations, existing artifact refusal, and locked atomic marker
  save plus uncertain durability. No firmware mutation is retried.
- `cargo test -p boothop-helper --test arch_setup_dispatch`: 3 passed.
  Root, apply interlock, unknown arguments, path-like flavor, Boot ID, and
  daily policy isolation are checked.
- `cargo test --workspace --all-targets`: passed, exit 0.
- `bash packaging/linux/tests/installer_fake.sh`: 8 passed.
- `bash packaging/linux/package-smoke.sh`: passed; private temp package
  contains fixed publisher and setup binary with root-owned archive metadata
  and required modes, and only the existing helper polkit action.
- `cargo fmt --all -- --check`, `git diff --check`, and
  `cargo clippy -p boothop-platform -p boothop-helper --lib --bins -- -D warnings`:
  passed.
- `cargo clippy -p boothop-platform -p boothop-helper --all-targets -- -D warnings`
  was run but fails on a pre-existing Task 1 test lint at
  `crates/platform/tests/setup_firmware.rs:135`
  (`field_reassign_with_default`). This task did not alter that test.

## Self-review and integration limits

- The code adds no journal, rollback, automatic uninstall or recovery, Windows
  ESP reader, or lifecycle IPC. Tests use injected fakes and temp package
  staging only. No host efivarfs/ESP/preset/GRUB write, real mkinitcpio,
  pkexec, setup execution, reboot, or root install occurred.
- A production adapter remains necessary for live package-update-route
  verification, safe guarded preset and exact post-hook installation, trusted
  publisher ownership checks, serialized initial mkinitcpio invocation with
  root-only initial mode, stale-stage removal, artifact inspection, and
  efivarfs operations. Those operations were not safely implementable or
  testable under the no-host-mutation constraint here. The packaged CLI
  refuses to proceed rather than presenting fake setup success.
- The runner's backend contract requires these operations, but fake tests
  cannot establish that the host's package hook rebuilds the selected preset
  or that its initial/update modes are correctly installed. Isolated Arch
  acceptance remains required before enabling the adapter.
- A trusted root peer could race the marker's absent check and rename. The
  local threat model excludes adversarial root peers; the operation lock
  serializes BootHop operations. An uncertain write or sync result is terminal.
