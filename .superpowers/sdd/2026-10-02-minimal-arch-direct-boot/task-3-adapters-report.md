# Task 3 continuation — native Arch setup adapters

## Status

DONE_WITH_CONCERNS. The production adapter methods now exist, but the packaged
`boothop-arch-setup` executable remains explicitly fail closed and does not
construct `NativeArchCalls` or invoke `run_arch_setup`. No actual setup
operation, root install, mkinitcpio build, ESP or efivarfs write, or reboot
was run. Real machine and isolated UEFI acceptance remain separate gates.

## Implemented

- Added `SystemArchSetupBackend<C: ArchSystemCalls>` as the concrete
  `ArchSetupBackend`, `ArchSetupSource`, and `SetupFirmware` adapter.
  Its I/O is injected through one narrow trait, with production methods in
  `NativeArchCalls`. The daily helper and standalone setup binary do not
  instantiate the native type.
- Read-only planning enumerates installed preset names, requires the persistent
  root-owned `/etc/kernel/cmdline`, checks the SecureBoot global variable,
  and obtains exactly one mounted vfat ESP at `/boot` or `/efi` with GPT ESP
  type, partition number/start/size, and UEFI-order PARTUUID bytes. Unknown
  sources and layouts fail closed.
- The package-update route reads the fixed libalpm hook and script under
  trusted parent paths, checks that the selected flavor has exactly one
  installed module `pkgbase` and kernel image, checks the selected preset
  and post-hook route, rejects `--nopost`, and requires exact SHA-256
  fingerprints of the observed supported hook and script. Package changes
  therefore require a separately reviewed fingerprint update. The
  `kernel-install` `--nopost` path is unsupported.
- Setup methods verify the installed publisher is root-owned mode 0755,
  atomically replace only the selected root-owned mode-0644 preset when
  its bytes still equal the read snapshot, install only one exclusive
  root-owned fixed post hook, create a trusted BootHop directory if needed,
  remove a trusted stale stage, construct only `/usr/bin/mkinitcpio -p
  <validated flavor>` with `BOOTHOP_ARCH_INITIAL=1`, and inspect the
  published final image. The hook normally calls the fixed publisher in
  update mode; only the explicit initial environment selects initial mode.
  The publisher performs the full UKI validation and same-ESP rename.
- Native firmware I/O opens the fixed efivarfs directory with NOFOLLOW and
  filesystem-type validation. It enumerates the complete raw namespace,
  separates the four-byte efivarfs attributes from payloads, uses
  `O_CREAT|O_EXCL` for one Boot#### creation, and makes one BootOrder
  replacement write without `O_TRUNC` or retry. Task 1's runner still
  controls fresh BootNext/entry/order checks and exact readbacks.
- Native construction holds both the existing BootHop operation lock and an
  exclusive pacman `db.lck` for the whole setup. This blocks normal package
  transactions while the initial build shares the fixed stage path. The
  native marker save delegates to the existing locked atomic identity store.
  Failure observations use only reads and preserve unknown states.

## TDD evidence

### RED

- `cargo test -p boothop-platform --test arch_setup_system` initially failed
  with unresolved import `linux::arch_setup_system`. This was the expected
  pre-implementation failure.

### GREEN

- `cargo test -p boothop-platform --lib --test arch_setup_system --test
  arch_setup`: passed. Library: 34/34, existing runner: 6/6, new injected
  adapter: 6/6. Adapter fakes cover exact route and `--nopost` rejection,
  stage clearing before build, fixed process/hook inputs, successful order,
  precondition failures, and uncertain EFI writes with one attempt and
  read-only residual observations.
- Native unit tests use an isolated ordinary temporary directory to verify
  exclusive descriptor creation and one-call writes; pure tests verify GPT
  UUID byte order and reject malformed command-pair output. They do not
  open real efivarfs or construct `NativeArchCalls`.
- `cargo test --workspace --all-targets`: passed, exit 0.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`, `git diff --check`: passed.
- `bash packaging/linux/package-smoke.sh`: passed with a private temporary
  package stage; no root installation.

## Self-review and remaining risks

- New adapter production files are about 1,160 formatted lines, in two
  focused modules. They add no journal, rollback, recovery, uninstall,
  Windows ESP access, or lifecycle IPC. This remains below half of the old
  experimental branch's 7,588 added production lines when combined with
  the earlier minimal work, subject to the controller's final branch count.
- The accepted libalpm script/hook fingerprint is intentionally strict for
  this one observed Arch installation. A routine mkinitcpio package update
  changes the bytes and blocks setup until the route is reviewed again.
- Native `findmnt`/`lsblk` output, vfat directory mode behavior,
  efivarfs create/replace semantics, package-lock interaction, post-hook
  behavior, and actual UKI boot have **not** been exercised on the host.
  Unknown or unsupported results stop; fake and temporary-descriptor tests
  do not prove real firmware behavior.
- BootOrder has no compare-and-swap. An external firmware writer can race
  the latest read and single write. The adapter makes no transaction claim.
  The package manager lock excludes ordinary pacman updates, not arbitrary
  privileged peers running mkinitcpio directly.
- The artifact inspection checks final-file trust, PE signature, and absent
  stage after the publisher succeeds. Bootability and module compatibility
  still require isolated boot acceptance.
