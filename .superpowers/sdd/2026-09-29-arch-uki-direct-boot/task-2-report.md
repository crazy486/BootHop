# Task 2 report — Phase 2 UKI discovery/build abstraction

## Outcome

Implemented a read-only Arch/mkinitcpio UKI planner, injected build and publication interfaces, and a narrowly scoped mkinitcpio post-build publisher. The planner fixes the final path at `EFI/BootHop/arch.efi` and staging path at `EFI/BootHop/arch.efi.staging`. It does not execute mkinitcpio, inspect or write system configuration, or access firmware variables.

Discovery fails closed when the supported flavor is ambiguous, the preset/configuration is unsupported, the ESP is not mounted at the supplied normalized path, required kernel/initramfs files are absent, no persistent static command line exists, the command line is dynamic or has unsupported root/crypt settings, or Secure Boot signing is required without an already-configured signer. Preset `default_cmdline`/`ALL_cmdline` takes precedence; static preset cmdline files, `/etc/kernel/cmdline`, and `/etc/cmdline.d/boothop.conf` are supported. `/proc/cmdline` is never accepted. The selected preset must point its UKI output at the exact staging file; a direct stable-path output is rejected.

The builder contract validates before and after optional signing. Publication stages to the fixed sibling path and then calls an injected same-filesystem atomic replace operation. The publisher contract requires replace failures to leave the stable file untouched. Fake tests cover build, validation, signing, partial-stage, disk-full, and rename failures.

## TDD evidence

Tests were added before production code. The first RED command was:

```text
cargo test -p boothop-platform --test uki_discovery
```

It failed at compilation because `boothop_platform::linux::uki` did not yet exist (`could not find uki in linux`), as expected. After implementation, focused GREEN runs passed:

```text
cargo test -p boothop-platform --test uki_discovery  # 7 passed
cargo test -p boothop-platform --test uki_publish    # 3 passed
```

## Files

- `crates/platform/src/linux.rs` — exports the `uki` module.
- `crates/platform/src/linux/uki.rs` — read-only discovery types/function, validation, staging-path enforcement, injected builder/publisher traits, and fixed-path publish orchestration.
- `crates/platform/tests/uki_discovery.rs` — synthetic discovery fixtures and fail-closed cases.
- `crates/platform/tests/uki_publish.rs` — fake builder/filesystem and stable-file preservation cases.
- `packaging/linux/boothop-uki-publish.sh` — validates staged UKI sections, optionally signs using configured key/certificate values, verifies the signature, and atomically renames to the fixed sibling final filename.
- `packaging/linux/tests/boothop-uki-publish-test.sh` — isolated integration checks with temporary files and stubbed mount/image/signing commands.

## Verification

- `cargo test -p boothop-platform --test uki_discovery` — passed, 7 tests.
- `cargo test -p boothop-platform --test uki_publish` — passed, 3 tests.
- `cargo test --workspace --all-targets` — passed all workspace targets. Repeated after final edits with `--quiet`; all targets passed.
- `cargo fmt --check` — passed.
- `bash -n packaging/linux/boothop-uki-publish.sh` — passed.
- `cargo clippy -p boothop-platform --all-targets --no-deps -- -D warnings` — passed.
- `cargo clippy --workspace --all-targets -- -D warnings` — blocked by two clippy diagnostics in the existing Phase 1 `crates/core/src/arch_provision.rs`: `% 2 != 0` at line 365 (`manual_is_multiple_of`) and `chunks_exact(2)` at line 369 (`chunks_exact_to_as_chunks`). Neither diagnostic is in this task's files.

## Self-review and concerns

- All discovery and publication tests use in-memory fixtures. No host presets, `/boot`, ESP, EFI variables, or system update path were read or changed. No real build or signing command was run.
- The official mkinitcpio manual describes post hooks as receiving kernel, image, and optional UKI arguments, and states that post hooks are disabled when `kernel-install` invokes mkinitcpio: <https://man.archlinux.org/man/mkinitcpio.8>. The selected live kernel update path was not inspected because the task forbids host configuration inspection. Before real provisioning, confirm that the selected path invokes this post hook and does not pass `--nopost`; stop if it disables post hooks. The current host update path therefore remains unconfirmed.
- The production filesystem adapter is intentionally not included here; the trait contract and behavior are exercised through fakes. Any adapter must preserve the documented same-filesystem atomic replacement guarantees and must not direct mkinitcpio at the stable path.
- The publisher expects mkinitcpio to have produced the third post-hook argument at the fixed staging path. The host preset/update-path wiring must be configured and independently confirmed before use.

## Review fix round

Review found missing Secure Boot state validation, an unbound suffix-based output path, incorrect precedence for preset-specific kernel/config values, and incomplete microcode discovery when config drop-ins override `HOOKS`. These were fixed as follows:

- The post-hook now requires `BOOT_HOP_SECURE_BOOT_REQUIRED` to be exactly `0` or `1`; unset and all other values fail before publication. It also requires an explicit normalized `BOOT_HOP_ESP_MOUNT`, confirms that exact mount is `vfat` with `findmnt`, and requires the staged argument to equal that mount's `EFI/BootHop/arch.efi.staging` path. There is no production environment wiring in this phase; missing values fail safely.
- `default_kver` and `default_config` now take precedence over `ALL_kver` and `ALL_config`.
- Discovery reads at most 64 direct `.conf` entries under `/etc/mkinitcpio.conf.d`, in sorted order. It applies only static `HOOKS=(...)` assignments; unsupported shell syntax, expansions, and non-assignment statements fail closed. Later hook assignments override earlier ones. Fake tests cover adding and removing `microcode`.
- TDD RED evidence: the preset precedence regression first failed by selecting `/boot/vmlinuz-linux` instead of `/boot/vmlinuz-linux-default`; the publisher shell test first showed that an unset Secure Boot flag was incorrectly accepted. The initial drop-in test also failed compilation because the read-only directory enumeration API was not yet defined.
- New verification: `cargo test -p boothop-platform --test uki_discovery` passed (10 tests); `cargo test -p boothop-platform --test uki_publish` passed (3 tests); `packaging/linux/tests/boothop-uki-publish-test.sh` passed using stubs for `findmnt`, `objdump`, `sbsign`, and `sbverify`; `bash -n` passed for both shell scripts. The workspace test suite, formatting check, and `cargo clippy -p boothop-platform --all-targets --no-deps -- -D warnings` passed after the fixes.
- `cargo clippy --workspace --all-targets -- -D warnings` remains blocked by the same two unrelated diagnostics in Phase 1 `crates/core/src/arch_provision.rs` (lines 365 and 369). Those files were not changed.
- No host EFI, presets, ESP, or NVRAM was accessed during this review round.

## Second review fix round

The second review identified two issues, both fixed in this round:

- Discovery now tracks whether the selected preset explicitly supplied `default_config` or `ALL_config`. For explicit config paths it reads only that file and ignores `/etc/mkinitcpio.conf.d/*.conf`, matching mkinitcpio's `-c` behavior. When the preset leaves the config implicit, it applies sorted static drop-ins. Regressions prove a conflicting default drop-in cannot override explicit config, while implicit config follows sorted drop-in overrides.
- UKI validation now checks GNU `objdump -f` for a `pei-*` PE image format, `objdump -p` for PE32 or PE32+ magic and the exact EFI application subsystem value, and `objdump -h` for exact `.linux`, `.initrd`, and `.cmdline` section names. Substring lookalikes are rejected before any stable-file rename.
- RED evidence: the explicit-config test initially detected microcode from a conflicting default drop-in; the publisher shell test initially accepted a fake ELF image. After the fixes, both regressions pass.
- `packaging/linux/tests/boothop-uki-publish-test.sh` now covers non-PE, wrong subsystem, `.linuxfoo`, and wrong-section staged artifacts. Each rejection verifies that the prior stable UKI remains and the invalid staged bytes are untouched. It uses temporary files and stubbed `findmnt`, `objdump`, `sbsign`, and `sbverify`; no signing utility or real ESP is used.
- Local GNU binutils advertises `pei-i386` and `pei-x86-64` support. I generated temporary minimal PE32 and PE32+ inspection fixtures (not UKIs) and confirmed that its `objdump -f`, `-p`, and `-h` output matches the exact format, magic, subsystem, and section checks. No real boot image was inspected or created.
- Final fix-round verification: `cargo test --workspace --all-targets --quiet`, `cargo fmt --check`, `cargo clippy -p boothop-platform --all-targets --no-deps -- -D warnings`, `bash -n packaging/linux/boothop-uki-publish.sh packaging/linux/tests/boothop-uki-publish-test.sh`, and `packaging/linux/tests/boothop-uki-publish-test.sh` all passed. The focused discovery suite passed 10 tests and publish suite passed 3 tests.
- The prior workspace clippy limitation is unchanged: only the two unrelated Phase 1 diagnostics in `crates/core/src/arch_provision.rs` remain.
- No host EFI, presets, ESP, or NVRAM was accessed in this round.
