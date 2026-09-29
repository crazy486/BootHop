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
