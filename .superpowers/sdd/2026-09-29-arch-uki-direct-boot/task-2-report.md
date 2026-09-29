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

## Third review fix round

The third review's three findings are addressed:

- Preset `_cmdline` values are now treated as paths passed to mkinitcpio `--cmdline`. Discovery accepts only an absolute path to an existing regular file, reads its content as the persistent command line, and rejects inline text, relative paths, directories, and dynamic content. When the preset omits cmdline, the existing persistent-file fallback remains. The discovery fixture now uses a cmdline file; regression cases reject inline, relative, and directory values.
- The shell validator requires each exact `.linux`, `.initrd`, and `.cmdline` section to have a nonzero hexadecimal size. The stubbed script test independently checks each empty-section case and confirms rejection preserves the old stable UKI and leaves the staged image unchanged.
- Secure Boot signer output now lives at `arch.efi` inside an exclusively created private temporary directory in the validated staging directory. The exit trap removes only that private directory. The signed artifact is verified and validated before it is moved over the staging file; only after that does publication replace the stable path. A preexisting `$stage.signed` symlink fixture confirms its sentinel target remains unchanged and the signer temp directory is cleaned up.

TDD evidence for this round: before production changes, the inline preset cmdline fixture was incorrectly accepted, and the shell harness demonstrated that the old predictable signer output followed a preexisting symlink and overwrote its sentinel. Both regressions now pass.

Verification after the round:

- `cargo test -p boothop-platform --test uki_discovery` — passed, 11 tests.
- `cargo test -p boothop-platform --test uki_publish` — passed, 3 tests.
- `packaging/linux/tests/boothop-uki-publish-test.sh` — passed with temporary files and stubbed external tools.
- `bash -n packaging/linux/boothop-uki-publish.sh packaging/linux/tests/boothop-uki-publish-test.sh` — passed.
- `cargo test --workspace --all-targets --quiet` — passed all targets.
- `cargo fmt --check` — passed.
- `cargo clippy -p boothop-platform --all-targets --no-deps -- -D warnings` — passed.
- `cargo clippy --workspace --all-targets -- -D warnings` — remains blocked only by the existing unrelated Phase 1 diagnostics in `crates/core/src/arch_provision.rs` (manual `is_multiple_of` at line 365 and `chunks_exact_to_as_chunks` at line 369).
- No real presets, `/boot`, ESP, EFI variables, or NVRAM were accessed; all added behavior was exercised with fake or temporary fixtures.

## Fourth review fix round

Both findings are fixed with focused regressions:

- Persistent cmdline validation now requires exactly one `root=` token. It accepts only nonempty `UUID=` or `PARTUUID=` identifiers containing hexadecimal digits and single internal hyphens, with at least one hex digit. It rejects empty, non-hex, path-like, leading/trailing/repeated-hyphen identifiers, and duplicate/conflicting roots. Tests include standard GUID and DOS partition suffix forms, plus uppercase hex.
- Immediately before final publication, the shell publisher checks an existing `EFI/BootHop/arch.efi`: only a non-symlink regular file is accepted. Directories, valid and dangling symlinks, and FIFOs fail before `mv`. The directory fixture uses a valid staged image and proves failure preserves staging bytes and its stable marker without creating a nested `arch.efi.staging`. Existing regular-file replacement remains covered by the explicit Secure Boot disabled success case.

TDD evidence: before implementation, the empty `root=UUID=` case was accepted, and the shell test showed that publishing to an existing final directory returned success. The stricter follow-up regression also first showed `root=UUID=not-a-uuid` was accepted. All focused regressions pass after the changes.

Verification:

- `cargo test -p boothop-platform --test uki_discovery` — passed, 12 tests.
- `cargo test -p boothop-platform --test uki_publish` — passed, 3 tests.
- `packaging/linux/tests/boothop-uki-publish-test.sh` — passed with temporary fixtures and stubbed tools.
- `bash -n packaging/linux/boothop-uki-publish.sh packaging/linux/tests/boothop-uki-publish-test.sh` — passed.
- `cargo test --workspace --all-targets --quiet` — passed all targets.
- `cargo fmt --check` — passed.
- `cargo clippy -p boothop-platform --all-targets --no-deps -- -D warnings` — passed.
- `cargo clippy --workspace --all-targets -- -D warnings` — remains blocked by the two known unrelated Phase 1 clippy diagnostics in `crates/core/src/arch_provision.rs` lines 365 and 369 (`manual_is_multiple_of` and `chunks_exact_to_as_chunks`).
- All new tests use in-memory or temporary fixtures. No host EFI, presets, ESP, or NVRAM were accessed.

## Final ownership review fix round

The final review found that fixed paths and regular-file type alone did not prove the stable UKI belonged to BootHop. Publication now requires an explicit typed journal state:

- `build_and_publish_uki` accepts a decoded `ArchProvisionState`. Only `Provisioning` and `Ready` are eligible; missing (`Unprovisioned`), uninstalling/unknown lifecycle state, or a non-fixed journaled UKI path fails before the builder runs.
- `Provisioning` authority permits publication only when the final path is absent. `Ready` authority carries the journaled SHA-256 and size and permits updates only when the existing stable path is a regular file with exact matching metadata. The fakeable `UkiPublishFs::final_path_state` contract is lstat-style (does not follow symlinks) and returns exact content hash/size. `build_and_publish_uki` checks before building, before staging, and before rename; `rename_stage_over_final` receives and must atomically re-enforce that authority. The function returns the new artifact's SHA-256 and size so the caller can persist complete journal metadata before any EFI-variable mutation.
- The shell post-hook requires `BOOT_HOP_JOURNAL_STATE`. `Provisioning` requires an absent stable path; `Ready` additionally requires well-formed `BOOT_HOP_JOURNAL_UKI_SHA256` and `BOOT_HOP_JOURNAL_UKI_SIZE` that match the current non-symlink regular file. Unknown/missing/malformed state, digest, or size fails before rename. Ownership is checked again immediately before final publication. The hook does not treat a standalone marker as proof: Phase 5 must source these inputs only from the trusted root-owned journal verifier.
- Phase 5 and Phase 7 plan text now gates hook installation on the trusted verifier/update path. It requires missing/corrupt journal states to block updates, initial Provisioning to refuse any existing fixed UKI, Ready updates to match exact journal metadata, successful publication metadata to be durably recorded before EFI writes, and serialization across the final ownership check and atomic rename.

TDD evidence: the Rust authority tests first failed to compile because the API was absent. The shell regression first failed because a missing journal state was accepted. Added cases cover unowned initial-path refusal, absent-path initial success, exact Ready update success, hash and size mismatch with stable preservation, missing/unknown journal state, malformed/missing shell inputs, and valid shell Ready update. Fake Rust publication rechecks authority inside its rename operation.

Verification:

- `cargo test -p boothop-platform --test uki_publish` — passed (6 tests).
- `packaging/linux/tests/boothop-uki-publish-test.sh` — passed using temporary files and stubbed tools.
- `bash -n packaging/linux/boothop-uki-publish.sh packaging/linux/tests/boothop-uki-publish-test.sh` — passed.
- `cargo test --workspace --all-targets --quiet` — passed all targets.
- `cargo fmt --check` — passed.
- `cargo clippy -p boothop-platform --all-targets --no-deps -- -D warnings` — passed.
- `cargo clippy --workspace --all-targets -- -D warnings` — remains blocked by the same unrelated Phase 1 clippy diagnostics in `crates/core/src/arch_provision.rs` lines 365 and 369 (`manual_is_multiple_of` and `chunks_exact_to_as_chunks`).
- No host EFI, presets, ESP, or NVRAM were accessed. There is no production adapter/verifier wired yet; its required interface is the typed verified journal state plus final-path inspection and an authority-enforcing atomic rename, with returned publication metadata durably saved before EFI-variable writes. Phase 5/7 now explicitly blocks hook installation and real provisioning until this boundary is implemented and tested.

## Publication lifecycle checkpoint review fix

The follow-up lifecycle review found that `Provisioning` did not distinguish the pre-publication checkpoint, and the API could report `UkiPublished` without exposing a durable journal-save boundary. The journal model and injected publisher contract now make that boundary explicit:

- `ProvisioningStep::UkiPublicationPending` has no `PublishMetadata`. The serialized record version is now 3; version 2 is rejected because its `UkiPublished` checkpoint may have been written before stable-file readback. Pending is serializable without fabricated metadata.
- Initial publication order is durable Attempted(expected SHA-256/size) → staging write → atomic rename → exact stable-file readback → durable UkiPublished. Attempted is persisted before any ESP write. Any Attempted restart is reconciliation-only: exact file readback can be presented for explicit recovery, while absent/mismatched bytes fail closed and are never rebuilt, retried, or deleted.
- `UkiPublishJournal` is an injected durable-checkpoint interface. The coordinator must hold the same exclusive journal lock from verified state load through authority checks, rename, readback, and durable checkpoint save. The platform function reports success only after the injected callback reports durable completion. Ready updates likewise save new hash/size only after readback; if rename succeeds and that save fails or has uncertain outcome, the old checkpoint cannot authorize another update because its exact old hash/size no longer matches the file.
- Phase 7 plan text now specifies the durable record serialization and crash behavior; Phase 5/7 hook gates remain unchanged. No hook was installed or wired.

TDD evidence: before the implementation, the lifecycle regressions failed to compile because the journal checkpoint interface and reconciliation helper were absent. A subsequent schema test exposed that the existing all-step roundtrip fixture put publish metadata on Pending; the fixture was corrected to encode Pending without metadata, and the model rejects Pending with stale metadata. Dedicated tests verify Attempted is recorded before the staging write and that a failed Attempted save causes no staging or rename. Injected tests cover interruption after rename, final readback mismatch, failure saving UkiPublished, reconciliation-only retry, and Ready update journal-save failure. The fake journal refuses UkiPublished unless the exact Attempted metadata matches.

Verification for this round:

- `cargo test -p boothop-core --test arch_provision_record` — passed, 9 tests.
- `cargo test -p boothop-platform --test uki_publish` — passed, 11 tests.
- `cargo test -p boothop-platform --test uki_discovery` — passed, 12 tests.
- `packaging/linux/tests/boothop-uki-publish-test.sh` and `bash -n packaging/linux/boothop-uki-publish.sh packaging/linux/tests/boothop-uki-publish-test.sh` — passed.
- `cargo test --workspace --all-targets --quiet` — passed all targets.
- `cargo fmt --check` — passed.
- `cargo clippy -p boothop-platform --all-targets --no-deps -- -D warnings` — passed.
- `cargo clippy --workspace --all-targets -- -D warnings` — blocked by the same two pre-existing Phase 1 diagnostics in `crates/core/src/arch_provision.rs` (`manual_is_multiple_of` and `chunks_exact_to_as_chunks`); those are outside this bounded fix.
- All lifecycle tests use in-memory fakes. No host EFI, presets, ESP, or NVRAM were accessed.
