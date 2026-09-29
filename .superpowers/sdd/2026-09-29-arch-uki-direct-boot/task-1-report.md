# Task 1 — Phase 1 ownership/data model report

## Outcome

Implemented the Arch provisioning lifecycle record and its root-protected journal. Missing journal bytes map to `Unprovisioned`; malformed, incomplete, unsupported-version, and unsupported-identity records return errors. `Ready` entries require the supported identity version, canonical fixed BootHop EFI path, fixed `EFI/BootHop/arch.efi` publish path, and nonempty build/publish metadata.

The journal is stored in `arch-provision.json`, separate from ordinary `targets.json` records. `ArchProvisionStore` acquires the same `LockedStore` directory protection and operation lock, and saves with an exclusive temporary file, complete write loop, file sync, atomic rename, and directory sync.

## TDD evidence

Added the requested codec/state tests and fake-filesystem store tests before production implementation:

- `unprovisioned_is_only_absent_journal`
- `lifecycle_records_roundtrip`
- `unknown_or_corrupt_record_fails_closed`
- `owned_entry_requires_supported_identity_and_fixed_path`
- store cases for missing journal and target-store separation, short writes, file and directory sync errors, and preserving unknown/corrupt journals

RED: `cargo test -p boothop-core --test arch_provision_record` failed at compile time with unresolved imports for the new lifecycle types and codec functions (`E0432`), confirming the API/feature was absent. The first RED attempt also caught a mutable/immutable borrow in the new test fixture (`E0502`); I corrected the test fixture and reran after implementation.

GREEN: both focused targets passed after implementation, with four passing tests each.

## Files changed

- `crates/core/src/arch_provision.rs` — lifecycle types, versioned codec, identity/path validation.
- `crates/core/src/lib.rs` — public exports.
- `crates/core/tests/arch_provision_record.rs` — codec/state tests.
- `crates/platform/src/linux/arch_provision_store.rs` — separate journal store wrapper.
- `crates/platform/src/linux/store.rs` — journal read/atomic replace methods sharing `LockedStore` protection.
- `crates/platform/src/linux.rs` — exports the journal store module.
- `crates/platform/tests/arch_provision_store.rs` — fake-filesystem persistence tests.
- `crates/platform/tests/support/mod.rs` — journal helpers and lifecycle fixture for the fake filesystem.

## Commands and results

- `cargo test -p boothop-core --test arch_provision_record` — passed, 4 tests.
- `cargo test -p boothop-platform --test arch_provision_store` — passed, 4 tests.
- `cargo test --workspace --all-targets` — passed; all workspace targets completed with zero failures.
- `cargo fmt --check` — passed.
- `git diff --check` — passed.

All store tests used the existing in-memory fake filesystem. No EFI variables, efivarfs, GRUB, mkinitcpio files, ESP, Windows boot state, or reboot path were accessed.

## Self-review and concerns

- Missing data is distinguished from every present-but-invalid journal; saving always reloads and validates the current journal first, so unknown and corrupt bytes are preserved.
- The journal and target record filenames remain separate while using the same protected directory and lock inode.
- Canonical identity is serialized by reusing the existing target-record codec and embedded as lowercase hex in the journal. This reuses existing identity validation and keeps the schema fail-closed, at the cost of a larger representation; the one-MiB journal limit bounds it.
- No known blocking concerns for Phase 1. Later phases should continue to use `ArchProvisionStore` and the fixed paths/versions defined here rather than writing the journal or UKI directly.
