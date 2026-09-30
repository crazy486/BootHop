# Phase 5A — trusted Linux lifecycle coordinator

Status: DONE_WITH_CONCERNS

Implementation commit: `c426b68`

Changed files:

- `crates/platform/src/linux/coordinator.rs` — lock-held provision/uninstall/recovery coordinator, private proof-bound transitions, injected trusted backend boundary.
- `crates/platform/src/linux/arch_provision_store.rs` — crate-private proof commit entrypoint.
- `crates/platform/src/linux/store.rs` — proof validation and atomic journal commit under the existing `operation.lock` guard.
- `crates/platform/src/linux.rs` — coordinator module export.
- `crates/platform/tests/coordinator.rs` — fake full lifecycle, ordered read/mutate/readback checks, residual/no-retry failures, read-only restart recovery, mismatched precondition, and proof tests.

Tests and commands:

- `cargo test -p boothop-platform --all-targets --quiet` — passed.
- `cargo clippy -p boothop-platform --all-targets --no-deps -- -D warnings` — passed.
- `cargo fmt --all -- --check` — passed.
- `git diff --check` — passed.

Self-review:

- Provisioning and uninstalling keep the same `ArchProvisionStore` guard across load, exact backend readbacks, mutation calls, proof-bound checkpoints, residual saves, and the uninstall tombstone.
- Generic journal saves still cannot manufacture forward checkpoints, `Ready`, or `Uninstalled`; only a private proof can advance lifecycle state. Restart recovery calls observation only and never advances an attempted checkpoint. BootOrder presence adds residual evidence and never proves the original order.
- Fake failures retain the attempted state, add a deduplicated residual, and reject subsequent mutation attempts. No production Linux syscall, EFI/NVRAM, ESP, mkinitcpio, or reboot path is instantiated.

Remaining concern: the coordinator exposes an injected `LifecycleBackend` only; the production helper adapter that binds it to the existing `BootEntryIo`, `BootOrderIo`, and fixed-path UKI adapters remains Phase 5B wiring. The coordinator intentionally cannot perform real platform access in this slice.
