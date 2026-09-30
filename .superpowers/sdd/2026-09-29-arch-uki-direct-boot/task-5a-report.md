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

## Review-fix round 1

Status: DONE_WITH_CONCERNS

Implementation commit: `b8657be`

Fixes:

- Post-mutation readback mismatches now retain a deduplicated residual at the attempted checkpoint under the held lock.
- Proof commit failures after an external mutation preserve the attempted residual when possible, or retain an atomically landed verified checkpoint without retrying the mutation.
- Restart recovery checks the journaled UKI hash/size for attempted BootEntry and BootOrder states, keeps every attempted checkpoint observation-only, and never infers ownership from Boot#### presence.
- Proof validation now constrains every attempted and terminal/intermediate binding, including `BootEntryCreated` and `BootOrderAppended`.
- Fake coverage now exercises every attempted provision/uninstall recovery checkpoint, publication/entry/order readback mismatches, owned identity mismatch, durability-uncertain checkpoint order, success checkpoint ordering, and uninstall ordering. Existing Linux Switch regression coverage continues to assert BootNext-only mutation.

Verification:

- `cargo test -p boothop-platform --all-targets --quiet` — passed (all fake/unit targets).
- `cargo clippy -p boothop-platform --all-targets --no-deps -- -D warnings` — passed.
- `cargo fmt --all -- --check` — passed.
- `git diff --check` — passed.

No real EFI/NVRAM, ESP, system configuration, mkinitcpio, or reboot path was used.

## Review-fix round 2

Status: DONE_WITH_CONCERNS

Implementation commit: `531fbd9`

Fixes:

- Restart recovery now records residual evidence for absent Boot#### and BootOrder observations at attempted create/append checkpoints while preserving the checkpoint and remaining read-only.
- Fake journal events now decode each durable checkpoint, and tests assert exact attempted/verified ordering and residuals.
- Linux Switch coverage explicitly rejects Boot####, BootOrder, and UKI lifecycle mutation calls while allowing its BootNext write.
- Fake uninstall coverage asserts the complete durable lifecycle sequence through BootOrder, Boot####, UKI, and the terminal tombstone.

Verification:

- `cargo test -p boothop-platform --all-targets --quiet` — passed.
- `cargo clippy -p boothop-platform --all-targets --no-deps -- -D warnings` — passed.
- `cargo fmt --all` — passed.
- `git diff --check` — passed.

No real EFI/NVRAM, ESP, system configuration, mkinitcpio, or reboot path was used.
