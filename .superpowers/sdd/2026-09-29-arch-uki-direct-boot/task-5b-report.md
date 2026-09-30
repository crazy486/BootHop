# Phase 5B — Linux lifecycle transport and GUI actions

Status: DONE_WITH_CONCERNS

Implementation commit: `116d307` (`feat: wire Linux lifecycle transport and UI`)

## Scope completed

- Added the `RecoveryRequired` terminal lifecycle status while keeping the wire protocol closed, version checked, correlation checked, and strict about unknown fields.
- Added `decode_lifecycle_response_for` and a separate Linux lifecycle client exchange. Linux lifecycle launches the helper with the distinct `--lifecycle` argument and never uses the ordinary `Request`/`Report` decoder.
- Wired `helper/src/main.rs` to select ordinary or lifecycle dispatch from the fixed Linux process argument. The production lifecycle callback is deliberately fail-closed with `LifecycleStatus::Failed` until a concrete trusted backend is authorized and available.
- Added an independent Linux `LifecycleController` with explicit `Provision` and `Uninstall` intents. It sends nothing during construction or startup, maps terminal statuses for display, and disables both actions after `RecoveryRequired`, pending, or `UnknownAfterSend` transport results.
- Added Linux-only Slint setup/uninstall actions and status display. The Windows entry point explicitly hides and disables lifecycle actions; its ordinary callbacks remain unchanged.
- Added fake transport/helper/controller/UI tests for lifecycle correlation, separate process arguments, post-send uncertainty, explicit-only actions, no-retry states, fail-closed production routing, strict response validation, and Windows UI absence.

## Verification

- `cargo test -p boothop-helper --all-targets --quiet` — passed.
- `cargo test -p boothop-gui --all-targets --quiet` — passed.
- `cargo test --workspace --all-targets --quiet` — passed.
- `cargo fmt --all -- --check` — passed.
- `cargo clippy --workspace --all-targets --no-deps -- -D warnings` — passed.
- `git diff --check` — passed.

The lifecycle client/controller tests were first run before the corresponding implementation and failed for the missing API; they passed after the minimal implementation was added.

## Self-review and limitations

- Ordinary Linux and Windows Inspect/Configure/Switch paths do not accept lifecycle frames or call the lifecycle controller. Windows lifecycle input is rejected by the existing ordinary decoder before guard/platform construction.
- `LifecycleStatus::Failed` from the production helper path means unavailable before any journal or platform mutation. No fake backend is registered as production success.
- No EFI/NVRAM access, UKI build/publish, helper execution, pkexec invocation, host configuration read/write, or reboot was performed.
- The remaining concern is intentional: the Phase 5A coordinator still has only its injected `LifecycleBackend`; concrete filesystem/UKI/BootOrder adapters and separately authorized Phase 7 preparation are not present. Production provision/uninstall therefore remains unavailable until that seam is implemented and authorized.
