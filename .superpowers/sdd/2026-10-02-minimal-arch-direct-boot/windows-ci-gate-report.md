# Windows CI test gate

The Windows all-targets Clippy failure came from `arch_setup_dispatch.rs` importing `boothop_helper::arch_setup_cli`, which is compiled only on Linux. The neighboring Linux-only integration tests (`pipe.rs` and `trust.rs`) already have file-level `target_os = "linux"` gates; this was the only helper integration test missing one.

Added the same file-level gate to `arch_setup_dispatch.rs`. This changes test selection only and does not affect production code.

Verification:

- Before the fix, `cargo clippy -p boothop-helper --all-targets --target x86_64-pc-windows-msvc -- -D warnings` failed with the unresolved import.
- After the fix, that Windows-target Clippy command passed.
- `cargo fmt --all -- --check` passed.
- `cargo test -p boothop-helper --test arch_setup_dispatch` passed (3 tests).
- `cargo clippy -p boothop-helper --all-targets -- -D warnings` passed on Linux.
