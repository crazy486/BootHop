# Task 8 report — Windows GUI launcher and authenticated client

## Implemented

- Extracted the platform-neutral request/response exchange from the existing
  client while preserving Linux `pkexec` spawn arguments, environment, phase
  classification, aggregate frame budget, and no-retry behavior.
- Added a distinct Windows boundary with fixed Program Files identities,
  `asInvoker` GUI / `runas` helper launch metadata, `SEE_MASK_NOCLOSEPROCESS`,
  per-request pipe names, explicit user/SYSTEM/Administrators SDDL, and
  first-instance/remote-client rejection policy.
- Added injectable identity validation requiring the launched helper PID,
  elevated/high-integrity token, fixed image, and expected session. The
  different-admin UAC case remains valid because no equal-user-SID check is
  used. The native boundary retains the helper process handle and repeats
  identity checks during I/O.
- Added Windows-only native calls behind `cfg(windows)`. Tests use only the
  fake boundary; they do not create pipes, launch the helper, open real tokens,
  display UAC, or touch ProgramData/firmware/reboot APIs.

## Verification

- `cargo test -p boothop-gui --test client --test windows_client --test controller`
  — PASS (15 + 6 + 43 tests).
- `cargo fmt --all -- --check` — PASS.
- `cargo clippy -p boothop-gui --lib --tests -- -D warnings` — PASS.
- `cargo check -p boothop-gui --target x86_64-pc-windows-msvc` — PASS.
- `cargo clippy -p boothop-gui --target x86_64-pc-windows-msvc --lib -- -D warnings` — PASS.
- `cargo test -p boothop-gui --target x86_64-pc-windows-msvc --no-run` — PASS.

## Limits

No real UAC, ShellExecuteExW, named-pipe, process/token, Program Files,
firmware, protected-store, reboot, or post-boot acceptance action was run.
Windows runtime acceptance remains a separate authorized stage.
