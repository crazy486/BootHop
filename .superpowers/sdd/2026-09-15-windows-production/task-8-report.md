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
  elevated/high-integrity token, fixed image, expected session, retained file
  identity, and live process. The different-admin UAC case remains valid
  because no equal-user-SID check is used. The native boundary repeats identity
  checks during I/O and terminal-response draining.
- Added Windows-only native calls behind `cfg(windows)`. Tests use only the
  fake boundary; they do not create pipes, launch the helper, open real tokens,
  display UAC, or touch ProgramData/firmware/reboot APIs.

## Fix round 1 evidence

- Added one absolute 120-second launch/UAC/connect/auth watchdog and one
  30-second post-auth operation watchdog. The launch watchdog is armed before
  `ShellExecuteExW`; overlapped connect/read/write operations use cancellation
  followed by a completion barrier before event/OVERLAPPED/buffer cleanup.
- Added fixed helper pre-open identity checks (canonical Program Files path,
  regular non-reparse file, nonzero volume/file identity) and retained the
  opened handle with delete sharing excluded. The identity is re-opened and
  compared through the session, while helper PID/token/integrity/image/session
  liveness is checked before each I/O.
- Extended pure `PeerIdentity` fakes with file identity, reparse/regular-file,
  and process-continuity evidence. Deterministic tests cover replacement,
  reparse, dead-process, mismatch, different-admin acceptance, and start
  deadline behavior.
- Hardened TOKEN_USER SID pointer/header/declared-region validation and made
  LocalFree and security-critical handle close failures explicit/fail-closed.
- Drained a terminal pipe response before reporting the helper's real exit code,
  so a normal one-shot helper exit cannot turn a delivered response into an
  unknown result. Native failure branches capture Win32 last-error values
  immediately.
- Passed the single precomputed launch/authentication deadline through the
  shared client seam, preventing a callback-time `now + 120s` extension.

## Verification

- `cargo test -p boothop-gui --test windows_client` — PASS (9 tests).
- `cargo test -p boothop-gui --test client --test windows_client --test controller` — PASS (15 + 7 + 43 tests).
- `cargo fmt --all -- --check` — PASS.
- `cargo clippy -p boothop-gui --lib --tests -- -D warnings` — PASS.
- `cargo check -p boothop-gui --target x86_64-pc-windows-msvc` — PASS.
- `cargo clippy -p boothop-gui --target x86_64-pc-windows-msvc --lib -- -D warnings` — PASS.
- `cargo test -p boothop-gui --target x86_64-pc-windows-msvc --no-run` — PASS.

## Limits

No real UAC, ShellExecuteExW, named-pipe, process/token, Program Files,
firmware, protected-store, reboot, or post-boot acceptance action was run.
Windows runtime acceptance remains a separate authorized stage.
