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

## Fix round 2 evidence

- Replaced the atomic watchdog with a synchronized Armed/Disarmed/Expired
  state machine, worker-start handshake, equality-expired race handling,
  bounded worker finish/join, poison fail-closed behavior, and injectable abort
  hook; production uses process abort.
- Every issued overlapped connect/read/write timeout, unexpected wait result,
  cancellation failure, and completion-barrier failure now proves terminal
  completion or aborts before native state can be released. A completed write
  is explicitly committed before later cleanup and is therefore always mapped
  to UnknownAfterSend.
- The send boundary verifies retained process liveness, token/path/session and
  fixed-file identity immediately before writing. Terminal reads drain a
  bounded buffered response before accepting the retained helper's exit code.
- Cleanup is phase-aware: pre-request UAC/launch/hello errors remain
  Cancelled/BeforeSend, while committed-send cleanup/continuity errors remain
  UnknownAfterSend. Native handles are retained for Drop retry or fail-closed
  abort on close failure; pipe creation captures LastError before descriptor
  cleanup and closes a valid pipe if descriptor release fails.
- Fix round 2 additionally applies the Task 7 completion-barrier rule to every
  native overlapped path: cancellation must observe a signalled event and a
  terminal `GetOverlappedResult`, otherwise the process aborts before native
  state can leave scope. A completed write is preserved as committed even when
  observed at the deadline, and cleanup classification follows that state.

## Fix round 3 evidence

- Made completion barriers operation-aware. A signalled, terminal read result
  carrying `ERROR_BROKEN_PIPE` (or the documented `ERROR_NO_DATA`/
  `ERROR_PIPE_NOT_CONNECTED` closure) becomes `PipeClosed`; connect/write
  barriers retain strict abort-on-closure behavior.
- Pipe closure waits, within the existing operation deadline, for the retained
  helper handle's real exit code. The shared bounded-frame state then accepts
  only a complete terminal response and maps empty/partial header/body closure
  to the existing before/unknown phase errors without retry.
- Added pure decision coverage for pending read closure, complete/empty/
  partial buffered frames, and rejection of write-side broken-pipe closure.
- The latest aggregate host test execution was blocked by the local application
  control policy (OS error 4551) before the test binary started; the focused
  Windows fake suite and all compile/lint/no-run checks remain green.

## Verification

- `cargo test -p boothop-gui --test windows_client` — PASS (9 tests).
- `cargo test -p boothop-gui --test client --test windows_client --test controller` — PASS (15 + 9 + 43 tests).
- `cargo fmt --all -- --check` — PASS.
- `cargo clippy -p boothop-gui --lib --tests -- -D warnings` — PASS.
- `cargo check -p boothop-gui --target x86_64-pc-windows-msvc` — PASS.
- `cargo clippy -p boothop-gui --target x86_64-pc-windows-msvc --lib -- -D warnings` — PASS.
- `cargo test -p boothop-gui --target x86_64-pc-windows-msvc --no-run` — PASS.

## Limits

No real UAC, ShellExecuteExW, named-pipe, process/token, Program Files,
firmware, protected-store, reboot, or post-boot acceptance action was run.
Windows runtime acceptance remains a separate authorized stage.
