# BootHop Windows Production Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` to execute this plan task by task.
> Every task is test-first, committed independently, and receives a fresh
> task-scoped spec/quality review before the next task begins.

**Goal:** Implement the complete Windows production software path—shared
switch/rollback semantics, native adapter, protected store, one-shot elevated
helper transport, GUI wiring, packaging baseline, CI, and acceptance runbooks—
without executing any real firmware, privilege, UAC, helper, shutdown, BCD, or
reboot operation.

**Architecture:** `boothop-core` remains the only semantic workflow;
`boothop-platform` supplies closed fakeable Windows mechanisms; an ordinary GUI
launches one fixed transient elevated helper and sends one closed request over
an authenticated local named pipe. Firmware mutation is limited to BootNext,
BootOrder and Boot#### stay immutable, and unknown post-send state is never
retried.

**Tech stack:** Rust 1.98.1, `windows-sys`, serde/JSON protocol, Slint,
PowerShell packaging checks, GitHub Actions Windows MSVC CI.

**Spec:** `docs/superpowers/specs/2026-09-15-windows-production-design.md`

## Global constraints

- Never invoke a real Windows firmware getter/setter, adjust a real process
  privilege, display UAC, launch the production helper, modify BCD, request
  shutdown, or reboot during implementation or verification.
- Fixed global-variable GUID:
  `{8be4df61-93ca-11d2-aa0d-00e098032b8c}`; firmware privilege:
  `SeSystemEnvironmentPrivilege`; reboot privilege: `SeShutdownPrivilege`.
- BootOrder and Boot#### are strictly read-only. No entry creation/deletion,
  range scan, BCD repair, arbitrary variable name/GUID, or generic public
  firmware writer is permitted.
- Windows firmware payload excludes the Linux efivarfs four-byte attribute
  prefix. Exact accepted attributes are `7` for BootOrder/BootNext/Boot#### and
  `6` for BootCurrent. Per-variable and cumulative raw-inventory payload limits
  are each 1 MiB; over-budget inventory never returns partially.
- Win32 203 and every other non-buffer read failure remain an unavailable/error
  result, not confirmed absence, until a separate evidence-backed policy is
  approved. W4/W5 remain blocked by that separate absence-mapping gate.
- GUI input is intent only. The helper recomputes record, option, identity,
  conflict, and readback decisions using shared core.
- The helper is one-shot and transient. IPC is local-only, one-instance,
  explicit-DACL, mutually authenticated by OS process/token/image/session
  evidence, 64 KiB total, with 120-second launch/authentication and 30-second
  operation deadlines.
- Configure may update only the protected ProgramData record; it performs no
  firmware mutation or reboot. Switch may set only BootNext and only after all
  validation and conflict checks.
- Windows rollback is fail-closed/non-mutating until safe exclusivity exists;
  shared fakes still prove exact-restore policy and reporting.
- Main worktree and `boothop-sdd` remain untouched. Work only on
  `codex/windows-production`; no milestone tags, no merge to the integration
  branch, no force push.
- Production real-system acceptance remains NOT STARTED regardless of software
  test results.

---

### Task 1: Shared rollback and error/report contract

**Files:**
- Modify: `crates/core/src/model.rs`
- Modify: `crates/core/src/error.rs`
- Modify: `crates/core/src/flow.rs`
- Modify: `crates/core/tests/flow.rs`
- Modify: `crates/protocol/src/lib.rs`
- Modify: `crates/helper/tests/protocol.rs`

**Interfaces:**
- Add closed rollback outcome/assessment and stages from the spec.
- Extend `Platform` with the narrow `rollback_next(original, written)` method.
- Increment the protocol version from 1 to 2 under the spec's atomic package
  upgrade rule and map every new closed variant both ways; no negotiation or
  v1 fallback.

- [ ] Add RED core tests for: exact-original restore; safe clear in an
  exclusive fake; same-target pre-existence causing no rollback; rejected
  reboot causing one rollback only when core wrote; unknown reboot causing no
  rollback; write/readback failures causing no speculative rollback;
  concurrent/unsafe/failure outcomes; original `RebootRejected` retained when
  rollback fails; correct residual/stage reporting.
- [ ] Add RED protocol tests for round trips, strict shape rejection, compact
  failure preservation, exact nonzero lowercase-hex 128-bit request IDs,
  response echo/mismatch rejection, compact-response ID retention, and v2-only
  version rejection.
- [ ] Implement the smallest shared changes. Give the existing Linux fake and
  adapters an explicitly non-mutating `Unsafe` result; do not change Linux
  firmware writes or reboot flow.
- [ ] Run `cargo test -p boothop-core --test flow`,
  `cargo test -p boothop-protocol`, and
  `cargo test -p boothop-helper --test protocol` to GREEN; run fmt and scoped
  clippy.
- [ ] Commit as `feat(core): model conservative BootNext rollback`.

### Task 2: Pure Windows firmware read/write state machine

**Files:**
- Modify: `crates/platform/src/lib.rs`
- Create: `crates/platform/src/windows.rs`
- Create: `crates/platform/src/windows/firmware.rs`
- Create: `crates/platform/tests/windows_firmware.rs`
- Create: `crates/platform/tests/support/windows.rs`

**Interfaces:**
- Closed `VariableName`, `FirmwareType`, `ReadOutcome`, and `WindowsCalls`
  abstractions with no caller-controlled native names or GUID.
- Pure bounded reader/parser/discovery functions and a private
  `set_boot_next(BootId)` function reachable only by the adapter.

- [ ] Add RED fake tests for UEFI/non-UEFI/unknown; exact attribute and payload
  shapes; 4 KiB growth to 1 MiB; non-increasing/oversized/truncated results;
  immediate raw errors including 203 as unavailable; malformed controls;
  BootOrder/BootCurrent-only referenced union/deduplication; proof that
  `read_options` does not read BootNext; missing/unreadable Boot####; no range
  scan; 1 MiB per-variable and cumulative raw budget; parser handoff without
  efivarfs prefix.
- [ ] Add RED write tests for exact `BootNext`, fixed GUID, two-byte LE value,
  attributes `7`, one call/no retry, and no arbitrary writer surface.
- [ ] Implement the pure state machine and fake boundary. Do not add native
  imports in this task.
- [ ] Run `cargo test -p boothop-platform --test windows_firmware`, fmt, and
  scoped clippy to GREEN on the host without native calls.
- [ ] Commit as `feat(platform): add Windows firmware state machine`.

### Task 3: Exact-state privilege scope and native firmware backend

**Files:**
- Modify: `crates/platform/Cargo.toml`
- Modify: `crates/platform/src/windows.rs`
- Modify: `crates/platform/src/windows/firmware.rs`
- Create: `crates/platform/src/windows/privilege.rs`
- Create: `crates/platform/tests/windows_privilege.rs`

**Interfaces:**
- Fakeable token calls preserving the complete prior `TOKEN_PRIVILEGES` state.
- Windows-only direct-import backend for the allowlisted firmware/token APIs.

- [ ] Add RED fake tests for absent privilege, Lookup failure,
  `ERROR_NOT_ALL_ASSIGNED`, already-enabled, enable success, exact restore on
  every success/error path, restore failure precedence, and exactly one handle
  close.
- [ ] Add compile/static tests proving fixed names/GUID, direct imports, no
  dynamic loading/process/BCD/reboot APIs, and that tests never construct the
  system backend.
- [ ] Implement Windows-only `windows-sys` calls with `SetLastError(0)` before
  adjustments/reads and immediate `GetLastError`; use RAII for exact restore
  and closure. Limit `SetFirmwareEnvironmentVariableExW` to the private
  BootNext function.
- [ ] Run both Windows platform fake tests, `cargo check -p
  boothop-platform --target x86_64-pc-windows-msvc`, fmt, and scoped clippy.
  Compile only; do not run a Windows binary that constructs the backend.
- [ ] Commit as `feat(platform): add Windows firmware native boundary`.

### Task 4: Protected ProgramData store

**Files:**
- Modify: `crates/platform/Cargo.toml`
- Modify: `crates/platform/src/windows.rs`
- Create: `crates/platform/src/windows/store.rs`
- Create: `crates/platform/tests/windows_store.rs`

**Interfaces:**
- `WindowsStoreCalls` models known-folder resolution, handles/metadata,
  owner/DACL inspection, explicit secured creation, exclusive temporary files,
  flush/close, `ReplaceFileW`, and cleanup.
- `WindowsProtectedStore` implements `ProtectedStore` with a fixed
  ProgramData/BootHop/targets.json path.

- [ ] Add RED fake tests for trusted known-folder resolution; root containment;
  reparse/object/owner/DACL rejection; mutation-capable inherited ACE
  rejection; validated absence only; bounded reads; corrupt/unsupported
  records; fixed global mutex DACL, timeout/abandonment failure, and
  exactly-once release by the guard primitive.
- [ ] Add RED save tests for explicit protected DACL, same-directory exclusive
  temp, bounded encoding, flush/close/replace order, first creation,
  `ReplaceFileW` flags zero, cleanup, ACL revalidation, logical success versus
  durability-unknown, and no retry after replacement.
- [ ] Implement pure decisions plus Windows-only native store calls. Native
  constructors remain helper-only; tests use temporary fake roots and never
  access real ProgramData or alter real ACLs.
- [ ] Run `cargo test -p boothop-platform --test windows_store`, Windows target
  check, fmt, and scoped clippy.
- [ ] Commit as `feat(platform): add protected Windows target store`.

### Task 5: Windows platform integration and reboot boundary

**Files:**
- Modify: `crates/platform/src/windows.rs`
- Create: `crates/platform/src/windows/reboot.rs`
- Create: `crates/platform/tests/windows_adapter.rs`
- Modify: `crates/platform/tests/linux_adapter.rs`

**Interfaces:**
- `WindowsPlatform` implements shared `Platform` by composing protected store,
  firmware/token calls, and reboot calls.
- Native reboot uses only `InitiateSystemShutdownExW` with the exact planned,
  non-forced flags from the spec and a separate exact-state shutdown privilege
  scope.

- [ ] Add RED integration tests for Inspect, Configure, and every Switch
  conflict/readback/rollback/reboot branch; assert full call order and that
  Configure never writes/reboots and reboot never precedes readback.
- [ ] Add RED reboot tests for absent/not-all-assigned privilege,
  accepted/rejected/unknown boundary outcomes, immediate error capture, exact
  restoration, and no force flags or shell fallback.
- [ ] Implement composition and the Windows default non-mutating rollback
  result. Keep system constructors private to production helper wiring.
- [ ] Re-run Linux adapter tests to prove shared trait/report changes do not
  alter Linux behavior; run all platform tests, Windows target check, fmt, and
  scoped clippy.
- [ ] Commit as `feat(platform): integrate Windows production adapter`.

### Task 6: Protocol authentication and trusted Windows dispatch

**Files:**
- Modify: `crates/protocol/src/lib.rs`
- Modify: `crates/helper/src/lib.rs`
- Modify: `crates/helper/src/dispatch.rs`
- Create: `crates/helper/src/windows.rs`
- Create: `crates/helper/tests/windows_dispatch.rs`
- Modify: `crates/helper/tests/protocol.rs`

**Interfaces:**
- Keep authentication out of semantic protocol DTOs: the transport accepts a
  request only after OS-backed peer verification, without a bearer secret or
  protocol negotiation. The v2 request/response envelopes correlate one
  intent with one exact 128-bit request ID.
- `run_windows` always calls shared core with `Os::Windows`; system production
  wiring constructs the locked protected store and Windows platform only after
  authentication.

- [ ] Add RED protocol tests for v2-only hello/request/response, duplicate/
  unknown fields, invalid lengths, arbitrary path/name/GUID/command rejection,
  exact response-ID echo/mismatch handling, frame and aggregate budget, and no
  credential/authenticator field.
- [ ] Add RED dispatch tests for non-elevated rejection, single request/single
  response, host OS fixed to Windows, helper revalidation through core,
  authentication-before-request, mutex acquisition before store/firmware work,
  ownership through terminal reporting, timeout/abandonment failure, no retry
  after send, and handle/store lock lifetime.
- [ ] Implement pure authentication and dispatch with injectable boundaries.
  No real pipe or helper entry point is launched in this task.
- [ ] Run protocol/helper tests, Windows target check, fmt, and scoped clippy.
- [ ] Commit as `feat(helper): add trusted Windows one-shot dispatch`.

### Task 7: Authenticated Windows named-pipe helper endpoint

**Files:**
- Modify: `crates/helper/Cargo.toml`
- Modify: `crates/helper/src/main.rs`
- Modify: `crates/helper/src/windows.rs`
- Create: `crates/helper/src/windows/pipe.rs`
- Create: `crates/helper/tests/windows_pipe.rs`

**Interfaces:**
- Strict helper CLI parser for version, 128-bit request-ID/pipe suffix, and GUI
  PID only.
- Fakeable pipe/process/token/image/session boundary; Windows-only system
  implementation uses first-instance local named pipe with explicit DACL.

- [ ] Add RED pure/fake tests for exact argument grammar; traversal/extra/
  duplicate/malformed arguments; first-instance and remote rejection; one
  connection; explicit allowed principals/minimum rights; server PID/session/
  fixed GUI image/continuous-process verification; generic pre-request auth
  failure; exact pipe/request/response ID correlation; proof no command-line
  secret exists; 120/30 second deadline
  behavior; extra frame rejection; exactly-once closure.
- [ ] Implement helper endpoint and Windows entry point behind target cfg.
  `main` tests only the parser/fake session and never start the endpoint.
- [ ] Add static assertions against service/autostart/child/shell/dynamic-loader/
  BCD APIs in helper source.
- [ ] Run helper fake tests, Windows target check, fmt, and scoped clippy.
- [ ] Commit as `feat(helper): add authenticated Windows pipe endpoint`.

### Task 8: Windows GUI launcher and authenticated client

**Files:**
- Modify: `crates/gui/Cargo.toml`
- Modify: `crates/gui/src/helper_client.rs`
- Create: `crates/gui/src/helper_client/windows.rs`
- Modify: `crates/gui/tests/client.rs`
- Create: `crates/gui/tests/windows_client.rs`

**Interfaces:**
- Windows boundary creates the secured pipe, starts the fixed Program Files
  helper using `ShellExecuteExW(runas, SEE_MASK_NOCLOSEPROCESS)`, authenticates
  its PID/token/image/session, then reuses closed protocol requests.

- [ ] Refactor the platform-neutral client test-first so Linux spawn semantics
  remain unchanged and Windows supplies a distinct launch/session boundary.
- [ ] Add RED Windows fake tests for fixed paths, asInvoker GUI/runas helper,
  explicit pipe ACL, UAC cancellation, launch failure, different-admin token,
  PID/image/session mismatch, peer-authentication failure, fresh nonzero OS
  random request IDs, exact pipe/request/response correlation and mismatch,
  before-send versus unknown-after-send, no automatic retry, one request/
  response, and deadlines.
- [ ] Implement the Windows client and native launcher/pipe calls. Tests must
  not call `ShellExecuteExW`, create a real named pipe, or launch the helper.
- [ ] Run GUI client/controller tests, Windows target check, fmt, and scoped
  clippy.
- [ ] Commit as `feat(gui): add Windows elevated helper client`.

### Task 9: Windows GUI cache and application entry point

**Files:**
- Modify: `crates/gui/src/cache.rs`
- Create: `crates/gui/src/cache/windows.rs`
- Modify: `crates/gui/src/main.rs`
- Modify: `crates/gui/tests/cache.rs`
- Modify: `crates/gui/tests/controller.rs`
- Modify: `crates/gui/tests/ui_static.rs`

**Interfaces:**
- Per-user cache resolves the fixed LocalAppData path and stores bounded,
  display-only state; it is never a trust source.
- Windows `main` wires existing controller/UI to the Windows helper client and
  cache with no direct platform adapter dependency.

- [ ] Add RED cache tests for fixed known-folder resolution, absolute
  containment, reparse/oversize/malformed handling, atomic user-file update,
  sanitized descriptions, and no identity/raw-data fields.
- [ ] Add RED controller/static tests for distinct validated/BootNext/reboot/
  rollback/unknown-after-send messages and proof the GUI source has no firmware,
  privilege, reboot, BCD, arbitrary process, or generic writer capability.
- [ ] Implement Windows cache and entry point while preserving Linux tests and
  UX behavior.
- [ ] Run all GUI tests, Windows target check, fmt, and scoped clippy.
- [ ] Commit as `feat(gui): wire Windows production application`.

### Task 10: Windows package staging, static audit, CI, and acceptance docs

**Files:**
- Create: `packaging/windows/stage.ps1`
- Create: `packaging/windows/check-package.ps1`
- Create: `packaging/windows/check-capabilities.ps1`
- Create: `packaging/windows/manifest.json`
- Create: `packaging/windows/boothop-gui.manifest`
- Create: `packaging/windows/boothop-helper.manifest`
- Create: `packaging/windows/tests/package_fake.ps1`
- Modify: `.github/workflows/test.yml`
- Modify: `docs/acceptance/firmware.md`
- Modify: `docs/acceptance/gui.md`
- Modify: `docs/acceptance/release.md`
- Modify: `docs/research/support-matrix.md`
- Modify: `README.md`

**Interfaces:**
- Deterministic non-installing stage layout, asInvoker GUI manifest,
  requireAdministrator helper manifest, binary hashes, architecture and signing
  placeholders; no service/autostart/driver/BCD behavior.
- GitHub Windows job compiles and runs only pure/fake tests and static/package
  audits.

- [ ] Add RED fake package tests for fixed Program Files/ProgramData layout,
  manifests, no install side effects, no external paths, stable hashes, no
  service/autostart artifacts, matching protocol-v2 metadata, expected failure
  on missing/extra/mixed-version binaries, and an explicit non-production
  marker until atomic installer/recovery/downgrade work exists.
- [ ] Add RED capability-audit fixtures covering allowed and forbidden
  occurrences of firmware/token/reboot/process/dynamic-loader/BCD symbols.
- [ ] Implement scripts and update CI. The CI job must contain no UAC,
  production helper execution, firmware/BCD, ACL mutation, shutdown, or reboot
  step.
- [ ] Update acceptance docs with W1--W5 separately authorized stages,
  Windows1W/Stage5 separation, Win32-203 limitation, signing requirement, and
  exact no-overclaim status.
- [ ] Run package/capability fake tests, YAML/static validation, fmt, clippy,
  workspace tests where local policy permits, Windows target checks, and Git
  ignore/status checks.
- [ ] Commit as `build(windows): add production packaging and CI gates`.

### Task 11: Full software verification and integration readiness

**Files:**
- Modify only files required by independently reviewed verification findings.
- Store reports only in this plan's ignored SDD workspace.

**Interfaces:**
- Produce reproducible software evidence without real-system execution.

- [ ] Run `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked
  -- -D warnings`, `cargo test --workspace --locked`, all Windows-target compile
  checks, Linux package/isolation checks, Windows package/capability checks,
  source audits, PE import audit when a PE can be produced, and clean-worktree/
  ignore checks.
- [ ] If Smart App Control 4551 blocks local execution, record the exact error;
  do not weaken policy. Use trusted-target compile/tests where permitted and
  require both GitHub Linux and Windows jobs green before a software-complete
  claim.
- [ ] Run independent platform/API, security boundary, helper/IPC,
  rollback/state-machine, whole-code-quality, and integration-readiness
  reviews. Route every Critical/Important finding through the bounded fix and
  scoped re-review process.
- [ ] Confirm no Windows1W/Stage5/new acceptance tag exists or is created, no
  real collector/production API path ran, and the main worktree remains clean.
- [ ] Commit only review-required tracked fixes/documentation. Stop at the
  development-branch integration approval boundary; do not merge.
