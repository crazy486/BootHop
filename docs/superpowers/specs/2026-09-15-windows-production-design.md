# BootHop Windows production design

Date: 2026-09-15  
Status: approved architecture, software implementation authorized; real-system acceptance not authorized

## Purpose and boundary

This specification defines the Windows production adapter, protected store,
transient elevated helper, GUI transport, packaging baseline, and their tests.
It extends the approved shared design and its opaque-identity and Linux-first
amendments. It supersedes only their protocol-v1 freeze as described below; all
other shared and Linux requirements remain binding. The shared core remains the
sole owner of target validation and the Inspect/Configure/Switch state machine.

This implementation session may compile and link Win32 calls and may exercise
only injected fakes, pure parsers, compile-time checks, and ordinary filesystem
tests under temporary test roots. It must not invoke a real firmware API,
enable a real token privilege, display UAC, launch the production helper,
write BCD, request shutdown, or reboot. Those actions remain separate,
explicitly authorized acceptance stages.

The baseline acceptance state is unchanged by software completion:

- shared/Linux software verification and Linux Stages 1--4: PASS;
- Linux Stage 5: pending Windows-side post-boot closure;
- Windows1W: PASS_WITH_LIMITATION;
- Windows production real-system acceptance: NOT STARTED;
- Windows to Linux real switch and final bidirectional MVP: NOT STARTED.

## Non-negotiable invariants

1. `boothop-core` owns parsing, canonical identity, record validation, target
   selection, conflict handling, mutation ordering, readback, reboot ordering,
   residual reporting, and rollback policy.
2. `boothop-platform` owns only Windows mechanisms: firmware I/O, scoped token
   privileges, protected filesystem storage, and the reboot request.
3. The ordinary GUI is untrusted semantic input. It cannot import firmware
   write APIs, open the protected record, enable privileges, or request reboot
   except by sending one closed `Request` to the authenticated helper.
4. The elevated helper is transient and one-shot. It re-decodes, revalidates,
   executes at most one request, sends at most one terminal response, and exits.
   There is no service, daemon, autostart entry, arbitrary command, arbitrary
   path, arbitrary variable name, or arbitrary GUID in the protocol.
5. `BootOrder` is read-only. BootHop never creates, deletes, repairs, reorders,
   or edits `Boot####`, and never invokes `bcdedit`.
6. The only production firmware mutation surface is a private, typed
   `set_boot_next(BootId)` operation and the private exact-restore operation
   described below. No public generic variable writer exists.
7. No reboot request occurs before target revalidation, conflict checks,
   successful write (when needed), and exact immediate `BootNext` readback.
8. An IPC or API ambiguity after mutation is never retried automatically.

## Crate and module layout

The implementation adds the following Windows-only modules:

```text
crates/platform/src/windows.rs
crates/platform/src/windows/firmware.rs
crates/platform/src/windows/privilege.rs
crates/platform/src/windows/store.rs
crates/platform/src/windows/reboot.rs
crates/helper/src/windows.rs
crates/helper/src/windows/pipe.rs
crates/gui/src/helper_client/windows.rs
crates/gui/src/cache/windows.rs
packaging/windows/*
```

`windows-sys` is a target-specific dependency and all native functions are
behind small injectable traits. Non-Windows hosts compile the pure state
machines and fakes; Windows targets additionally compile the system backends.
The research collector remains an independent tool and is not a production
dependency.

## Shared state-machine changes

### Platform contract

The existing `Platform` trait remains semantic rather than Win32-shaped. It is
extended with one narrow rollback method:

```rust
fn rollback_next(
    &mut self,
    original: Option<BootId>,
    written: BootId,
) -> RollbackOutcome;
```

`RollbackOutcome` is closed:

- `NotNeeded`: the current value already equals the original value;
- `Restored`: the adapter safely restored the exact original value;
- `Unsafe`: no write was made because current state, exclusivity, or absence
  semantics could not be proven sufficiently;
- `Failed(Error)`: a restore was attempted but failed or its readback failed.

The method cannot choose a different target and cannot clear a value unless
`original` is `None`. Linux preserves its current behavior by returning
`Unsafe` without adding new efivarfs writes. The first Windows production
backend also returns `Unsafe` without writing: Windows exposes no firmware
compare-and-swap and BootHop cannot exclude non-BootHop writers. Fakes may model
an exclusive backend to test the shared exact-restore policy. A later real
rollback implementation requires a separately approved proof of exclusivity;
two consecutive reads alone are not that proof.

### Switch ordering

For `Switch`, core performs:

1. load and validate the protected record;
2. validate requested OS against the opposite of the host OS;
3. check the platform environment without mutation;
4. read the bounded option inventory and validate the recorded option's exact
   canonical identity, including opaque OptionalData length and SHA-256;
5. read `BootNext` and retain the exact original state;
6. if it is another target, stop with `BootNextConflict`;
7. if it is the same target, do not rewrite it;
8. if absent, re-read immediately, apply the same conflict rule, then write the
   target once;
9. read back and require exactly the selected target;
10. record `BootNextVerified`, then request reboot once.

If reboot is rejected after this flow wrote `BootNext`, core calls
`rollback_next(original, target)` once and records the outcome without hiding
the original `RebootRejected` cause. If the same target pre-existed, BootHop did
not create the state and does not attempt rollback. Unknown reboot outcome is
never rolled back because the system may already be shutting down. Write or
readback failures are treated as unknown mutation state and are not followed
by a speculative rollback.

Core records whether this invocation performed the BootNext write. After a
definite reboot rejection, it makes one read-only post-rejection observation.
If core did not perform the write, it never requests rollback. If the observed
state already equals the exact original state, rollback is `NotNeeded`. If the
observation is neither the exact original nor the value this invocation wrote,
or if the observation fails, rollback is `Unsafe` and no rollback method is
called. Only when the observation still equals the value written by this
invocation may core call `rollback_next`; the adapter must still enforce its
own exclusivity contract immediately before any restore write.

The stage/report model adds `RollbackAttempted`, `RollbackRestored`,
`RollbackUnsafe`, and `RollbackFailed`. A `RollbackAssessment` in
`FlowFailure` records the closed result independently of the existing residual
observation. `ResidualPossible` is retained whenever the post-failure state is
not proven equal to the original. Protocol DTOs mirror these additions and the
protocol version is incremented to 2.

This is a deliberate, narrow successor amendment to the earlier v1 freeze.
There is no released mixed-version deployment to preserve: GUI and helper must
be packaged and upgraded as one signed product unit. A v2 endpoint rejects v1 and
vice versa; there is no downgrade, negotiation, or compatibility decoder. The
Linux transport moves mechanically to the same v2 DTOs while preserving its
domain behavior. This explicit atomic-upgrade rule replaces the former
requirement to keep `PROTOCOL_VERSION == 1` unchanged.

This branch can stage and verify a co-versioned GUI/helper pair, but it does not
claim that a signed installer transaction or interrupted-upgrade recovery is
complete. Production distribution remains blocked until an installer proves
atomic replacement, rollback/recovery after interruption, and downgrade
prevention. Package tests reject mixed protocol-version metadata.

Stage semantics are exact: an already-original observation records
`RollbackAssessment::NotNeeded` and no rollback stage; an unreadable or
concurrently changed observation records `RollbackUnsafe` without
`RollbackAttempted`; a call to `rollback_next` first records
`RollbackAttempted`, then exactly one of restored/unsafe/failed. If the adapter
atomically observes that another actor already restored the original, the
assessment is `NotNeeded` with only `RollbackAttempted`. Restored or not-needed
state clears the residual witness; unsafe, failed, or unreadable state retains
`ResidualPossible`. Linux migrates the required trait method and test fakes,
but its system adapter always returns `Unsafe` without a firmware write.

## Windows firmware reads

### Native API and privilege scope

The backend uses documented imports only:

- `GetFirmwareType` to reject non-UEFI/unknown environments;
- `GetFirmwareEnvironmentVariableExW` for reads;
- `SetFirmwareEnvironmentVariableExW` only inside the private BootNext writer;
- `OpenProcessToken`, `LookupPrivilegeValueW`, `AdjustTokenPrivileges`,
  `SetLastError`, `GetLastError`, and `CloseHandle` for privilege scope.

Every firmware name is produced by a closed internal enum. The GUID is always
`{8be4df61-93ca-11d2-aa0d-00e098032b8c}`. No IPC or public API supplies either
field.

The helper opens its current-process token with
`TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY`, looks up
`SeSystemEnvironmentPrivilege`, clears last error, and calls
`AdjustTokenPrivileges`. A successful BOOL is insufficient:
`ERROR_NOT_ALL_ASSIGNED` fails closed. The exact returned prior
`TOKEN_PRIVILEGES` state is retained, restored on every exit path, and the
token handle is closed exactly once. The privilege scope covers only the
firmware portion of an operation; protected-store parsing and IPC setup happen
outside it. Restoration failure is terminal and is never downgraded to a
diagnostic.

The system backend is constructed only by the helper production entry point.
Tests inject a token/firmware call recorder and never construct that backend.

### Bounded read and parsing

Windows returns the firmware payload without Linux efivarfs' four-byte
attribute prefix. `GetFirmwareEnvironmentVariableExW` returns the payload byte
count and writes attributes separately; the adapter validates and combines
those values before passing a `Boot####` payload to the shared parser.

Reads start with 4 KiB and may grow only for an explicit insufficient-buffer
result, up to 1 MiB per variable and 1 MiB total raw inventory data across all
controls and referenced options. Cumulative accounting charges each successful
variable's returned payload byte count plus its four-byte attributes value.
Exceeding either bound fails the whole inventory without returning a partial
result. Zero means failure and `GetLastError` is
captured immediately. No native error, including observed Win32 203, is
silently converted to absence in the initial production policy. Consequently,
absence-sensitive `BootNext` operations fail closed until an explicitly
approved native absence mapping exists. This limitation is visible in errors,
tests, acceptance, and release notes.

Attributes and payload shapes are exact:

| Variable | Attributes | Payload |
|---|---:|---|
| `BootOrder` | `0x7` | non-empty, even-length LE `u16[]` |
| `BootCurrent` | `0x6` | exactly one LE `u16` |
| `BootNext` | `0x7` | exactly one LE `u16` |
| `Boot####` | `0x7` | bounded raw EFI load-option payload |

Inspect/Configure option discovery is the deduplicated union of IDs referenced
by `BootOrder` and `BootCurrent` only. `read_options` never reads `BootNext`, in
accordance with the shared contract. Switch reads `BootNext` separately through
`read_next`; a conflicting ID is sufficient to stop and is not expanded into
another Boot#### read. Production therefore does not reuse the collector's
three-control discovery union. It never scans
`Boot0000`--`BootFFFF`, enumerates arbitrary variables, or repairs malformed
state. Referenced missing, unreadable, malformed, or attribute-invalid options
fail closed. Duplicate `BootOrder` entries become bounded diagnostics while
duplicate returned IDs remain rejected by core.

### BootNext write

The private writer accepts only `BootId`, serializes exactly two little-endian
bytes, and calls `SetFirmwareEnvironmentVariableExW` for `BootNext` with the
fixed GUID and attributes `0x7`. It cannot write a zero-length payload and
therefore cannot delete. It captures the raw error immediately and never
retries.

The platform method is not exported outside the `Platform` implementation;
the GUI and protocol contain no writer-shaped request. Static tests fail if
the GUI declares/imports `SetFirmwareEnvironmentVariable*`, firmware getters,
privilege adjustment, reboot APIs, `bcdedit`, or dynamic API loading.

## Protected target store

The production record is
`FOLDERID_ProgramData\BootHop\targets.json`. It is distinct from the GUI's
per-user display cache. The trusted helper resolves the known folder through
the shell known-folder API; it does not accept environment variables, registry
overrides, relative paths, or IPC paths.

The `BootHop` directory and record have protected owner/DACL contracts:

- owner: `SYSTEM` or `BUILTIN\Administrators`;
- `SYSTEM` and `BUILTIN\Administrators`: full control;
- ordinary users: no access; never read/create/write/delete/change-permissions;
- inherited ACEs that grant ordinary-user mutation are rejected;
- reparse points, alternate target roots, and unexpected object types are
  rejected.

Creation uses an explicit security descriptor, not ProgramData inheritance.
Every load validates root containment, component metadata, owner, DACL, type,
size, and record encoding before accepting `Missing` or `Ready`. `Missing` is
valid only when the trusted directory is validated and the final component is
confirmed absent.

The helper acquires the fixed `Global\BootHop.Operation.v1` mutex before it
constructs the protected store, loads a record, or reads firmware, and holds it
through terminal response transmission. The mutex has an explicit DACL granting
only `SYSTEM` and `BUILTIN\Administrators` synchronization/full-control rights.
Timeout maps to `Busy`; an abandoned mutex fails closed as a platform error and
the operation does not inspect or mutate state. It is released exactly once on
every normal/error/unwind path. Store Save relies on this already-held
operation guard and writes a bounded same-directory exclusive temporary file
with the final protected DACL, flushes it, closes it, then uses `ReplaceFileW`
when the record exists. First creation uses an exclusive create followed by directory
and ACL revalidation. `ReplaceFileW` flags that ignore ACL/merge errors are
forbidden. Its unsupported `REPLACEFILE_WRITE_THROUGH` flag is not used.
Because Win32 does not expose a portable directory-fsync durability guarantee,
the store distinguishes logical replacement success from
`StoreDurabilityUnknown`; it never retries a completed replacement.

Tests use a fake store-call boundary and ordinary temporary roots only. They
verify operation order and security decisions but do not claim that a real
ProgramData ACL was exercised.

## Transient helper and IPC

### Launch

The installed GUI resolves a fixed helper path beneath Program Files and calls
`ShellExecuteExW` with verb `runas` and `SEE_MASK_NOCLOSEPROCESS`. Arguments
contain only a versioned mode marker, random 128-bit pipe suffix, and GUI PID.
The random suffix prevents accidental name collisions but is not treated as an
authenticator or secret. The request itself travels only after OS-backed peer
authentication. UAC cancellation is reported as cancellation; launch failure
before complete request delivery is retryable only by explicit user action.

The helper refuses unknown, duplicate, malformed, overlong, relative-path, or
command-shaped arguments and refuses to run unless its token is elevated and
its executable path matches the installed Program Files path. It is not
installed as a service and has no persistent endpoint.

### Named pipe session

The GUI creates a local named-pipe server using the random suffix, first-pipe
instance semantics, remote-client rejection, one instance, and an explicit
DACL granting only the launching interactive user SID, `SYSTEM`, and elevated
Administrators the minimum required access. The default pipe ACL is forbidden.

Both endpoints authenticate the peer before request delivery:

- GUI obtains the connected helper PID and verifies an elevated/high-integrity
  token, session expectations, and the fixed helper image path;
- helper obtains the server PID and verifies the original GUI process handle,
  session, fixed GUI image path, and continuity of that process;
- a different administrator credential at UAC is allowed, so equal user SIDs
  are not required.

Authentication is complete only when all DACL, PID, live process handle,
elevation/integrity, fixed image, and session checks succeed in both directions.
There is no application cryptographic handshake, command-line secret, bearer
token, or reusable credential. Failure ordering reveals only a generic
authentication failure and closes the session before request bytes are read.

The GUI keeps a synchronization handle to the launched helper and validates
that the pipe peer PID is that process. Handles are closed once on all paths.

Wire frames remain `u32` little-endian length plus canonical UTF-8 JSON, with
the prefix included in every budget. The sole GUI-to-helper request frame is at
most 65,536 bytes. All helper-to-GUI output for one operation—the hello and
terminal response frames plus any bounded diagnostics/stderr—is at most 65,536
bytes in aggregate. Authentication/connect has one 120-second deadline;
authenticated request/response and reboot dispatch have one 30-second
deadline. Exactly one request and one response are allowed.
After complete request delivery, timeout, disconnect, malformed response, or
helper exit maps to unknown-after-send and is never automatically replayed.

Protocol v2 adds a required `request_id` to request and response envelopes. It
is exactly 32 lowercase hexadecimal characters encoding a fresh, nonzero
128-bit value generated from the OS random source for every GUI invocation.
The helper validates the syntax, binds the ID to exactly one decoded intent,
and echoes it unchanged in the sole response; the GUI rejects a mismatch as
unknown-after-send. On Windows the same value is the named-pipe suffix passed
at launch, binding the launched helper, pipe namespace, request, and response.
It is correlation data, not an authenticator or secret. On Linux it is carried
only in the request/response envelopes. IDs are never retried or reused, and
compacted terminal responses retain the same ID.

### Trusted dispatch

Helper dispatch recognizes only `Inspect`, `Configure { boot_id, os }`, and
`Switch { os }`. It supplies `Os::Windows` to shared `execute`; it never trusts
the GUI to name the host. Configure and Switch therefore re-read firmware and
recompute canonical identity in the elevated process. The pipe remains open
until the terminal result has been fully encoded or a bounded transport error
occurs.

## Reboot contract

The Windows platform requests a planned reboot through
`InitiateSystemShutdownExW(NULL, NULL, 0, FALSE, TRUE,
SHTDN_REASON_FLAG_PLANNED | SHTDN_REASON_MAJOR_OTHER)`. It does not shell out,
force applications, or fall back to another reboot API.

`SeShutdownPrivilege` is enabled in its own exact-state RAII scope only after
`BootNextVerified`, checked for `ERROR_NOT_ALL_ASSIGNED`, and restored if the
process continues. Nonzero means the request was accepted, not that Windows
will reboot or the target OS will boot. A definite zero plus captured error is
`Rejected`; transport/process loss after the call boundary is `Unknown`.

No unit or CI test constructs the native reboot backend. Fakes record call
ordering and prove reboot is never reached before readback.

## GUI and user-visible state

The controller and Slint UI remain platform-neutral. A Windows entry point
wires the Windows helper client and Windows per-user cache. The cache stores
only display-safe `BootId`, OS, and sanitized description under the user's
local application-data directory; it is not trusted for Switch or Configure
and contains no canonical identity or opaque raw bytes.

The UI reports these separately:

- target configured/validated;
- BootNext verified;
- reboot accepted, rejected, or unknown;
- rollback not needed, restored, unsafe, or failed;
- unknown-after-send with an explicit no-auto-retry instruction.

Success never claims that the destination OS booted. Windows1W completion and
Stage 5 closure are separate evidence conclusions and are not inferred from a
production software test.

## Error mapping

Platform errors retain a fixed operation label and the immediate raw Win32
code, never a path, variable payload, user SID, request ID, or identity digest.
The model distinguishes at least:

- `NotUefi`;
- `PrivilegeUnavailable` / `PrivilegeEnableFailed` /
  `PrivilegeRestoreFailed`;
- `FirmwareReadFailed` / `FirmwareWriteFailed`;
- `BootNextUnavailable` / `BootNextConflict`;
- `TargetMissing` / `IdentityMismatch` / unsupported record or identity;
- protected-store validation, replacement, and durability failures;
- `ReadbackFailed`;
- `RebootRejected` / unknown-after-send;
- rollback unsafe and rollback failed.

The protocol uses closed tagged variants and rejects unknown fields/variants.
Raw numeric codes are diagnostics only; application decisions use the closed
semantic class.

## Packaging and installation baseline

The repository supplies a deterministic Windows staging script and manifest
that place:

- the ordinary GUI in Program Files;
- the helper at its one fixed Program Files path;
- the protected store directory in ProgramData with the explicit ACL;
- no service, scheduled task, Run key, startup shortcut, driver, or shell
  command handler.

The package manifest records architecture, binary hashes, requested execution
level (GUI asInvoker; helper requireAdministrator), publisher placeholder, and
protocol version 2 for both binaries. Package checks reject a mixed pair. CI
may build and inspect staging output but does not install it. Production
distribution requires the atomic installer/recovery/downgrade work, code
signing, and an installer-signing/release process; self-signed development
certificates are not a production acceptance claim.

## Test strategy

All behavior is developed test-first. Required software tests include:

### Read and parse

- UEFI success and non-UEFI rejection;
- bounded growth, malformed sizes, invalid attributes, malformed controls,
  missing/unreadable referenced options, parser failures, and raw-code mapping;
- union-only discovery and proof that no range scan occurs;
- Windows payload passes to core without an efivarfs prefix.

### Privilege

- absent privilege and `ERROR_NOT_ALL_ASSIGNED` fail closed;
- already-enabled, enable-success, exact prior-state restore, restoration on
  every error path, restoration failure, and one handle close;
- firmware and reboot privilege scopes are separate.

### Configure/store

- valid record, missing target, identity mismatch, record-version failure;
- protected-directory/owner/DACL/reparse validation;
- same-directory exclusive temp, flush/close/replace order, ACL preservation,
  first creation, cleanup, durability-unknown, and no retry;
- Configure performs no firmware write and no reboot.

### Switch/rollback/reboot

- BootNext absent, same target, conflicting target, unavailable state;
- target missing/mismatched and opaque OptionalData changes;
- little-endian payload, exact attributes, one write, matching/mismatching
  readback;
- rollback exact original, safe clear in an exclusive fake, concurrent change,
  unsafe backend, attempted failure, and readback failure;
- accepted/rejected/unknown reboot and proof it never precedes readback;
- original failure is retained when rollback also fails.

### IPC/security/GUI

- strict argument grammar, first-instance local pipe, explicit DACL, PID/token/
  image/session verification, different-admin elevation, request-ID/pipe
  correlation, one-shot
  frame and deadline behavior;
- cancellation, before-send, and unknown-after-send classifications;
- GUI cannot bypass helper and has no native mutation/reboot imports;
- protocol rejects arbitrary paths, variable names, GUIDs, duplicate keys,
  unknown fields, extra frames, and over-budget messages;
- per-user cache is untrusted, bounded, sanitized, and ignored by Git.

### Static capability audit

Source, produced PE imports, package layout, and scripts are audited for:
`SetFirmwareEnvironmentVariable*`, `GetFirmwareEnvironmentVariable*`,
`AdjustTokenPrivileges`, `InitiateSystemShutdown*`/`ExitWindows*`,
`CreateProcess*`/`ShellExecute*`, `bcdedit`, and
`LoadLibrary*`/`GetProcAddress`. Every occurrence must be in the named backend,
UAC launcher, audited runtime support, or negative test allowlist; the GUI must
have no firmware/privilege/reboot path.

## CI and verification

Linux CI continues to run formatting, clippy with warnings denied, workspace
tests, package smoke tests, and isolation audit. A Windows job pins the Rust
toolchain, compiles all targets with MSVC, runs only fake/pure tests, stages the
package without installation, and performs source/import audits. CI must not
request elevation, instantiate `SystemWindowsCalls`, launch the helper, touch
firmware/BCD, or request shutdown.

Local Smart App Control error 4551 is a documented host execution limitation,
not a test pass. Where it blocks local executables, verification must combine a
trusted external target directory where permitted, compile/check evidence, and
green GitHub Linux and Windows jobs; the limitation remains reported.

## Separately authorized real-system acceptance

The software branch stops before all stages below. Each requires fresh,
explicit authorization and private evidence:

1. **W1 read-only:** production native reads and privilege restoration only;
   no write or reboot. This does not repeat or replace Windows1W research.
2. **W2 configure:** elevated helper, protected ProgramData store, ACL and
   record readback only; no firmware write or reboot.
3. **W3 pre-switch:** target identity and BootNext conflict observations only.
4. **W4 mutation:** blocked until a separately reviewed and explicitly approved
   mapping can distinguish confirmed native BootNext absence from unavailable
   state. After that gate, one authorized BootNext write and immediate readback,
   with automatic reboot disabled by an acceptance interlock.
5. **W5 switch:** blocked by the same absence-mapping gate; afterward, one
   authorized production Windows-to-Linux switch and reboot,
   followed by post-boot evidence.

Windows1W API evidence and Linux Stage 5 post-boot closure may share an
authorized read-only evidence session, but their reports and conclusions stay
separate. Neither proves this production implementation, and production
software verification does not prove any real-system stage.

## Official contract references

- [GetFirmwareType](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwaretype)
- [GetFirmwareEnvironmentVariableExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexw)
- [SetFirmwareEnvironmentVariableExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfirmwareenvironmentvariableexw)
- [Changing privileges in a token](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [Named pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)
- [InitiateSystemShutdownExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-initiatesystemshutdownexw)
- [UEFI 2.10 variable services](https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html)

## Design self-review

- Placeholder audit: no production path, GUID, API, privilege, attribute,
  framing limit, or timeout is left as TBD. Publisher/signing identity is
  explicitly a release input, not invented by this implementation.
- Contradiction audit: helper-only mutation, GUI untrustworthiness, one-shot
  transport, unknown-after-send, and no real-system operations agree across
  the shared, platform, IPC, GUI, CI, and acceptance sections.
- Protocol audit: the rollback report requires v2; the earlier v1 freeze is
  explicitly superseded for a co-versioned GUI/helper package with no
  mixed-version fallback, while distribution stays blocked until atomic
  installer/recovery/downgrade behavior is implemented and tested.
- Linux divergence audit: core additions are additive reporting and a rollback
  hook whose Linux implementation is non-mutating; existing Linux firmware,
  reboot, store, and authorization mechanics remain unchanged.
- Security audit: no arbitrary native writer, variable name, GUID, path,
  command, dynamic API, default pipe ACL, blind clear, speculative retry, or
  implicit privilege grant is introduced.
- Scope audit: BCD repair, boot-entry management, services, drivers, semantic
  decoding of Windows OptionalData, updater behavior, and real acceptance are
  excluded.
- Evidence audit: Windows1W remains research evidence with limitations; no
  software test or compiled native backend is relabeled as real-system proof.
