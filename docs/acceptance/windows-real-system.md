# Windows real-system acceptance runbook

Status: **W0 NOT STARTED / W1 NOT STARTED**. This runbook defines future,
separately authorized operations. Building or staging binaries does not perform
W0 or W1 and does not establish release readiness.

Windows1W remains the independent native-read research gate with verdict
`PASS_WITH_LIMITATION`. Linux Stage 5 remains pending. Neither status is changed
by this runbook or by Windows production artifact preparation.

## Evidence and artifact identity

Each run uses a new ID and stores complete output only below the gitignored
private root:

```text
.superpowers/sdd/2026-09-15-windows-production/private/
  artifacts/<commit>/
  w0/<run-id>/
  w1/<run-id>/
```

Before writing evidence, verify the destination with `git check-ignore`.
Private evidence may retain full paths, signatures, ACLs, screenshots, and raw
diagnostics. A tracked report may contain only commit IDs, artifact SHA-256 and
size, PE architecture, signature status, Boot IDs, payload lengths, firmware
attributes, payload hashes, Win32 error codes, parsed state, and the verdict.
Never commit raw firmware payloads or complete machine-specific device paths.

The acceptance pair is exactly the staged AMD64 PE files built from the stated
commit. Record the GUI and helper SHA-256, size, Authenticode status, embedded
execution level, protocol version, and source commit before W0. An unsigned
candidate is acceptance-only evidence and is not a signed release.

## W0 — acceptance-only installation

W0 exists solely to create and verify the fixed production layout needed by
W1. It is not firmware acceptance and must never configure a target, launch a
BootHop executable, request elevation through BootHop, or access firmware.

W0 requires fresh authorization for these exact host mutations:

- place the exact-hash GUI and helper at
  `C:\Program Files\BootHop\boothop-gui.exe` and
  `C:\Program Files\BootHop\boothop-helper.exe`;
- create or validate `C:\ProgramData\BootHop` with an owner restricted to
  `SYSTEM` or `BUILTIN\Administrators` and no ordinary-user access;
- establish the persistent protected-store layout required by the production
  helper, without creating `targets.json` or selecting a boot target;
- read back file identity, hashes, manifests, owner and ACL for evidence.

W0 must not install a service, scheduled task, run key, startup shortcut,
driver, shell command handler, or BCD entry. It must not start either PE. It
must not weaken Windows security policy or work around Smart App Control.

The repository currently supplies a deterministic non-installing stage, not an
atomic installer. Until an installation mechanism is separately implemented
and reviewed, W0 is blocked: ad-hoc copying or ACL commands are not an approved
substitute. Even a future successful acceptance-only W0 would not satisfy the
signed installer, upgrade recovery, downgrade prevention, or release gates.

W0 passes only when the approved installer/provisioner reports success and an
independent readback confirms the exact hashes, regular non-reparse files,
fixed paths, execution-level manifests, protected directory owner/ACL, absence
of `targets.json`, and absence of every forbidden persistence mechanism.

## W1 — production Inspect, read-only

W1 validates the production GUI-to-helper Inspect path exactly as implemented.
It does not repeat Windows1W and it does not read `BootNext`.

After a successful W0 and fresh W1 authorization, the operator may:

1. start the exact-hash `C:\Program Files\BootHop\boothop-gui.exe` normally;
2. click **检查启动配置** exactly once;
3. accept exactly one `runas` UAC prompt for the fixed helper;
4. wait for the single terminal Inspect response and save evidence privately;
5. close the GUI without selecting Configure or Switch.

The allowed sensitive operations are limited to:

- authenticated GUI → elevated fixed-path helper IPC;
- helper current-process token handling for
  `SeSystemEnvironmentPrivilege`, including exact prior-state restoration;
- `GetFirmwareType`;
- `GetFirmwareEnvironmentVariableExW` for `BootOrder`, `BootCurrent`, and the
  deduplicated union of `Boot####` IDs referenced by those two controls;
- shared load-option parsing, canonical identity validation, and read-only
  protected-record validation.

`BootNext` is deliberately outside W1. It first appears in W3 conflict
observation. The Windows1W observation of Win32 203 remains research evidence
and must not be converted into `BootNext` absence.

W1 forbids Configure, Switch, `SetFirmwareEnvironmentVariable*`, any firmware
write, protected-store save, BCD mutation, installer mutation, repair,
shutdown, or reboot. It also forbids a second automatic attempt after request
delivery or an unknown result.

W1 passes only when the exact artifacts and authenticated/elevated boundary are
verified; firmware type is UEFI; every required read has valid attributes and
shape; every referenced `Boot####` passes the shared parser; any ready protected
record passes canonical identity validation; the response has no mutation
stages; the protected layout remains byte-for-byte and metadata-stable; and no
forbidden capability is observed. Missing layout, identity mismatch, privilege
enable/restore failure, malformed firmware data, unknown transport outcome, or
any side effect is a W1 failure. A missing protected record is acceptable only
as the explicit unconfigured state after the protected layout itself validates.

## Later stages

- W2: separately authorized protected-record Configure acceptance, with no
  firmware write or reboot.
- W3: separately authorized target and `BootNext` conflict observation.
- W4: separately authorized interlocked `BootNext` mutation/readback, still
  blocked on an approved native absence mapping.
- W5: separately authorized Windows-to-Linux Switch and reboot, blocked by the
  same gate.

No W0 or W1 result completes Linux Stage 5, Windows-to-Linux acceptance, or the
final bidirectional MVP.
