# Linux → Windows Quick Hop acceptance — 2026-09-23, updated 2026-09-24

Current status: **POST-BOOT EVIDENCE RECORDED — STAGE 5 PENDING (PRE-RUN BOOTORDER MISSING)**

The status below describes the historical 2026-09-23 pre-flight attempt only.

This record covers the first attempted real Quick Hop preparation on the
Arch Linux host. No production Switch was launched because the required
preconditions were not satisfied. It is not a firmware or reboot result.

## Git identity

- Branch: `boothop-simple`
- Local HEAD: `bc5d7a9481f1994666ccbcab7c05c7b9d4e64af7`
- `origin/boothop-simple`: the same commit
- Tracked worktree: clean

## Read-only pre-flight observations

- `/etc/os-release`: Arch Linux.
- UEFI variable directory exists.
- `efivarfs` is mounted read-only (`ro`). A BootNext write cannot be
  authorized while this condition remains.
- systemd: 261.3; polkit: 127; graphical session: Wayland.
- `Boot0003`, `BootCurrent`, and `BootOrder` variable names were present.
- No `BootNext` variable name was observed during this pre-flight check; this
  is only an observation and not a Switch result.
- `cargo` and `rustup` were not available in the current environment, so an
  exact-HEAD release build could not be produced.
- Existing installed GUI/helper files were present, but their build identity
  could not be established as the current exact HEAD release artifact.
- `/var/lib/boothop/targets.json` and `/var/lib/boothop/operation.lock` were
  absent. Therefore no authoritative protected Windows target record was
  available for Quick Hop.
- A user cache file existed, but cache is not an authority and cannot replace
  the protected record.

## Execution result

- Quick Hop executable: **not launched**.
- `Request::Switch`: **not sent**.
- pkexec/polkit helper: **not invoked**.
- Protected target validation: **not reached**.
- BootNext write: **not performed**.
- BootNext read-back: **not performed**.
- logind reboot request: **not sent**.
- Reboot: **not performed**.
- Actual arrival in Windows: **not observed**.
- BootOrder/Boot####/BCD mutation: **none performed by this attempt**.

## Blocking conditions and safe next step

The acceptance stops before any mutation. A future separately continued run
must first restore a writable efivarfs mount through the normal system setup,
provide the pinned Rust toolchain, build and install the exact HEAD, and use
the existing Configure flow to establish a protected Windows target record.
Those changes are provisioning steps; they are not claimed here and must be
verified before another single authorized Quick Hop attempt.

No automatic retry was performed. No EFI variable, BootOrder, boot entry,
BCD, security policy, or reboot state was modified.

## 2026-09-24 post-boot follow-up

This follow-up records the later Linux → Windows Quick Hop reported by the
operator and the single authorized Windows-side read-only collector run. It
does not replace or rewrite the historical 2026-09-23 pre-flight result above.

### Git and run identity

- Branch: `boothop-simple`.
- HEAD when the collector ran: `8b4e281c34ae875f1baddb2312ff58df6244d13e`
  (equal to `origin/boothop-simple` at collection time).
- Collector run-id: `linux-quick-hop-stage5-20260924-01`.
- Private report: `.superpowers/sdd/2026-09-08-boothop/private/windows1w/linux-quick-hop-stage5-20260924-01/collector-report.txt`.
- The evidence directory is ignored by Git. Raw option payloads remain private
  there and are not part of this tracked report.

### Quick Hop result (operator report)

- Production Quick Hop completed once; no manual retry was performed.
- Target validation, BootNext write/read-back, and normal reboot were reported
  successful through the production flow.
- Actual arrival in Windows: **PASS** (user-confirmed observation).
- This is separate from the collector's `BootCurrent` observation.

### Windows read-only collector result

The collector was invoked exactly once from an Administrator PowerShell. Its
process exit code was `1`; the report was successfully written and records
`terminal=BootNextUnavailable`, `stable=true`, and
`boot_next_absent=false`. The nonzero exit is the collector's expected
non-accepted result for the unresolved BootNext read, not evidence of a write
or a reason to retry.

| Observation | Pass 1 | Pass 2 | Result |
| --- | --- | --- | --- |
| BootOrder | `[0000,0003]`; 4 bytes; attributes `7`; Win32 `0`; SHA-256 `1112da16eb081d8d3dedf4cfb31fb10f96d713988136da3dc00e9f0c8def0e0e` | `[0000,0003]`; 4 bytes; attributes `7`; Win32 `0`; same SHA-256 | Stable across the two sequential reads; this alone does not prove unchanged across the reboot. |
| BootCurrent | `0003`; 2 bytes; attributes `6`; Win32 `0`; SHA-256 `9b4fb24edd6d1d8830e272398263cdbf026b97392cc35387b991dc0248a628f9` | `0003`; 2 bytes; attributes `6`; Win32 `0`; same SHA-256 | Stable across the two sequential reads. |
| BootNext | `Error`; 0 bytes; attributes `0`; raw Win32 `203` | `Error`; 0 bytes; attributes `0`; raw Win32 `203` | Stable unavailable observation; semantics are not inferred as absence or consumption. |

Both referenced options (`Boot0000` and `Boot0003`) were read with attributes
`7` and passed the collector's shared parser. The collector used only the
read-only firmware path and wrote its private report/payload evidence; no
BootOrder, BootNext, Boot####, BCD, or reboot mutation was performed during
this post-boot evidence session. The production Quick Hop's reported
BootNext operation above is its distinct, expected switch action.

### Stage 5 verdict

- Quick Hop actual arrival in Windows: **PASS**.
- Post-boot BootOrder: **`[0000,0003]`, stable between both collector reads**.
- Quick Hop pre-run BootOrder: **NOT RECORDED / NOT AVAILABLE** in the current
  tracked acceptance/handoff or locally available current-run evidence. The
  2026-09-14 historical Windows1W observation is not used as a substitute.
- Permanent BootOrder preservation across this reboot: **NOT VERIFIED**.
- Post-boot BootNext: **Win32 `203` / unavailable**, recorded without inferring
  that the variable is definitely absent or consumed.
- Linux → Windows Quick Hop Stage 5: **PENDING** because the current run's
  pre-run BootOrder baseline is missing. No PASS tag or complete PASS claim is
  made.

No firmware repair or additional Switch was attempted. To close Stage 5,
obtain an authentic pre-run BootOrder record for this exact Quick Hop if one
exists outside this Windows workspace; otherwise retain this run as pending
rather than reconstructing a baseline from historical values.
