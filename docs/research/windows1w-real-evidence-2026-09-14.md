# Windows1W real read-only evidence review — 2026-09-14

## Scope and immutable run identity

- Collector execution: exactly once, after one external UAC elevation.
- Reviewed HEAD: `cde23657fa0130c28d94d5365a3792e70b8e068f`.
- Artifact size: 252,416 bytes.
- Artifact SHA-256: `51FA26999455FA543E01CE8F1337A7274CBDD00D95CB80DBAD7056859B426713`.
- Run ID: `windows1w-stage5-closure-20260914-01`.
- Evidence remains in the gitignored private Windows1W area and is not committed.
- Collector exit: code 1, `accepted=false`, `terminal=BootNextUnavailable`; this is the reviewed fail-closed result, not an API-execution failure.

No retry was performed. The collector process exited, no BootHop helper or elevated child remained, and the tracked worktree stayed clean. No firmware write, BCD operation, switch, shutdown, or reboot path existed or was invoked.

## Sanitized observations

All observations are sequential, not an atomic snapshot.

| Variable | Pass 1 | Pass 2 | Attributes | SHA-256 / interpretation |
|---|---|---|---:|---|
| `BootOrder` | success, 4 bytes, `[0000,0003]` | identical | 7 | `1112da16eb081d8d3dedf4cfb31fb10f96d713988136da3dc00e9f0c8def0e0e` |
| `BootCurrent` | success, 2 bytes, `0000` | identical | 6 | `96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7` |
| `BootNext` | failure, 0 bytes, Win32 203 | identical | 0 | no payload; collector did not infer absence |
| `Boot0000` | success, 110 bytes | not reread | 7 | parser valid; `462eacda8fc8dbe39002ddae879bec0742ee4e22d5bdb6cbe1a82d3236ffa82a` |
| `Boot0003` | success, 300 bytes | not reread | 7 | parser valid; `4ba074afdfb31c3203ceb04f3c10192a9f45c78d1168d5391d31ed6724c108ee` |

Only the referenced `Boot0000` and `Boot0003` variables were read. The raw Windows payloads parsed successfully without Linux efivarfs's separate four-byte attributes prefix, supporting use of Windows-returned payload bytes as input to the shared parser.

The reviewed control flow establishes that `GetFirmwareType` selected the UEFI branch, `SeSystemEnvironmentPrivilege` enablement succeeded sufficiently for the reads, and privilege restoration returned success; otherwise this artifact would have emitted a failed collection rather than `BootNextUnavailable`. The report format did not directly persist the firmware enum, previous privilege attributes, or restoration call result, so those facts are control-flow attestations rather than independently recorded fields.

Microsoft documents that `GetFirmwareEnvironmentVariableExW` returns zero on failure and requires `GetLastError` for details. Microsoft also defines Win32 203 as `ERROR_ENVVAR_NOT_FOUND`. Post-capture review therefore judges the repeated 203 result consistent with a missing or consumed `BootNext`, but the firmware-read API page does not explicitly guarantee 203 as its missing-variable result. The collector correctly preserved the raw code instead of making that inference.

- [GetFirmwareEnvironmentVariableExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexw)
- [System Error Codes 0–499](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)
- [AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)

## Independent verdict A — Windows1W

- `windows1w_gate=PASS_WITH_LIMITATION`
- `native_read_evidence=PASS`
- `sequential_stability=true`
- `payload_parser_compatibility=PASS`
- `boot_next_observation=error_203_unavailable`
- `boot_next_absence_collector_inference=false`
- `uefi_type=attested_by_reviewed_control_flow`
- `privilege_enable_restore=attested_by_reviewed_control_flow`
- `windows_production_implementation=NOT_STARTED`
- `windows_production_windows1w_gate=RELEASED_WITH_RECORDED_LIMITATIONS`

This verdict validates the native read/API research gate only. It does not validate a Windows production adapter, helper, UAC integration, switch path, or firmware write path.

## Independent verdict B — Linux Stage 5

- Known pre-switch `BootOrder`: `[0000,0003]`.
- Both post-boot observations: `[0000,0003]`; permanent order preservation is supported.
- User-confirmed arrival: Windows 11.
- `BootCurrent=0000` on both passes does not corroborate direct selection of intended target `Boot0003`; an intermediary chain is possible but is not established by this evidence.
- BootNext error 203 is consistent with consumption/absence but lacks an API-specific documented guarantee.
- `linux_stage5=NOT_CLOSED_PENDING`

Stage 5 must not be called PASS and no Stage 5 completed tag may be created. Further firmware observation requires a new explicit authorization; this run cannot be retried.

