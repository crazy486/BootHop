# Windows1W collector preparation

Date: 2026-09-14

This package is a read-only research collector preparation artifact. It is
not the BootHop Windows adapter, helper, GUI, installer, or production
implementation. Windows1W remains **BLOCKED**, Linux Stage 5 remains
**pending**, and the Windows production implementation has **not begun**.

## Native boundary

The release executable targets `x86_64-pc-windows-msvc` and uses a closed
`VariableName` enum. Its Windows-only backend directly imports only the
allowlisted firmware/security calls: `GetFirmwareType`,
`GetFirmwareEnvironmentVariableExW`, `OpenProcessToken`,
`LookupPrivilegeValueW`, `AdjustTokenPrivileges`, `GetLastError`, and
`SetLastError`, `CloseHandle`. It uses the documented current-process pseudo-handle, the
fixed UEFI global GUID, and the fixed `SeSystemEnvironmentPrivilege` name.

`SetLastError(ERROR_SUCCESS)` is established immediately before each
privilege adjustment and firmware read, and the resulting error value is
captured immediately afterward. The braced GUID passed to the firmware API is
`{8be4df61-93ca-11d2-aa0d-00e098032b8c}`.

The backend never requests UAC, starts a child process, dynamically resolves
APIs, mutates firmware/BCD, or requests shutdown/reboot. Tests exercise only
the pure parser and Task 1 fake boundary; they do not invoke `main`, spawn
the executable, or construct the native backend.

## Entry-point interlock and evidence

The executable accepts exactly these ordered arguments:

```text
--acknowledge=WINDOWS1W_NATIVE_READ_ONLY_AUTHORIZED
--run-id=<validated-id>
```

Run IDs are bounded ASCII path components and reject traversal, absolute or
drive/UNC syntax, trailing dots, separators, and Windows reserved device
names. Evidence setup rejects pre-existing symlink/reparse components,
canonicalizes the directory, and verifies fixed-root containment. Reports are
created exclusively and have a fixed size limit. A residual TOCTOU window
between metadata checks and later filesystem operations remains documented.
Evidence is written only below the fixed private root
`.superpowers/sdd/2026-09-08-boothop/private/windows1w/<run-id>/`.

The collector performs bounded reads (maximum 1 MiB), preserves native error
codes and returned attributes, retains raw option payloads separately from
`boothop-core` parsing, and restores the exact prior privilege attributes
before normal exit. The native backend preserves every non-buffer firmware
failure (including error 203) as `ReadStatus::Error`; it never infers
BootNext absence. Explicit `ReadStatus::Missing` and two-matching absence
proof are fake-only semantic coverage pending Windows1W evidence.

The private report records every attempt, both sequential (not atomic)
control snapshots, and bounded Boot#### payload length/digest entries. Raw
Boot#### payloads are written to exclusive `Boot%04X.bin` files below the
private root, separate from parsed summaries. The entry point returns failure for invalid setup,
collection, or report writes, and success only for accepted evidence. This
artifact provides preparation and static evidence,
not Windows firmware behavior evidence; no real-session authorization is
requested by this document.

The final PE import audit distinguishes backend imports from runtime support.
The backend imports observed were `kernel32.dll`:
`GetFirmwareEnvironmentVariableExW`, `SetLastError`, `GetLastError`,
`CloseHandle`, `GetFirmwareType`; and `advapi32.dll`:
`OpenProcessToken`, `AdjustTokenPrivileges`, `LookupPrivilegeValueW`.
Runtime/support imports observed in the same PE included `kernel32.dll`
`GetProcAddress`/`LoadLibraryA` and filesystem/startup/exception symbols,
`api-ms-win-core-synch-l1-2-0.dll` wait/address symbols,
`bcryptprimitives.dll` `ProcessPrng`, `ntdll.dll` file/status symbols,
`VCRUNTIME140.dll` CRT exception/memory symbols, and the
`api-ms-win-crt-*` startup/heap/math/locale/stdio symbols. These runtime
imports are an explicitly audited PE exception; application/backend source
does not declare, import, dynamically resolve, or call dynamic-loading or
process-launch APIs.
