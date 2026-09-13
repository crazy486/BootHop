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
before normal exit. The entry point returns failure for invalid setup,
collection, or report writes, and success only for accepted evidence. This
artifact provides preparation and static evidence,
not Windows firmware behavior evidence; no real-session authorization is
requested by this document.
