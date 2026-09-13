# Windows1W Read-Only Research Collector Design

Date: 2026-09-14

## Scope and status

This document specifies software preparation only. The collector is an independent research and acceptance tool for a later, separately authorized Windows1W real-system session. It is not the BootHop Windows adapter, helper, GUI, or production implementation. Building, testing, and auditing it does not complete Windows1W or Linux Stage 5.

This phase must not execute `GetFirmwareType`, manipulate a real process token for `SeSystemEnvironmentPrivilege`, call `GetFirmwareEnvironmentVariableExW`, request UAC, start a BootHop helper, modify BCD or firmware, launch a child process, or request shutdown/reboot.

## Architecture

The collector is a standalone workspace package under `tools/windows1w-collector`. Its library contains an orchestration state machine parameterized by a narrow `WindowsCalls` boundary. Unit and integration tests use a deterministic fake only. A Windows-only backend is compiled into the binary but is never constructed or executed by tests. No production BootHop crate depends on the collector.

The boundary accepts only a closed `VariableName` enum: `BootOrder`, `BootCurrent`, `BootNext`, and `Boot(BootId)`. The global GUID and `SeSystemEnvironmentPrivilege` are private constants in the Windows backend. There is no arbitrary GUID, variable-name, output-root, dynamic-library, or command-execution input.

## Allowed native surface

The native backend may directly import only these security/firmware functions plus ordinary Rust runtime and local filesystem support:

- `GetFirmwareType`
- `GetFirmwareEnvironmentVariableExW`
- `OpenProcessToken`
- `LookupPrivilegeValueW`
- `AdjustTokenPrivileges`
- `SetLastError` (to establish a known success baseline before each native attempt)
- `GetLastError`
- `CloseHandle`

The backend does not import or call dynamic-loading or process-launch APIs.
The release PE may contain ordinary Rust/MSVC runtime imports (including
startup, filesystem, allocator, exception, or CRT support symbols); those are
audited and are not collector capabilities.

It must not declare, import, dynamically resolve, or call any `SetFirmwareEnvironmentVariable*`, BCD mutation, shutdown/restart, process-launch, shell, `LoadLibrary`, or `GetProcAddress` API.

## Fixed collection algorithm

The future real entry point verifies the UEFI firmware type, opens its own process token, resolves and enables only `SeSystemEnvironmentPrivilege`, and treats API failure, an unknown/non-UEFI firmware type, or `ERROR_NOT_ALL_ASSIGNED` as fatal before any firmware-variable read. The backend uses the documented current-process pseudo-handle value rather than importing `GetCurrentProcess`. It validates every native handle/result, closes the token handle exactly once, and retains the exact previous privilege state for explicit restoration.

It reads `BootOrder`, `BootCurrent`, and `BootNext` through `GetFirmwareEnvironmentVariableExW`. Every successful read validates the exact shared prerequisite variable attributes: `7` for `BootOrder`, `BootNext`, and `Boot####`; `6` for `BootCurrent`. Any other value, including unknown authentication/additional bits, is recorded and rejected. It then deduplicates the `BootId` union referenced by successful, structurally and attribute-valid control reads and reads only those `Boot%04X` variables. It never scans `Boot0000..BootFFFF`. A missing or failed `BootNext` does not expand discovery. Two matching explicit missing observations may establish `boot_next_absent`; a generic error remains unavailable and is never interpreted as absence. Missing, unreadable, or attribute-invalid referenced options are recorded and make the collection non-accepting; nothing is repaired.

Control variables are read a second time. Equality means only that the sequential observations were stable; the collector never calls them an atomic snapshot. Any difference is recorded as unstable.

The collector restores the original privilege state before normal exit. A restore failure records a diagnostic, causes failure, performs no further firmware reads, launches no child process, and exits. Tests assert the call log ends at the failed restore.

## Read and evidence contract

Each native attempt records semantic variable name, success/failure, returned byte count, the immediately observed last-error value, returned UEFI attributes, payload SHA-256, and a bounded non-sensitive summary. Failures retain raw Win32 error values and are not automatically equated with absence, especially for `BootNext` before Windows1W evidence exists.

The maximum payload is 1 MiB per variable and the retained `BootOrder`/`BootCurrent`/`Boot####` enumeration evidence has a separate aggregate 1 MiB budget; `BootNext` is outside that aggregate. Buffer growth is bounded and only follows an explicit buffer-too-small outcome; exceeding either cap fails closed without truncated success. `BootOrder` must be an even-length little-endian `UINT16` array. `BootCurrent` and a successful `BootNext` must each be exactly one little-endian `UINT16`. `Boot####` raw bytes remain separate from the parsed `EFI_LOAD_OPTION` summary and are parsed with `boothop-core`.

Evidence is written only below `.superpowers/sdd/2026-09-08-boothop/private/windows1w/<run-id>/`. Run IDs are locally validated safe path components. Raw payloads and detailed local analysis remain ignored/private. Tracked reports may contain only non-sensitive lengths, attributes, Boot IDs, digests, error semantics, and acceptance conclusions.

## Execution interlock

The binary requires exactly two arguments, in order: `--acknowledge=WINDOWS1W_NATIVE_READ_ONLY_AUTHORIZED` and `--run-id=<id>`. The ID is 1-64 ASCII characters, starts with an ASCII alphanumeric, continues only with ASCII alphanumeric, `.`, `_`, or `-`, is neither `.` nor `..`, does not end in `.`, and is not a case-insensitive Windows reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, or `LPT1`-`LPT9`, with or without a suffix after a dot). Separators, drive/UNC prefixes, absolute paths, empty values, extra arguments, and reordered arguments are rejected.

The fixed evidence directory is checked component-by-component with no-follow
metadata, rejects symlinks/reparse points, is canonicalized, and is verified
to remain under the fixed root. Reports use exclusive create and a fixed size
limit. These checks leave the documented residual TOCTOU window between
metadata validation and subsequent filesystem operations. Invalid arguments,
path setup, collection, or report writes return a nonzero process exit code;
only accepted evidence returns success.

Argument parsing is a pure library function. Tests call it directly; they never use `Command`, spawn the binary, invoke `main`, or construct the native backend. This is defense in depth, not authorization: this phase still must not execute the binary. The program never requests elevation and never spawns a process; a future authorized operator must arrange elevation externally.

## Verification

TDD fake coverage must include firmware-type API failure/non-UEFI short-circuiting; privilege failure/success/original-state/restore behavior; raw read/error preservation; every per-attempt semantic name, byte count, immediate last error, attributes, SHA-256, and bounded summary field; exact variable-attribute acceptance (`7` for `BootOrder`/`BootNext`/`Boot####`, `6` for `BootCurrent`) and rejection of all other values; bounded resizing and size rejection; strict control parsing; failed/missing BootNext without absence inference or discovery expansion; malformed BootOrder fail-closed behavior; referenced-only discovery; deduplication; sequential stability; evidence path restrictions; handle closure; and a safety call log proving zero firmware writes, BCD calls, reboot calls, and child launches.

The acceptance artifact targets Windows 11 x86-64 with `x86_64-pc-windows-msvc`; the underlying read API minimum is Windows 8 desktop. Its tracked report must state that Windows1W remains blocked, Linux Stage 5 remains pending, and Windows production implementation has not begun.

The final release artifact is hashed and audited with `dumpbin /imports`. Source and dependency trees are searched for prohibited symbols. Independent spec, quality, and security reviewers must close all Critical and Important findings before any real-session authorization request.
