# Windows1W Read-Only Research Collector Design

Date: 2026-09-14

## Scope and status

This document specifies software preparation only. The collector is an independent research and acceptance tool for a later, separately authorized Windows1W real-system session. It is not the BootHop Windows adapter, helper, GUI, or production implementation. Building, testing, and auditing it does not complete Windows1W or Linux Stage 5.

This phase must not execute `GetFirmwareType`, manipulate a real process token for `SeSystemEnvironmentPrivilege`, call `GetFirmwareEnvironmentVariableExW`, request UAC, start a BootHop helper, modify BCD or firmware, launch a child process, or request shutdown/reboot.

## Architecture

The collector is a standalone workspace package under `tools/windows1w-collector`. Its library contains an orchestration state machine parameterized by a sealed `WindowsCalls` boundary. Unit and integration tests use a deterministic fake only. A Windows-only backend is compiled into the binary but is never constructed or executed by tests. No production BootHop crate depends on the collector.

The boundary accepts only a closed `VariableName` enum: `BootOrder`, `BootCurrent`, `BootNext`, and `Boot(BootId)`. The global GUID and `SeSystemEnvironmentPrivilege` are private constants in the Windows backend. There is no arbitrary GUID, variable-name, output-root, dynamic-library, or command-execution input.

## Allowed native surface

The native backend may directly import only these security/firmware functions plus ordinary Rust runtime and local filesystem support:

- `GetFirmwareType`
- `GetFirmwareEnvironmentVariableExW`
- `OpenProcessToken`
- `LookupPrivilegeValueW`
- `AdjustTokenPrivileges`
- `GetLastError`
- `CloseHandle`

It must not declare, import, dynamically resolve, or call any `SetFirmwareEnvironmentVariable*`, BCD mutation, shutdown/restart, process-launch, shell, `LoadLibrary`, or `GetProcAddress` API.

## Fixed collection algorithm

The future real entry point verifies the UEFI firmware type, opens its own process token, resolves and enables only `SeSystemEnvironmentPrivilege`, and treats API failure or `ERROR_NOT_ALL_ASSIGNED` as fatal. It retains the exact previous privilege state for explicit restoration.

It reads `BootOrder`, `BootCurrent`, and `BootNext` through `GetFirmwareEnvironmentVariableExW`. It then deduplicates the `BootId` union referenced by successful, structurally valid control reads and reads only those `Boot%04X` variables. It never scans `Boot0000..BootFFFF`. A missing or failed `BootNext` does not expand discovery. Missing or unreadable referenced options are recorded and make the collection non-accepting; nothing is repaired.

Control variables are read a second time. Equality means only that the sequential observations were stable; the collector never calls them an atomic snapshot. Any difference is recorded as unstable.

The collector restores the original privilege state before normal exit. A restore failure records a diagnostic, causes failure, performs no further firmware reads, launches no child process, and exits.

## Read and evidence contract

Each native attempt records semantic variable name, success/failure, returned byte count, the immediately observed last-error value, returned UEFI attributes, payload SHA-256, and a bounded non-sensitive summary. Failures retain raw Win32 error values and are not automatically equated with absence, especially for `BootNext` before Windows1W evidence exists.

The maximum payload is 1 MiB per variable. Buffer growth is bounded and only follows an explicit buffer-too-small outcome; exceeding the cap fails closed without truncated success. `BootOrder` must be an even-length little-endian `UINT16` array. `BootCurrent` and a successful `BootNext` must each be exactly one little-endian `UINT16`. `Boot####` raw bytes remain separate from the parsed `EFI_LOAD_OPTION` summary and are parsed with `boothop-core`.

Evidence is written only below `.superpowers/sdd/2026-09-08-boothop/private/windows1w/<run-id>/`. Run IDs are locally validated safe path components. Raw payloads and detailed local analysis remain ignored/private. Tracked reports may contain only non-sensitive lengths, attributes, Boot IDs, digests, error semantics, and acceptance conclusions.

## Execution interlock

The binary requires an exact, explicit read-only authorization acknowledgement and a valid run ID. This is defense in depth, not authorization: this phase still must not execute the binary. The program never requests elevation and never spawns a process; a future authorized operator must arrange elevation externally.

## Verification

TDD fake coverage must include privilege failure/success/restore behavior, raw read/error preservation, bounded resizing and size rejection, strict control parsing, referenced-only discovery, deduplication, sequential stability, evidence path restrictions, and a safety call log proving zero firmware writes, BCD calls, reboot calls, and child launches.

The final release artifact is hashed and audited with `dumpbin /imports`. Source and dependency trees are searched for prohibited symbols. Independent spec, quality, and security reviewers must close all Critical and Important findings before any real-session authorization request.
