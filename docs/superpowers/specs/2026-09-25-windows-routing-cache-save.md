# Windows routing cache save blocker

Date: 2026-09-25

## Symptom

On the production Windows machine, Inspect succeeds for `Boot0000 / Linux / GRUB`; protected-record and live-identity validation report no error. The GUI then reports `展示缓存读写失败；不会自动重复配置。` The failed native cache stage and operating-system error are not currently visible.

## Goal

`Ready Inspect → cache-v1.json safely persisted → next ordinary launch can route to Quick Hop`.

The cache remains an untrusted routing/display hint. Protected records and live identity continue to authorize every operation. No cache field or cache diagnostic may become an authorization input.

## Evidence and current judgment

- The Windows CI cache integration test uses a test-owned temporary directory and exercises the native Windows backend on the Windows runner: create the `BootHop` child, save, load, replace, load again, and check that only the final cache file remains.
- Native Windows cache errors are collapsed to `CacheError::Unavailable`; the UI displays only a generic warning. The production failure therefore has no recorded stage or raw Win32 code, and its primary cause cannot yet be identified.
- A definite secondary defect exists in failure cleanup: the owned temp handle is marked with `FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_ON_CLOSE`, although it was not opened with `FILE_FLAG_DELETE_ON_CLOSE`. Microsoft MS-FSCC specifies `STATUS_NOT_SUPPORTED` for that combination. This can leave an owned temp file after an earlier save failure; it does not establish why the production rename/save first failed.
- The earlier Task 11 root-directory final-path mismatch was fixed and passed Windows CI at `e300fff`; it is not evidence for this later production warning.
- The forced Windows rename-conflict regression on the development machine returned `Rename / raw_code=5` from `SetFileInformationByHandle(FileRenameInfo)`. This proves the new diagnostic path and cleanup behavior for a real destination-sharing conflict, but it is a controlled test result, not the missing raw code from the production Inspect.

## Bounded change

1. Preserve a closed Windows cache stage and optional raw Win32 code in the cache error. Display only the fixed stage name and numeric code in the existing cache warning. Do not include a path, cache bytes, identity, description, SID, or localized OS error text.
2. Correct owned-temp cleanup to set delete disposition without `ON_CLOSE`, then close the owned handle.
3. Add a Windows-native failure regression that holds the existing cache without delete sharing, forces replace to fail, checks `Rename` plus a raw error code, verifies the old cache remains readable, and verifies the owned temp file is removed.
4. Keep the existing temp-root native success round trip as coverage for parent creation, first save, replacement, and reload. The test root represents LocalAppData; tests must never write the real production cache.

## Implementation outcome

- `CacheError` now preserves a closed `WindowsCacheStage` and optional raw Win32 code. The existing GUI warning displays only that fixed stage and number; it excludes paths, cache payloads, IDs, names, and localized error text.
- The stage constructor and Windows-native imports are compiled only for Windows; Linux keeps the existing generic cache-error path without dead code or unused imports.
- `SetFileInformationByHandle(FileDispositionInfoEx)` now sets `FILE_DISPOSITION_FLAG_DELETE` without `FILE_DISPOSITION_FLAG_ON_CLOSE`. Cleanup errors retain their own bounded stage/code rather than replacing all failures with `Unavailable`.
- The native Windows regression holds `cache-v1.json` without delete sharing, invokes the real save path, and checks the rename stage and raw conflict code, preservation/reload of the old cache, and removal of the owned temporary file. The Windows temp-root success test still exercises native create, save, replace, reload, and one-file cleanup.
- Production failure stage/code remains unknown until a diagnostic build is used for a later ordinary Inspect. No Inspect was run during this implementation.

## Boundaries

Do not change ProgramData/protected store, Configure, Switch, firmware, reboot, UAC, or cache authorization semantics. Do not replace the native path with a bare `std::fs::write`. Do not run production Inspect as part of this change.

## Acceptance

- Workspace tests, `cargo fmt --check`, and workspace Clippy pass locally.
- Linux and Windows CI pass for the pushed commit; Windows CI runs the native cache tests.
- Commit and push the change, then stop before real-machine Inspect.
