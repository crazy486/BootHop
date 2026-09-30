# Task 5F — CI capability assertion report

## Change

Updated the two stale fake-test expected reasons in `packaging/windows/tests/package_fake.ps1` from `SetFirmwareEnvironmentVariable` to `SetFirmwareEnvironmentVariableEx`.

The GUI fixture `forbidden-capabilities.rs` contains `SetFirmwareEnvironmentVariableExW`; the misplaced platform fixture `allowed-platform-firmware.rs` contains `GetFirmwareEnvironmentVariableExW` and `SetFirmwareEnvironmentVariableExW`. Neither has a base `SetFirmwareEnvironmentVariable` token. The checker registers Ex as a distinct capability and the audit reports the full Ex capability. No checker, allowlist, production code, or fixture behavior was changed.

## Validation

- `git diff --check` — passed.
- `package_fake.ps1` — not run: neither `pwsh` nor `powershell` is installed locally. The real script still requires Windows CI.

## Scope

Only the two expected reason strings and this report were changed. No EFI/NVRAM or other hardware-facing operations were performed.
