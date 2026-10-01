# Task 5G — Windows PE audit diagnostics report

Updated `packaging/windows/check-capabilities.ps1` so forbidden GUI and helper PE imports are collected using the existing capability regexes and reported as `DLL!symbol` values. Both errors retain their existing generic prefixes (`GUI PE imports a forbidden capability` and `helper PE imports a forbidden capability`) for compatibility with `Assert-Fails` checks.

No regex, allowlist, capability policy, source audit, fixture, or production path was changed.

## Verification

- `git diff --check` passed.
- PowerShell is unavailable on this machine (`pwsh` and `powershell` are not installed); no tools were installed. Windows CI must run the fake packaging audit with real release PEs to observe the matched symbol.
