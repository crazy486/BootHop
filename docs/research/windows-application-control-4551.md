# Windows Application Control error 4551 investigation

Date: 2026-09-14

Scope: read-only policy/event inspection and disposable local Rust/Cargo probes. No Windows security policy, Defender setting, registry value, trust root, certificate, firmware API, BootHop helper, or production source was changed.

## Summary

The failure is not a BootHop code defect. Windows Code Integrity event 3077 attributes the block to the inbox `VerifiedAndReputableDesktop` policy (`{0283ac0f-fff1-49ae-ada1-8a933130cad6}`), and `Get-MpComputerStatus` reports Smart App Control `On`. Microsoft documents that policy GUID as the Smart App Control enforcement policy.

The narrow reproducible condition is a default-parallel, fully fresh BootHop workspace build producing a new unsigned `icu_normalizer_data` build-script hash. Two independent fresh target directories failed at that executable with Win32 error 4551. A third fully fresh target built and ran the complete workspace successfully with Cargo serialized via `-j1`.

This is therefore classified as a machine-specific Windows Smart App Control compatibility limitation affecting some newly generated Cargo artifacts during the default-parallel workspace build. The external Code Integrity decision is confirmed; the internal reputation/appraisal reason why the blocked hashes were rejected while other new unsigned hashes were allowed is not exposed by the available event data, so a more specific claim would be unsupported.

## Exact reproduction

From the `codex/windows-workspace-baseline` worktree with Rust `1.98.1-x86_64-pc-windows-msvc`:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:LOCALAPPDATA 'Temp\boothop-cargo-4551-<run-id>'
cargo +1.98.1 test --workspace --locked
```

The default-parallel command was run with two separate new target directories. Both stopped before executing the first rejected build script:

```text
error: failed to run custom build command for `icu_normalizer_data v2.3.0`
could not execute process ...\debug\build\icu_normalizer_data-c90282c6b1808d56\build-script-build (never executed)
应用程序控制策略已阻止此文件。 (os error 4551)
```

The two blocked PE files had different paths and SHA-256 values, demonstrating that each target build produced a distinct artifact:

| Result | Artifact | SHA-256 |
|---|---|---|
| blocked | fresh target 1 `icu_normalizer_data-...\build-script-build.exe` | `1AA98FADA7BA2DC430956F826A1EFA637D8EB84C1A2BCCC9594827DD32CFC099` |
| blocked | fresh target 2 `icu_normalizer_data-...\build-script-build.exe` | `C7170208C20D3BAF44D7CCC31A3F1B5C6C1A9C768770AB497149FD82AD921DC6` |

Re-running the first target and directly starting its rejected executable continued to return native error 4551. `net helpmsg 4551` returned `An Application Control policy has blocked this file.`

## Enforcement evidence

The matching `Microsoft-Windows-CodeIntegrity/Operational` records were:

- Event 3033: `cargo.exe` attempted to load the generated build-script executable, which did not meet the Enterprise signing level.
- Event 3089 with the same correlation ID: zero signatures, signature type 0, validated signing level 0, publisher `Unknown`.
- Event 3077: enforced block, status `0xc0e90002`, policy name `VerifiedAndReputableDesktop`, policy GUID `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`.

Direct execution produced the same 3033/3077 pair with `pwsh.exe` as parent. The AppLocker EXE/DLL, MSI/Script, and packaged-app logs had no matching event. This identifies Code Integrity/Smart App Control, not AppLocker, as the enforcing subsystem.

The machine reported Windows 11 Pro, build 26200, and Smart App Control `On`. `CiTool.exe -lp -json` was attempted read-only but returned access denied without elevation; elevation was not requested because it is outside this investigation boundary. The event record and Microsoft inbox-policy mapping are sufficient to identify the enforced policy.

Microsoft references:

- [Smart App Control overview](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview)
- [Inbox App Control policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/inbox-appcontrol-policies)
- [SmartScreen reputation for Windows app developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)

## Working-versus-blocked comparison

The closest trusted-cache control was the same crate and Cargo suffix from the previously usable target cache:

| Property | Trusted-cache artifact | Fresh blocked artifact |
|---|---|---|
| crate/file | `icu_normalizer_data-c90282c6b1808d56\build-script-build.exe` | same |
| length | 138240 bytes | 138240 bytes |
| SHA-256 | `BDBC3FD954C5BAB9AA4235B9F879FDE78D0512884C0222CA5553E5F7CC6F4545` | `1AA98FADA7BA2DC430956F826A1EFA637D8EB84C1A2BCCC9594827DD32CFC099` |
| Authenticode | `NotSigned` | `NotSigned` |
| Zone.Identifier | absent | absent |
| owner | current user | current user |
| effective user access | executable | executable |
| direct execution | exit 0 | native error 4551 |

Copying the trusted artifact into the same fresh temporary directory preserved its SHA-256 and it still exited 0. This rules out the original cache path and its inherited ACL as the deciding condition. It also confirms that “trusted cache” does not mean Authenticode-signed.

All compared artifacts were generated by the same Rust 1.98.1 MSVC toolchain. Cargo verbose output showed `rustc.exe` compiling the registry crate's `build.rs` as a PE executable and `cargo.exe` attempting to start it. Absolute target/output paths differ and the resulting hashes differ; the policy decision tracks the resulting code identity/reputation rather than the Cargo directory name alone.

## Disposable probes

All probes lived under a uniquely named local temporary directory and were not added to BootHop or committed.

1. A no-dependency ordinary Rust executable was built in a fresh target. It was `NotSigned`, had no Zone.Identifier, and executed successfully.
2. A no-dependency crate with a local `build.rs` was built in a fresh target. Cargo compiled and executed the unsigned build script successfully.
3. A repo-independent crate depending only on `icu_normalizer_data = "=2.3.0"` was built offline in a fresh target. Its newly generated unsigned ICU build script executed successfully.
4. BootHop was built again in a fresh target with only one variable changed:

   ```powershell
   $env:CARGO_TARGET_DIR = Join-Path $env:LOCALAPPDATA 'Temp\boothop-cargo-4551-serial-<run-id>'
   cargo +1.98.1 test --workspace --locked -j1
   ```

   The complete workspace compiled and all Windows-applicable tests and doc-tests passed. The serial ICU build script was also unsigned, had no Zone.Identifier, and had SHA-256 `008EAB19F4C8831ADE0B5798F5749C3033C8774B9EE2A1BCA471F2A264C224D2`. No matching Code Integrity block event was recorded for the serial target.

These controls falsify the broader hypotheses that BootHop emits a special executable, that all new Rust executables are blocked, that all Cargo build scripts are blocked, or that `icu_normalizer_data` is categorically blocked. The remaining evidence supports a Smart App Control reputation/appraisal interaction exposed by the default-parallel workspace build on this machine. Serialization is a diagnostic result, not a proposed policy bypass or repository change.

## Decision

- Classification: **machine-specific environment** — Rust/Cargo default-parallel workspace builds can expose Smart App Control rejection of particular new unsigned artifact hashes on this machine.
- BootHop code change required: **no**.
- Windows security policy change required: **no**, and none is recommended.
- Default-parallel fresh-target verdict: **BLOCKED (reproduced twice)**.
- Serialized fresh-target verdict: **PASS**.
- Existing trusted-cache verification: must continue to be reported separately from fresh-target verification.
- Integration impact: this is a documented local environment limitation, not permanent evidence against integrating the branch once repository CI and the normal software verification gates are green.
