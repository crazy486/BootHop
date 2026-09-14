# Windows Application Control error 4551 investigation

Date: 2026-09-14

Scope: read-only policy/event inspection and disposable local Rust/Cargo probes. No Windows security policy, Defender setting, registry value, trust root, certificate, firmware API, BootHop helper, or production source was changed.

## Summary

The evidence does not demonstrate a BootHop code defect. Windows Code Integrity event 3077 attributes the block to the inbox `VerifiedAndReputableDesktop` policy (`{0283ac0f-fff1-49ae-ada1-8a933130cad6}`), and `Get-MpComputerStatus` reports Smart App Control `On`. Microsoft documents that policy GUID as the Smart App Control enforcement policy.

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

The closest trusted-cache control was the same crate and Cargo suffix from the previously usable target cache. Paths and identities below are sanitized (`<user>`, `<domain-users>`, `<sandbox-users>`, and `<extra-SID>`):

| Property | Trusted-cache artifact | Fresh blocked artifact |
|---|---|---|
| path | `C:\Users\<user>\BootHop\.worktrees\windows1w-collector-prep\target\debug\build\icu_normalizer_data-c90282c6b1808d56\build-script-build.exe` | `C:\Users\<user>\AppData\Local\Temp\boothop-cargo-4551-<timestamp>\debug\build\icu_normalizer_data-c90282c6b1808d56\build-script-build.exe` |
| crate/file | `icu_normalizer_data-c90282c6b1808d56\build-script-build.exe` | same |
| creation provenance | Pre-existing artifact in a previously usable Cargo target cache from the sibling `windows1w-collector-prep` worktree; exact source commit was not recorded | Newly generated by `rustc` 1.98.1 MSVC from locked `icu_normalizer_data v2.3.0` during a BootHop workspace build in a new `CARGO_TARGET_DIR` |
| length | 138240 bytes | 138240 bytes |
| SHA-256 | `BDBC3FD954C5BAB9AA4235B9F879FDE78D0512884C0222CA5553E5F7CC6F4545` | `1AA98FADA7BA2DC430956F826A1EFA637D8EB84C1A2BCCC9594827DD32CFC099` |
| Authenticode | `NotSigned` | `NotSigned` |
| Zone.Identifier | absent | absent |
| owner / effective access | current user / executable | current user / executable |
| raw ACL (sanitized SDDL) | `O:<user>G:<domain-users>D:AI(A;ID;0x1200a9;;;<sandbox-users>)(A;ID;FA;;;SYSTEM)(A;ID;FA;;;Administrators)(A;ID;FA;;;<user>)` | `O:<user>G:<domain-users>D:AI(A;ID;0x1301bf;;;<sandbox-users>)(A;ID;0x1301bf;;;<extra-SID>)(A;ID;FA;;;SYSTEM)(A;ID;FA;;;Administrators)(A;ID;FA;;;<user>)` |
| invocation / parent | direct `pwsh.exe` launch → artifact; exit 0 | workspace Cargo launch `cargo.exe` → artifact (blocked before entry); direct `pwsh.exe` launch → artifact (4551) |
| matching policy-event status | No matching 3033/3077 block event for this exact trusted path during the recorded direct run | Cargo launch: 3033/3089/3077; direct launch: 3033/3077 |

The raw ACLs are not equivalent: the fresh file has an additional inherited modify ACE and `Modify` for `<sandbox-users>`, while the trusted file has only `ReadAndExecute` for that principal. Both have the current user as owner and executable effective access. Copying the trusted artifact into the same fresh temporary directory preserved its SHA-256 and it still exited 0; this controls for the original source path, but does not prove that ACL differences are irrelevant to policy. It also confirms that “trusted cache” does not mean Authenticode-signed.

All compared artifacts were generated by the same Rust 1.98.1 MSVC toolchain. Cargo verbose output showed `rustc.exe` compiling the registry crate's `build.rs` as a PE executable and `cargo.exe` attempting to start it. Absolute target/output paths differ and the resulting hashes differ. The observation is consistent with a hypothesis that policy appraisal considers resulting code identity/reputation rather than the Cargo directory name alone, but the available events do not expose those internal policy inputs and do not prove that hypothesis.

## Disposable probes

All probes lived under a uniquely named local temporary directory and were not added to BootHop or committed.

1. A no-dependency ordinary Rust executable was built in a fresh target. It was `NotSigned`, had no Zone.Identifier, and executed successfully.
2. A no-dependency crate with a local `build.rs` was built in a fresh target. Cargo compiled and executed the unsigned build script successfully.
3. A repo-independent crate depending only on `icu_normalizer_data = "=2.3.0"` was built offline in a fresh target. Its newly generated unsigned ICU build script executed successfully.
4. BootHop was built again in a fresh target with Cargo serialized via `-j1`:

   ```powershell
   $env:CARGO_TARGET_DIR = Join-Path $env:LOCALAPPDATA 'Temp\boothop-cargo-4551-serial-<run-id>'
   cargo +1.98.1 test --workspace --locked -j1
   ```

   The complete workspace compiled and all Windows-applicable tests and doc-tests passed. The serial ICU build script was also unsigned, had no Zone.Identifier, and had SHA-256 `008EAB19F4C8831ADE0B5798F5749C3033C8774B9EE2A1BCA471F2A264C224D2`. Its invocation was `cargo.exe` → build script; no matching Code Integrity block event was recorded for the serial target. Because `-j1` changes Cargo build ordering and therefore the generated artifact hashes, this establishes only the observed default-parallel-blocked versus serial-pass contrast; it does not prove parallelism causality.

These controls falsify the broader hypotheses that BootHop emits a special executable, that all new Rust executables are blocked, that all Cargo build scripts are blocked, or that `icu_normalizer_data` is categorically blocked. The remaining evidence is consistent with, but does not prove, a Smart App Control reputation/appraisal interaction exposed by the default-parallel workspace build on this machine. Serialization is a diagnostic result, not a proposed policy bypass or repository change.

## Decision

- Classification: **machine-specific environment (observed)** — Rust/Cargo default-parallel workspace builds exposed Smart App Control rejection of particular new unsigned artifact hashes on this machine; the internal reason for the differing decisions remains unresolved.
- BootHop code change required: **not indicated by this evidence**.
- Windows security policy change required: **no**, and none is recommended.
- Default-parallel fresh-target verdict: **BLOCKED (reproduced twice)**.
- Serialized fresh-target verdict: **PASS**.
- Existing trusted-cache verification: must continue to be reported separately from fresh-target verification.
- Integration impact: this is a documented local environment limitation, not permanent evidence against integrating the branch once repository CI and the normal software verification gates are green.
