# Task 7 implementation report

Status: DONE. Base: 5d6e5b6. Worktree: `/home/mani/Projects/BootHop/.worktrees/boothop-sdd`.
Implementation and verification only; real firmware/logind acceptance remains separately authorized work.

## Implemented

- `LinuxPlatform` borrows the already protected/locked store and implements exactly the seven existing Platform methods. The helper retains the store/operation guard through the callback and reporting. The production constructor is lazy, fixed-resource, and is never constructed by tests.
- Descriptor-relative traversal of `/` → `sys` → `firmware` → `efi` → `efivars`; NOFOLLOW/CLOEXEC/DIRECTORY, directory validation, efivarfs magic `0xde5e81e4`, writable mount requirement, regular-file validation, size/device/inode/mtime/ctime snapshots. Native metadata uses fstat, fstatfs and fstatvfs; raw syscall errors keep fixed operation labels.
- Strict global GUID `8be4df61-93ca-11d2-aa0d-00e098032b8c` and `Boot[0-9A-F]{4}` discovery, including orphan options. Other case/name/GUID patterns are ignored. All BootOrder/BootCurrent/actual BootNext values validate attributes and exact shapes. Missing BootOrder/Current fails; missing referenced entries fails; enumerated entry disappearance fails. Empty BootOrder remains valid without selecting a target.
- Prefix separated before parsing: Boot#### and BootOrder attributes 7, BootCurrent attributes 6 with total length 6, BootNext attributes 7 with total length 6. Only the optional BootNext leaf's opening ENOENT is None. The reader validates EOF/final size, detects descriptor changes, reopens the leaf to detect observed replacement, and checks directory metadata across the inventory. These checks do not claim a firmware snapshot or CAS.
- Per-variable temporary raw cap 1 MiB+4 and cumulative inventory raw cap 1 MiB including prefixes and controls, with checked accounting and no partial inventory. BootOrder has at most 65536 elements; duplicate diagnostics appear once per ID. Fallible vector reservation maps allocation/capacity failure to ResourceLimit. Read loops and native enumeration check a 30-second deadline; EINTR is returned immediately, with no read retry loop.
- BootNext uses exclusive creation with fresh offset zero and one six-byte write request `[7,0,0,0,id_lo,id_hi]`. No TRUNC, APPEND, replay, deletion, cleanup, mount repair or immutable changes. Short/zero/oversized returns and errno failures stop, preserve error context, and allow existing flow to report possible residual state. EEXIST preserves the competing variable. Full write alone creates no verified stage; core independently reads back.
- Environment checks precede firmware flow: root helper identity, systemd >=255, polkit Authority daemon >=124, exact logind interface and one `RebootWithFlags` method with one input `t` and no outputs. Standard D-Bus DOCTYPE is accepted with no external entity resolver; input is limited to 1 MiB and parsed nodes to 65536. BackendVersion is explicitly a daemon version check, **not GUI authentication-agent detection**. Agent/pkexec outcome handling remains Task9.
- Production zbus transport uses the fixed system bus socket `/run/dbus/system_bus_socket`, ignoring environment-selected bus addresses. Fixed destination/path/interface/method are `org.freedesktop.login1`, `/org/freedesktop/login1`, `org.freedesktop.login1.Manager`, `RebootWithFlags`, with uint64 1 only. Blocking method timeout is 30 seconds. Successful empty method reply is Accepted; explicit method denial is Rejected; transport loss, malformed/non-reply messages, NoReply/Timeout/Disconnected are Unknown. PrepareForShutdown cannot stand in for a reply. No fallback reboot mechanism exists.

## Controller ruling: diagnostics model

Controller approved changing only `Platform::read_options`'s return payload to `OptionInventory { entries, diagnostics }`, keeping seven methods. The only new diagnostic is `EnumerationDiagnostic::DuplicateBootOrder(BootId)`. Successful Report and existing structured FlowFailure carry the diagnostics. No public reference-state model or Task9 serialization was added. Core/helper fake implementations were minimally adapted. The diagnostic propagation test covers Inspect, Configure, Switch and structured conflict failure.

## TDD evidence

All commands below used this installed toolchain prefix:

```text
env CARGO_HOME=/home/mani/Projects/BootHop/.worktrees/boothop-sdd/.superpowers/sdd/2026-09-08-boothop/tools/cargo RUSTUP_HOME=/home/mani/Projects/BootHop/.worktrees/boothop-sdd/.superpowers/sdd/2026-09-08-boothop/tools/rustup PATH=/home/mani/Projects/BootHop/.worktrees/boothop-sdd/.superpowers/sdd/2026-09-08-boothop/tools/cargo/bin:$PATH
```

| Increment / command | Actual RED (exit 101) | Actual GREEN (exit 0) |
|---|---|---|
| `cargo test -p boothop-platform --test linux_adapter` initial scaffold | 0 passed / 1 failed: UnsupportedFormat instead of Some(BootId(3)) | 1 / 0 |
| Same command, lengths/errno/metadata/short reads | 1 / 4: empty bytes accepted as ID0; ENOENT not None; metadata ignored; one-byte chunk decoded as ID0 | 5 / 0 |
| `cargo test -p boothop-core --test flow inventory_diagnostics` | 0 / 1: diagnostics `[]` instead of `[DuplicateBootOrder(BootId(7))]` | 1 / 0 |
| Linux adapter enumeration | 6 / 4: strict/orphan and duplicate discovery, missing-control error and aggregate-boundary success all returned scaffold UnsupportedFormat | 10 / 0 |
| Linux adapter single write | 10 / 2: UnsupportedFormat instead of complete write success or short-write IO5 | 12 / 0 |
| Linux adapter environment/reboot | 12 / 2: supported environment still UnsupportedFormat | 14 / 0 |
| `cargo test -p boothop-platform --lib linux::firmware` | 0 / 2: native open/metadata scaffolds returned ENOSYS38 on isolated ordinary temp descriptors | 2 / 0 |
| `cargo test -p boothop-platform --lib linux::reboot` | 0 / 2: DisconnectedAfterSend instead of explicit Success/ExplicitDenial | 2 / 0 |
| `cargo test -p boothop-platform --lib native_enumeration` | 0 / 1: ENOSYS38 instead of strict names from isolated temp directory | 1 / 0 |
| `cargo test -p boothop-platform --lib native_probe` | 0 / 1: UnsupportedFormat instead of fixed-query probe result | 1 / 0 |
| Linux adapter observed replacement | 15 / 1: stale descriptor returned Some(BootId7) instead of read IO5 | 16 / 0 |
| Linux adapter BootOrder count limit | 18 / 1: 65537 IDs returned inventory instead of ResourceLimit | 19 / 0 |
| `cargo test -p boothop-platform --test linux_adapter introspection_` | 0 / 2: standard DOCTYPE rejected; 65536 extra XML nodes accepted | 2 / 0 |

The initial plain `cargo` invocation failed because cargo was not on PATH (exit127); it was not counted as RED. Inventory skeleton initially needed its public exports and an existing exhaustive test pattern updated before the genuine assertion RED. The native metadata compile needed rustix's actual `StatVfsMountFlags` name before GREEN. None of these compile/setup failures is claimed as behavioral evidence.

Additional end-to-end regression tests exercised behavior already developed in the preceding increments: write/readback ordering, same-next skip, competing next, exclusive-create race, short/error writes retaining state and blocking reboot, readback mismatch, Accepted/Unknown/Rejected stage and residual evidence. Pure capacity-overflow testing covers the extracted fallible-reservation mapping without exhausting memory. Native production connection/syscall wiring is compile-checked; only its pure or isolated-descriptor boundaries are executed. No claim of a real firmware/logind TDD experiment is made.

## Platform matrix exercised

| Area | Synthetic/native-isolated evidence |
|---|---|
| Errno | open/read/metadata/list failure cases: ENOENT2, EACCES13, EPERM1, EROFS30, ELOOP40, ENOTDIR20, EISDIR21, EIO5, ENODEV19, EINVAL22, ENOSPC28, EDQUOT122, ENOMEM12, EINTR4, ETIMEDOUT110; write matrix additionally verifies short/zero/oversized returns and no replay |
| Data lengths | BootNext empty/3/4/5/6/7/8, attributes6 rejection, little-endian `0x1234`, one-byte short reads; BootCurrent attrs6 and exact6; odd/empty/wrong-attrs BootOrder; wrong Boot#### attrs |
| Resources/races | Exactly 1 MiB raw inventory accepted, one byte over rejected; per-file oversize rejected; allocation capacity failure; excessive BootOrder/XML nodes; same-size stamp changes; replaced leaf; directory enumeration changes; disappearing option; missing references; no leaked fake handles |
| Discovery | Uppercase strict Boot IDs, non-global GUID/long/lowercase names ignored, orphan included, controls validated, duplicate diagnostic, empty order without automatic configuration |
| Firmware mutation | Literal six-byte buffer, fixed BootNext leaf, offset0, one call, EEXIST unchanged, partial retained state, no reboot on write/readback failures, no restoration after rejection/unknown |
| Environment | systemd255/257/261 accepted with valid method; 254/missing/malformed/overflow versions rejected; polkit123/non-root rejected; missing/wrong-interface/wrong-signature/wrong-direction/extra-argument methods rejected; probe failure prevents firmware flow |
| Logind | Flags1 in every fake scenario; explicit root block/block-weak and multi-session denial, delay then success, delay timeout, disconnect, signal without reply; native pure zbus message confirms `t` body and fixed endpoint; no fallback |
| Existing integration | Core38 flow tests, helper5 operation-lock tests, platform27 store tests remain passing; no store implementation changes |

Fake inhibitor/session labels test adapter handling of the contract's responses; they do not simulate systemd internals or establish actual root/inhibitor behavior.

## Dependency verification

- Official [zbus 5.19.0 package documentation](https://docs.rs/crate/zbus/5.19.0) and [upstream blocking/runtime FAQ](https://z-galaxy.github.io/zbus/faq.html) checked. Exact `=5.19.0` pin, default features disabled, only `blocking-api` and `async-io` explicitly enabled. Cargo resolved zbus and zbus_macros 5.19.0; source inspection verified blocking Builder::method_timeout and call_method result semantics. No Tokio/service architecture was introduced; async-io is the runtime required internally by zbus's blocking wrapper.
- [Upstream Builder timeout documentation](https://docs.rs/zbus/5.19.0/zbus/blocking/connection/struct.Builder.html) and downloaded official 5.19.0 source establish timeout-as-IO-error behavior. Native reply classification preserves uncertainty on NoReply/transport loss.
- Existing rustix remains `=1.1.4`, features fs plus process for geteuid. XML parser `roxmltree =0.21.1` uses only std (positions disabled); its source documents DTD behavior, bounded nodes and absent external resolver.
- [Official polkit Authority D-Bus documentation](https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html) verifies BackendVersion and fixed object/service. [Official systemd v255 manager interface](https://raw.githubusercontent.com/systemd/systemd/v255/man/org.freedesktop.systemd1.xml) verifies Version. These were source/documentation reads, not service calls.

## Final verification

Final commands after the DOCTYPE/node-limit fix:

| Command | Result |
|---|---|
| `cargo test --workspace --locked --quiet` | exit0: **176 passed, 0 failed**; core112, helper5, platform11 unit +21 Linux adapter +27 store; doc tests pass |
| `cargo fmt --all -- --check` | exit0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit0, no warnings |
| `git diff --check` | exit0 |

Earlier full-workspace run passed173 before final regression additions. The first clippy run identified only constant chunks_exact usage; replacing it with as_chunks eliminated the warning. Final evidence above supersedes intermediate counts.

## Safety, self-review, and remaining limits

- No test or command constructed `LinuxPlatform::system` or `SystemLinuxCalls`, opened real `/sys/firmware/efi/efivars`, connected to any D-Bus bus/logind/polkit, wrote real variables, requested reboot, elevated privileges, or read private samples/Windows data. Fixed paths occur only as production source constants and are not exercised by tests.
- Native resources exercised were exclusively ordinary files/directories created under a process-specific `boothop-firmware-unit-*` temp directory. Native open/metadata/directory helpers used those owned descriptors. The only native test write used the ordinary temp leaf `synthetic`. Cleanup removed only those test-created temporary trees. Existing Task6L tests likewise use their isolated temporary resources.
- Self-review caught and fixed observed leaf/directory replacement gaps, the BootOrder element cap, and standard D-Bus DOCTYPE compatibility; each behavioral fix has actual RED/GREEN above. Duplicate diagnostics are carried by successful reports and existing structured failures. No BootOrder-write/delete or reboot fallback API exists.
- Deadlines are checked between filesystem operations and supplied to zbus method calls; they do not promise interruption of a kernel firmware call. zbus connection establishment/handshake itself is not claimed to be interruptible by the method-call timeout. Task9 owns outer helper/IPC authorization/connection waiting and GUI outcomes.
- Filesystem rechecks and exclusive creation do not eliminate external ABA or prove firmware obeys BootNext. Real Ubuntu255/Arch261 inhibitor/delay/multi-session behavior, installation, actual firmware writes/reboots and final cross-platform acceptance remain unperformed as required. This implementation's DONE status is limited to Task7 code/fake verification.

## Exact files changed

`Cargo.lock`; `crates/platform/Cargo.toml`; `crates/platform/src/lib.rs`; new `crates/platform/src/linux.rs`, `linux/firmware.rs`, `linux/reboot.rs`, `crates/platform/tests/linux_adapter.rs`; `crates/core/src/{model,error,flow,lib}.rs`; `crates/core/tests/{flow.rs,support/mod.rs}`; `crates/helper/src/lock.rs` (test adapter signature only); this report. Task6L store implementation and unrelated files are unchanged.
