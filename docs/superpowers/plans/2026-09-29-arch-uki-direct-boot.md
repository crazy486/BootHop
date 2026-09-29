# 专用 Arch UKI 直达路径实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在普通开机仍进入现有 GRUB 菜单的前提下，增加 Windows → BootHop → 固定路径 Arch UKI → Arch 的一次性直达路径。

**Architecture:** Linux provision flow 发现 Arch 配置、构建并发布固定路径 UKI，再以版本化 root-owned ownership journal 管理专用 Boot#### 与 BootOrder 生命周期。复用现有 Inspect/Configure/Switch 完成 Windows 侧目标配置；日常 Switch 保持只写 BootNext。Provision、uninstall、虚拟固件验收、真实机器 provision 与真实 Windows reboot 验收分开实施和授权。

**Tech Stack:** 现有 Rust 2024 workspace、Linux efivarfs adapter、Windows UEFI adapter、mkinitcpio preset、隔离 QEMU/OVMF UEFI 测试。

**Spec:** [2026-09-29-grub-one-shot-arch-design.md](../specs/2026-09-29-grub-one-shot-arch-design.md)

## Global Constraints

- 普通启动保持现有 Boot0000 → GRUB 菜单；不得修改 Boot0000、普通 GRUB 配置或菜单。
- 首次 provision 只能把 BootHop 专用 Boot#### 追加到 BootOrder 末尾，原项目相对顺序和优先级不变；uninstall 只移除 BootHop-owned 项并保留其余顺序。
- 日常 Switch 只写 BootNext；不创建、删除或修改 Boot####，不写 BootOrder、grubenv、GRUB 或 UKI。
- Windows 不写 Linux root filesystem；不引入 daemon/service，不迁移到 systemd-boot，不维护版本化 BootHop kernel 副本。
- 固定 UKI 路径由 Arch 更新流程重建；Secure Boot 保持当前策略，不自动关闭、不创建密钥、不降低验证策略。
- 真实 mkinitcpio preset/UKI/NVRAM 写入与真实 Windows BootNext/reboot 均须分别取得用户明确授权。
- fake tests 不访问宿主 EFI；虚拟 UEFI acceptance 只能写隔离的 OVMF varstore 和测试磁盘。

## Review Focus

- Kernel flavor 或持久 kernel command line 缺失/不明确时必须 fail closed；Phase 2 测试覆盖多 flavor 与仅 `/proc/cmdline` fallback。
- Boot#### allocator 必须识别 BootOrder 外的 orphan ID；Phase 3 测试覆盖占用、竞态和 exclusive-create 失败。
- 任一 EFI/store 写入或 readback 结果未知时保留 journal 并报告 residual；Phase 3/4 测试覆盖每个变异点的部分成功与进程中断。
- 外部 BootOrder 修改和无 CAS 竞态不得触发旧快照回写；Phase 4 测试在读取、写前、写后分别注入变化。
- UKI 构建、签名或发布失败必须保留旧 UKI；Phase 2/7 测试覆盖 staged publish、验证失败和磁盘空间不足。
- Windows 无法把 EFI partition/file path 对应到可读 UKI 时不得继续 Switch；Phase 5 fake tests 与 Phase 6 虚拟验收覆盖未挂载、错分区、缺文件和格式错误。

## File Map

- `crates/core/src/arch_provision.rs`：BootHop Arch ownership record、生命周期状态、持久化 codec 与数据校验。
- `crates/platform/src/linux/arch_provision_store.rs`：Linux root-owned ownership journal；复用现有锁、原子替换和目录同步实现，不复用普通 per-OS `TargetRecord` 语义。
- `crates/platform/src/linux/uki.rs` 与 `packaging/linux/boothop-uki-publish.sh`：只读 Arch/mkinitcpio 配置发现、UKI build plan，以及受限 post-build staging/sign/validate/atomic-publish hook。
- `crates/platform/src/linux/boot_entry.rs`、`crates/platform/src/linux/boot_order.rs`：隔离的 Boot#### 与 BootOrder 生命周期 adapter/use-case；不把写能力放入 `Platform::write_next`。
- `crates/platform/src/windows/uki.rs`：只读地将 UEFI hard-drive/file-path target 映射到 EFI volume 并检查固定 UKI 文件；不得挂载、分配盘符或写文件系统。
- `crates/protocol/src/lib.rs`、`crates/helper/src/dispatch.rs`：封闭的 provision/uninstall operation 与 typed response；固定 Linux-only 操作，不接收 GUI 提交的路径、BootId、load option 或 identity。
- `crates/gui/src/helper_client.rs`、`crates/gui/src/helper_client/linux.rs`、`crates/gui/src/helper_client/windows.rs`、`crates/gui/src/controller.rs`、`crates/gui/src/main.rs`：仅在 Linux setup 中触发明确 provision/uninstall；Windows 日常 Inspect/Configure/Switch 继续走既有流程。
- `packaging/windows/check-capabilities.ps1` 与其 capability fixtures：审计新增 Windows EFI-volume API 仅用于只读打开/读取；禁止 mount-point/drive-letter mutation 和写入接口。
- `tools/uefi-acceptance/` 与 `fixtures/uefi/virtual/`：隔离磁盘、OVMF varstore 和可重复 acceptance harness；不得复用宿主 NVRAM。
- `docs/acceptance/windows-to-uki-arch.md`：记录仅经单独授权执行的真实 provision 和 Windows → UKI → Arch acceptance 证据。

## Task 1 — Phase 1 — Ownership/data model

**Files:** `crates/core/src/arch_provision.rs`、`crates/core/src/lib.rs`、`crates/platform/src/linux/arch_provision_store.rs`、`crates/platform/src/linux/store.rs`、`crates/platform/tests/arch_provision_store.rs`、`crates/core/tests/arch_provision_record.rs`。

**Interface:** `ArchProvisionState::{Unprovisioned, Provisioning(ProvisioningRecord), Ready(OwnedArchEntry), Uninstalling(UninstallingRecord)}`；缺少 journal 映射到 `Unprovisioned`。`OwnedArchEntry` 保存 owned/reserved `BootId`、当前 canonical load-option identity/版本、固定 UKI 路径及 build/publish metadata。`ProvisioningRecord` 和 `UninstallingRecord` 在其生命周期结束前都保留完整 `OwnedArchEntry`，另存各自的 operation/version、状态专属 lifecycle step 和已知 residual。Steps 区分 Boot#### create/readback、BootOrder append/readback，以及 uninstall 的 BootOrder、Boot####、UKI removal/readback 边界；这些 checkpoint/residual 只记录状态和不确定性，不授权自动 retry 或 cleanup。未知版本、损坏记录或身份不完整均为错误，不得折叠为 `Unprovisioned`。

- [x] 增加 codec/state 测试：`unprovisioned_is_only_absent_journal`、`lifecycle_records_roundtrip`、`unknown_or_corrupt_record_fails_closed`、`owned_entry_requires_supported_identity_and_fixed_path`。
- [x] 在独立 fake filesystem 上测试原子保存、短写、文件同步/目录同步失败、未知记录不被覆盖；使用现有 `LockedStore` 保护目录和互斥锁。
- [x] 运行 `cargo test -p boothop-core --test arch_provision_record` 与 `cargo test -p boothop-platform --test arch_provision_store`；本阶段不打开 efivarfs。

## Task 2 — Phase 2 — UKI discovery/build abstraction

**Files:** `crates/platform/src/linux/uki.rs`、`packaging/linux/boothop-uki-publish.sh`、`crates/platform/tests/uki_discovery.rs`、`crates/platform/tests/uki_publish.rs`；不修改任何系统 preset/config。

**Interface:** `discover_uki_plan(fs: &impl ArchConfigFs, policy: &UkiPolicy) -> Result<UkiBuildPlan, Error>` returns selected kernel image/flavor, mkinitcpio config and preset, stable final path `EFI/BootHop/arch.efi`, staged path on the same ESP filesystem, command-line source/value, microcode inclusion, Secure Boot/signing requirement and validation expectations. Builder/publisher is an injected trait; discovery does not execute mkinitcpio or write the filesystem.

- [ ] Test active preset discovery, unsupported layout, mounted ESP/path validation, kernel flavor ambiguity, explicit preset cmdline precedence, static cmdline files and `/proc/cmdline`-only fallback; ambiguous flavor or non-persistent/dynamic command line must return an actionable fail-closed result.
- [ ] Test `microcode` hook detection and UKI inputs contain the selected kernel, generated initramfs (with early microcode when configured), and confirmed cmdline; reject missing kernel/initramfs or unsupported root/crypt configuration.
- [ ] Test staged build/publish contract: build or validation/signing failure leaves previous stable UKI unchanged; successful same-filesystem atomic rename publishes only the fixed path; disk-full and incomplete-stage outcomes preserve the previous file.
- [ ] Use one narrowly scoped mkinitcpio post-build publisher: the selected preset writes to a staging filename in the same ESP directory; the hook validates the finished UKI, applies only an already-configured signer when Secure Boot requires it, verifies the resulting image, then atomically renames it to `EFI/BootHop/arch.efi`. Confirm the installed mkinitcpio update path invokes this hook; if the selected kernel update path disables post hooks, stop before real provision rather than publish directly to the live path. A kernel update must regenerate the same final path; no daemon and no versioned BootHop kernel copy.
- [ ] Run `cargo test -p boothop-platform --test uki_discovery` and `cargo test -p boothop-platform --test uki_publish`; tests use fake files and fake builder only.

**Read-only host findings to carry forward:** both `linux` and `linux-zen` presets are installed and currently produce split images; the running kernel is `linux-zen`, but that alone does not select the intended BootHop flavor. The usual persistent cmdline files were absent, so mkinitcpio would fall back to `/proc/cmdline`. The existing `microcode` hook is present. Phase 2 must resolve the intended GRUB Arch flavor and command line; Phase 7 may create an explicit persistent cmdline source only after authorization.

## Task 3 — Phase 3 — Boot#### provision abstraction

**Files:** `crates/platform/src/linux/boot_entry.rs`、`crates/platform/src/linux/firmware.rs`、`crates/platform/src/linux.rs`、`crates/platform/tests/boot_entry_provision.rs`、`crates/platform/tests/support/firmware.rs`。

**Interface:** a typed `BootEntryIo` accepts only `BootId`, structured `LoadOption`, and fixed BootHop description/path policy. `allocate_boot_id()` enumerates the complete strict Boot#### namespace, including orphan variables; `create_and_verify_entry()` uses exclusive creation, writes a serialized option, rereads/parses it, and compares the full canonical identity and exact owned payload. GUI data never reaches this interface.

- [ ] Test allocator skips all referenced and unreferenced occupied IDs, fails closed on incomplete enumeration/malformed names/namespace exhaustion, and rechecks the chosen ID immediately before exclusive create.
- [ ] Test create + readback exact match; collision after allocation; short/failed write; create reports error after possible mutation; absent/malformed/different readback; and crash after create. No path overwrites a preexisting option.
- [ ] Persist `Provisioning` ownership metadata before the first EFI variable write. On uncertain outcomes leave the journal for explicit read-only recovery; never auto-delete, allocate another ID, or restore guessed bytes.
- [ ] Run `cargo test -p boothop-platform --test boot_entry_provision`; all calls are fake `LinuxCalls`/firmware variables and never target host efivarfs.

## Task 4 — Phase 4 — BootOrder lifecycle and uninstall

**Files:** `crates/platform/src/linux/boot_order.rs`、`crates/platform/src/linux/firmware.rs`、`crates/platform/src/linux.rs`、`crates/platform/tests/boot_order_lifecycle.rs`。

- [ ] `append_owned_entry()` rereads and validates complete BootOrder, rejects malformed/duplicate lists and unexpected existing ID state, appends the owned ID once at the end, writes once, then validates full readback equals the pre-write current list plus that ID. Preserve the latest observed order; never restore an older snapshot.
- [ ] `begin_uninstall()` durably records `Uninstalling`, verifies the exact live owned identity and BootNext is not the owned ID, removes only that ID from the latest valid BootOrder while preserving all other elements, reads back, then deletes only the still-matching Boot#### after it is absent from BootOrder. Delete the BootHop UKI and journal only when their ownership/path/build metadata still match; otherwise retain them for manual recovery.
- [ ] Test append/readback, already-present/duplicate IDs, external BootOrder changes before write and before readback, firmware read/write errors, unknown write result, BootNext conflict, changed/non-owned option at same ID, crash at every uninstall step, and preservation of all other BootOrder items.
- [ ] Document the remaining firmware race: BootOrder has no verified compare-and-swap, so a writer can race between final read and write. Readback mismatch stops with residual state; implementation must not claim transaction or automatic rollback.
- [ ] Run `cargo test -p boothop-platform --test boot_order_lifecycle`; use isolated variable fakes only, never host NVRAM.

## Task 5 — Phase 5 — BootHop integration

**Files:** `crates/core/src/model.rs`、`crates/core/src/flow.rs`、`crates/protocol/src/lib.rs`、`crates/helper/src/dispatch.rs`、`crates/gui/src/helper_client.rs`、`crates/gui/src/helper_client/linux.rs`、`crates/gui/src/helper_client/windows.rs`、`crates/gui/src/controller.rs`、`crates/gui/src/main.rs`、`crates/platform/src/windows/uki.rs`、`crates/platform/tests/windows_uki.rs`、`crates/platform/tests/windows_adapter.rs`、`crates/helper/tests/protocol.rs`、`crates/helper/tests/windows_dispatch.rs`、`crates/gui/tests/controller.rs`、`packaging/windows/check-capabilities.ps1`、`packaging/windows/tests/fixtures/allowed-platform-firmware.rs`。

- [ ] Add closed `ProvisionArchEntry` and `UninstallArchEntry` requests and a typed lifecycle response. Route them only to Linux's trusted helper; reject them on Windows before any platform access. Request arguments contain operation intent only, never paths, IDs, raw EFI bytes, or canonical identity.
- [ ] Add an explicit Linux setup/uninstall action with separate helper authorization. Do not attach provision to Inspect, Configure or Switch. Reuse existing Windows Inspect/Configure so the user selects the appended `BootHop Arch` candidate as Linux; reuse existing Switch for the saved target.
- [ ] Keep ordinary `Switch` on the existing core/platform contract: live option identity check, BootNext conflict/readback and reboot. Add regression assertions that it never calls BootOrder/Boot#### create/delete/write paths.
- [ ] Implement Windows read-only UKI presence/format check by mapping the saved hard-drive/file-path identity to an existing EFI volume path. Do not mount the ESP, assign a drive letter, or write any volume. If the partition or fixed file cannot be resolved or validated, fail Switch before BootNext/reboot; never fall back to the old GRUB entry.
- [ ] Implement the root-only journal verifier and split publication paths before installing or wiring the post-hook. Missing, corrupt, unknown, or Uninstalling state blocks publication. The Rust initial coordinator accepts only exact `Provisioning(UkiPublicationPending)` with no publish metadata and an absent final path; it durably records `UkiPublicationAttempted` with expected SHA-256/size before writing any ESP stage, then renames and verifies exact final bytes before durable `UkiPublished`. The packaged mkinitcpio post-hook is updates-only: it accepts only `Ready`, passes the journaled SHA-256/size, and requires exact existing non-symlink regular-file contents before build/stage/replace; it never accepts Provisioning. A state marker alone is never proof. After successful Ready publication, durably update the journal before any EFI-variable mutation; if that update is interrupted or fails, preserve state and block later updates until explicit recovery. Hold one exclusive journal lock across verified state load, ownership checks, stage/rename, readback, and durable save.
- [ ] Implement the initial UKI checkpoint schema as version 3: `UkiPublicationPending` has no publish metadata, and `UkiPublicationAttempted` contains the exact expected SHA-256/size. Keep the same exclusive journal lock through durable Attempted save, staging, atomic rename, exact final readback, and durable UkiPublished save. Attempted restart is reconciliation-only; exact bytes may be surfaced for explicit recovery, while absent/mismatch requires manual recovery and cannot trigger rebuild, retry, or deletion. For a Ready update, update journal metadata only after exact readback; an uncertain save leaves either a matching new record/file or a stale old record that blocks the next update by hash/size mismatch.
- [ ] Keep the mkinitcpio post-hook updates-only: it accepts only `Ready` plus exact journal SHA-256/size and rejects every `Provisioning` checkpoint. Initial UKI publication must use the Rust coordinator's durable `UkiPublicationAttempted` checkpoint before any ESP write; do not route initial publication through mkinitcpio post-hook staging.
- [ ] Install or enable the post-hook only after initial provisioning has reached `Ready` and the trusted journal verifier/update path above is implemented and tested end to end. The hook's `BOOT_HOP_JOURNAL_STATE`, `BOOT_HOP_JOURNAL_UKI_SHA256`, and `BOOT_HOP_JOURNAL_UKI_SIZE` inputs must come only from that verifier; ordinary kernel updates without those trusted values fail closed.
- [ ] Test Linux provision dispatch only accepts fixed operations; Windows dispatch rejects both lifecycle requests before firmware access; UI handles partial/residual states without retry; Windows candidate selection and existing Configure/Inspect work; Switch writes only BootNext; Windows EFI-volume mapping handles absent, ambiguous, wrong-partition and missing/corrupt UKI.
- [ ] Update the IPC version/compatibility fixtures for the new typed request/response contract and retain strict unknown-field/version rejection.
- [ ] Run `cargo test -p boothop-core --test flow`, `cargo test -p boothop-platform --test windows_uki`, `cargo test -p boothop-platform --test windows_adapter`, `cargo test -p boothop-helper --test protocol`, `cargo test -p boothop-helper --test windows_dispatch`, and `cargo test -p boothop-gui --test controller`; in the existing Windows CI capability audit, allow only the new read-only volume APIs and prove mount/write APIs remain forbidden. No production helper, host EFI, or reboot is used.

## Task 6 — Phase 6 — Isolated / virtual UEFI acceptance

**Files:** `tools/uefi-acceptance/run.sh`、`tools/uefi-acceptance/README.md`、`fixtures/uefi/virtual/README.md`。

- [ ] Build a disposable test disk with existing test GRUB configuration and fixed-path UKI, plus an isolated OVMF variable store. Do not use host NVRAM or host ESP.
- [ ] Verify ordinary boot selects fixture Boot0000 → GRUB menu. Provision in the guest; assert BootHop entry is appended exactly once and all original BootOrder IDs remain in the same relative order.
- [ ] Execute BootHop Quick Hop in the Windows test guest: assert BootNext points to the BootHop Arch entry, reboot reaches the UKI and Arch without GRUB selection, firmware consumes BootNext, and the next ordinary boot returns to fixture Boot0000 → GRUB.
- [ ] Exercise UKI update, Secure Boot disabled, verified-signature and rejected-signature cases, plus injected failures and recovery reports. Test artifacts and keys stay within the disposable VM.
- [ ] Acceptance passes only with the complete sequence and captured before/after virtual BootOrder, BootNext, BootCurrent, UKI identity and observed OS; variable readback alone is not a boot-success claim.

## Phase 7 — Real Arch provision (separate user authorization required)

**Files:** only after explicit authorization: actual `/etc/mkinitcpio.d/<selected>.preset`, explicit persistent cmdline source if required, the fixed UKI location under the mounted ESP, the packaged post-build publisher installed under `/etc/initcpio/post/`, real UEFI Boot####/BootOrder, and the root-owned ownership journal.

- [ ] Before changing anything, show the user the selected kernel flavor, resolved command line source, fixed ESP-relative UKI path, Secure Boot state/signing result, and that provision creates one Boot#### and appends it to BootOrder. Obtain a new explicit authorization for this real setup.
- [ ] Under root, record the exact current Arch preset/config state for recovery (recording it does not authorize automatic restore). Do not install or wire the updates-only post-hook until initial provisioning has reached `Ready` and Phase 5's trusted root-owned journal verifier/update path is implemented and passed end-to-end tests. For first provision, use the Rust coordinator's durable Attempted-before-ESP-write publication flow and refuse to publish if the fixed UKI path already exists; the post-hook rejects all `Provisioning` states. Kernel updates require a valid `Ready` journal and exact journaled SHA-256/size match for the existing regular UKI before replacement. Missing/corrupt/unknown journal state blocks later kernel updates. After every successful publication, durably record the new UKI hash/size before Phase 3/4 EFI-variable changes. If publication and journal update do not both complete, stop and preserve state; never infer ownership or overwrite an unproven file.
- [ ] The initial journal must serialize `UkiPublicationPending` without invented publish metadata, then use the durable order `UkiPublicationAttempted(expected SHA-256/size) → stage write → atomic rename → exact final readback → UkiPublished`. Persist Attempted before any ESP write. Attempted is reconciliation-only: exact final bytes may be surfaced for explicit recovery, but absent/mismatched bytes require manual recovery; never rebuild, retry, or delete. The same exclusive journal lock must cover verified state load, ownership checks, rename, readback, and durable checkpoint writes. For Ready updates, persist updated metadata only after readback; if rename succeeds but the journal save fails or is uncertain, retain the old checkpoint and block subsequent updates on the old hash/size mismatch until explicit recovery.
- [ ] Read back the complete Boot#### and BootOrder; prove old order elements and priority are unchanged and BootHop appears once at the tail. Do not run a real BootNext test or reboot in this phase.
- [ ] If any state is uncertain, stop and preserve the journal and residuals; no automatic rollback or cleanup.

## Phase 8 — Real Windows → Arch acceptance (separate user authorization required)

**Files:** `docs/acceptance/windows-to-uki-arch.md` and captured acceptance evidence only.

- [ ] After Phase 7 is verified, obtain a separate explicit authorization for one real Windows BootNext operation and reboot.
- [ ] On Windows, Inspect the appended entry, have the user confirm/configure it as Linux, then run one Quick Hop. Verify BootNext write/readback, accepted reboot request, firmware consuming BootNext, and actual Arch boot from the fixed UKI without GRUB selection.
- [ ] Verify the next ordinary boot returns to unchanged Boot0000/GRUB and all preexisting BootOrder elements retain their relative order. Record each observation separately; do not equate API success/readback with actual boot success.
- [ ] Stop on any mismatch, unknown state, unexpected reboot target, or order change; preserve evidence and do not retry automatically.

## Phase Dependencies and Authorization Gates

| Phase | Depends on | Host root needed | Host EFI write | New user authorization |
|---|---|---:|---:|---:|
| 1 Ownership/data model | — | No (fake store tests) | No | No |
| 2 UKI discovery/build abstraction | —; feeds 3, 5, 7 | No (fake filesystem/builder) | No | No |
| 3 Boot#### provision abstraction | 1, 2 | Fake tests: no; trusted production helper: root-only by design | No in tests | No for code/fakes |
| 4 BootOrder lifecycle/uninstall | 1, 3 | Fake tests: no; trusted production helper: root-only by design | No in tests | No for code/fakes |
| 5 BootHop integration | 1–4 | No live operation; Linux helper code is privileged when invoked | No | No for code/fakes |
| 6 Virtual UEFI acceptance | 1–5 | No host root; isolated VM only | No host EFI; writes disposable OVMF vars | No |
| 7 Real Arch provision | 1–6 pass | **Yes, before preset/ESP/journal operations** | **First host EFI/NVRAM write is here** | **Yes, before any real preset, UKI or NVRAM write** |
| 8 Real Windows acceptance | 7 pass | Windows elevated helper as required | BootNext only; no BootOrder or Boot#### write | **Yes, separately before BootNext and reboot** |

Phases 1–6 can be implemented and verified without root access to the host or host EFI. The lifecycle operations introduced in Phase 3/4 execute through the existing root-owned Linux helper in production, but all tests before Phase 6 use fakes. Phase 6 writes only a disposable virtual firmware store. The first operation requiring root on the real Arch installation, and the first permission to write real EFI/NVRAM, is Phase 7. Phase 8 is a distinct authorization gate because it writes BootNext and reboots.

## Plan Self-Review

- Spec coverage: normal GRUB boot, fixed UKI/update path, ownership/lifecycle, explicit Linux provision/uninstall, BootOrder append/remove/readback, daily BootNext-only Switch, Secure Boot boundary, fake tests, virtual UEFI acceptance, separately authorized real provision and Windows acceptance are assigned to Phases 1–8.
- Failure review: unknown/corrupt ownership, orphan Boot####, identity changes, partial writes, crashes, external BootOrder changes, firmware races, UKI build/publish failures, Secure Boot rejection, and unreadable Windows UKI path all have explicit fail-closed tests.
- Dependency review: Phase 2 resolves kernel flavor and stable command line before production; Phases 3/4 consume the ownership journal; Phase 5 exposes only fixed lifecycle intents and reuses existing target workflow; Phases 7/8 cannot begin before Phase 6 passes and their separate authorization gates.
- Scope review: no implementation, host EFI access/write, GRUB modification, mkinitcpio system configuration change, or reboot is performed by this plan-writing task.

## Research Sources

- [Arch mkinitcpio(8)](https://man.archlinux.org/man/mkinitcpio.8) documents preset `*_uki`, `*_cmdline`, UKI sections, and command-line source fallback.
- [Arch Unified kernel image guidance](https://wiki.archlinux.org/title/Unified_kernel_image) describes preset integration and package-triggered rebuilds.
- [Arch Microcode guidance](https://wiki.archlinux.org/title/Microcode) describes the mkinitcpio `microcode` hook and early CPIO inclusion.
- [mkinitcpio upstream implementation](https://github.com/archlinux/mkinitcpio/blob/master/mkinitcpio) was reviewed for current build and post-hook behavior; safe atomic publication must be independently tested before real setup.
- [Microsoft GetVolumeNameForVolumeMountPoint](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumenameforvolumemountpointw) documents volume GUID paths; Phase 5 must still prove read-only partition resolution works for the actual EFI volume without assigning a mount point.
