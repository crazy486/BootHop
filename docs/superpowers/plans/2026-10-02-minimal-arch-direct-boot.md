# Minimal Arch direct boot implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one explicit Arch setup path so Windows BootHop can one-shot boot a fixed UKI while ordinary power-on retains the original GRUB menu.

**Architecture:** Start from pushed `boothop-simple` at `085ada1`, not from the full UKI branch. The Linux setup path has one fixed artifact, one exclusively created Boot####, a tail-only BootOrder append, and one installed identity marker. Windows uses its existing protected target and BootNext-only Switch. Failed setup stops and reports observations for manual recovery.

**Tech Stack:** Rust 2024 workspace; existing core/platform/helper boundaries; mkinitcpio preset and post hook; fake firmware/filesystems; isolated UEFI if already available.

**Spec:** [2026-10-02-minimal-arch-direct-boot.md](../specs/2026-10-02-minimal-arch-direct-boot.md)

## Global Constraints

- Never change original Boot0000, existing GRUB files/menu, Windows Boot Manager, or non-BootHop Boot####.
- Setup may append exactly one newly created ID to the tail of the latest BootOrder; preserve all original IDs and order. No CAS or automatic rollback claim.
- Daily Switch writes BootNext only; Windows does not access the ESP or UKI file.
- No persistent transaction journal, checkpoint enum, residual graph, automatic recovery, or automatic uninstall.
- No real host efivarfs, ESP, mkinitcpio preset, GRUB, BootNext, pkexec lifecycle, or reboot operation during this plan's implementation/tests.
- The explicit setup executable is separate from the passwordless polkit-authorized daily helper; the existing polkit action must never authorize setup.
- Unknown write outcome stops; no retry, alternate ID, or speculative cleanup.
- Secure Boot enabled and unsupported kernel/preset/cmdline/ESP/update-hook layouts fail closed.
- Preserve selected preset's existing default/fallback outputs when adding one BootHop stanza.

## Review Focus

- An orphan Boot#### outside BootOrder must block ID reuse (Task 1 fake).
- A short, failed, or uncertain EFI write must trigger observation/report only, never a second write (Task 3 fake).
- Existing preset syntax or a conflicting `boothop` stanza must stop without rewriting normal outputs (Task 2 temp fixture).
- A corrupt/foreign installation marker must block update publication (Task 2 temp fixture).
- Existing GRUB target Switch must behave exactly as before; direct UKI target still writes only BootNext (Task 4 fake).

## Phase M1 — reusable primitives

### Task 1: Small EFI setup primitives

**Files:** `crates/core/src/load_option.rs`, `crates/core/src/lib.rs`, `crates/platform/src/linux/setup_firmware.rs`, `crates/platform/src/linux.rs`, `crates/core/tests/arch_load_option.rs`, `crates/platform/tests/setup_firmware.rs`.

**Interfaces:** Add `GptEspIdentity { partition_number: u32, start_lba: u64, size_lba: u64, guid_uefi_bytes: [u8; 16] }`, fixed-path `arch_uki_load_option(esp: GptEspIdentity) -> Result<LoadOption, Error>`, and `serialize_load_option(&LoadOption) -> Result<Vec<u8>, Error>` using existing parser/device-path types. Add `SetupFirmware` as a narrow injected variable interface and `allocate_unused_id`, `create_exact_entry`, `decode_boot_order`, `append_tail_exact` functions. The injected interface exposes complete namespace enumeration, exact variable read, exclusive Boot#### create, and one BootOrder replace; only `create_exact_entry` and `append_tail_exact` mutate. No production setup runner in M1. `append_tail_exact` requires Boot0000 first, a fresh complete order, one write, and a full exact readback.

- [ ] RED: test exact GPT `HD()` + fixed `File()` + EndEntire bytes and parser round-trip; occupied, orphan, malformed Boot-like names, BootNext-present, and namespace exhaustion.
- [ ] RED: test exclusive-create collision, wrong exact readback, malformed/duplicate BootOrder, append preserving all IDs, external order change, short/unknown write with zero retries.
- [ ] GREEN: implement only the functions and fake boundary required by those tests; inspect old branch code selectively, without coordinator permits or journal types.
- [ ] Verify `cargo test -p boothop-core --test arch_load_option`, `cargo test -p boothop-platform --test setup_firmware`, then `cargo test --workspace --all-targets`; commit primitives and tests.

## Phase M2 — Linux explicit setup

### Task 2: Fixed UKI preset and publisher

**Files:** `crates/platform/src/linux/arch_uki.rs`, `crates/platform/src/linux/arch_identity.rs`, `packaging/linux/boothop-uki-publish.sh`, `crates/platform/tests/arch_uki.rs`, `crates/platform/tests/arch_identity.rs`, `packaging/linux/tests/boothop-uki-publish-test.sh`.

**Interfaces:** Read-only `plan_arch_uki(flavor: &str, source: &impl ArchSetupSource) -> Result<UkiPlan, SetupError>` accepts only installed preset names and `/etc/kernel/cmdline`, exact vfat ESP/GPT, Secure Boot disabled, and verified package-hook routing. `render_boothop_preset(existing: &str, plan: &UkiPlan) -> Result<String, SetupError>` adds only one BootHop stanza while preserving default/fallback lines and refusing conflicts. Define `InstalledIdentity` and exact root-owned marker bytes at `/var/lib/boothop/arch-direct.identity`: `BOOTHOP_ARCH_V1\nboot_id=XXXX\noption_sha256=<64 lowercase hex>\npath=EFI/BootHop/arch.efi\n`. The hook validates owner/mode and these exact fields, but does not re-read firmware. One publisher validates the exact stage, accepts explicit initial mode only with absent final/marker, or update mode only with a parsed marker and existing regular final file, then same-filesystem renames. No journal. The selected existing preset must be the one the package hook rebuilds.

- [ ] RED: temp-fixture tests for two installed flavors requiring explicit selection, missing/dynamic cmdline, unsupported ESP/Secure Boot, unknown package-hook route, conflicting preset, and preservation of default/fallback lines.
- [ ] RED: shell temp-fixture tests for invalid or truncated UKI, absent/corrupt/foreign marker, wrong output path, symlinked ESP parent/stage/final, stale staging residue, pre-existing final in initial mode, failed staging, initial/update mode, and preserved old final on failure.
- [ ] GREEN: implement narrowly, using the existing mkinitcpio preset/post-hook contract; do not transplant old `uki.rs` wholesale.
- [ ] Verify `cargo test -p boothop-platform --test arch_uki`, `cargo test -p boothop-platform --test arch_identity`, `bash packaging/linux/tests/boothop-uki-publish-test.sh`, and workspace tests; commit this task.

### Task 3: One-shot Linux setup and reporting

**Files:** `crates/platform/src/linux/arch_setup.rs`, `crates/platform/src/linux/store.rs`, `crates/helper/src/bin/boothop-arch-setup.rs`, `packaging/linux/build-package.sh`, `packaging/linux/install.sh`, `packaging/linux/package-smoke.sh`, `crates/platform/tests/arch_setup.rs`, `crates/helper/tests/arch_setup_dispatch.rs`, `docs/acceptance/manual-arch-direct-maintenance.md`.

**Interfaces:** `run_arch_setup(intent: SetupIntent, backend: &mut impl ArchSetupBackend) -> Result<InstalledIdentity, SetupFailure>` uses Task 1 primitives and Task 2 artifact plan. Its linear order is: read-only plan and package-update route verification → guarded selected-preset edit → fixed post-hook install → explicit initial `mkinitcpio -p <flavor>` invocation with initial-mode flag → inspect the published fixed UKI → exclusive Boot#### create and exact readback → fresh BootOrder append and full readback → atomic save of Task 2's `InstalledIdentity`. `ArchSetupBackend` exposes those named operations as injected methods; production adapters are reachable only from the separate setup executable. Package Task 2's publisher as root-owned `/usr/lib/boothop/boothop-uki-publish`; setup verifies that fixed asset's ownership and mode and installs a post hook referring only to that path. Package smoke tests assert the asset exists at the fixed path. `SetupFailure` carries stage plus read-only observed preset stanza, post-hook installation/exactness, artifact/entry/order/BootNext states, including unknown. Add `boothop-arch-setup --kernel <validated-flavor> --apply` as a distinct root-only binary, packaged without any polkit action; it must not share normal Switch IPC, accept paths/IDs, or execute in tests. The setup binary uses the existing trusted operation lock where applicable.

- [ ] RED: fake interruption after preset edit, after hook install, and at each later mutation boundary reports observed/unknown configuration and firmware objects without retry, delete, rollback, another ID, or damage to original Boot0000/order; re-check BootNext and exact new Boot#### just before latest-order append.
- [ ] RED: setup CLI rejects absent `--apply`, non-root, unknown args, paths/Boot IDs supplied as flavor; package/policy tests prove the daily helper and passwordless polkit action cannot invoke setup and that no setup polkit action is installed.
- [ ] GREEN: implement the linear runner, minimal atomic marker, read-only failure inspection, and fixed helper entrypoint; keep host adapters uninvoked by tests.
- [ ] Document exact read-only checks and administrator-controlled manual cleanup for partial preset/hook/artifact/firmware state, never deletion by label alone.
- [ ] Verify `cargo test -p boothop-platform --test arch_setup`, `cargo test -p boothop-helper --test arch_setup_dispatch`, and workspace tests; commit this task.

## Phase M3 — Windows reuse

### Task 4: Direct target through existing Switch

**Files:** `crates/core/tests/flow.rs`, `crates/platform/tests/windows_adapter.rs`, `crates/helper/tests/windows_dispatch.rs`; production files only if a failing test proves a gap.

**Interfaces:** The dedicated Boot#### is configured through existing Inspect/Configure and saved `TargetRecord`. Existing `validate_target` enforces Boot ID/canonical identity/OptionalData; Windows `Switch` performs its existing BootNext conflict/readback and reboot sequence. No lifecycle IPC, native EFI-volume reader, or new Windows API is introduced. Existing Windows capability audit is kept at stable baseline unless review finds a Minimal-specific gap.

- [ ] RED if needed: fake tests with a fixed UKI file-path target and changed live identity; prove no BootNext/reboot on mismatch, only BootNext on success, and unchanged GRUB-target behavior.
- [ ] GREEN only for a demonstrated gap; otherwise add regression assertions without expanding Windows production architecture.
- [ ] Verify targeted tests, workspace tests, and applicable Windows-source/package checks; commit this task if tests changed.

## Phase M4 — isolated acceptance

### Task 5: Small isolated boot acceptance

**Files:** `tools/uefi-acceptance/` and `docs/acceptance/minimal-arch-direct-boot.md` only if an already available isolated QEMU/OVMF environment supports the run; otherwise record the missing environment and stop before real firmware.

- [ ] Check for existing QEMU/OVMF and a disposable disk/guest; do not install system packages.
- [ ] If available, verify normal GRUB, BootNext direct UKI Arch, BootNext consumption, next normal GRUB, rebuilt artifact boot, and interrupted setup preserving original Boot0000.
- [ ] If unavailable, record precise blocker; never claim firmware boot acceptance from fake variable readbacks.

## Completion gate

Run `cargo fmt --check`, `cargo test --workspace --all-targets`, `cargo clippy --workspace --all-targets -- -D warnings`, applicable Linux isolation and package checks, and Windows CI checks. Obtain task and final independent reviews, count production/test LOC and added state/privileged/Windows/IPC surface against `codex/arch-uki-direct-boot`, then push `codex/arch-uki-minimal` and inspect CI. Stop if production complexity approaches the old architecture instead of falling by at least about half.
