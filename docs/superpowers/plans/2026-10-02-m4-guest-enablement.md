# Minimal M4 guest enablement implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the six requested UEFI boot checks in one disposable Arch QEMU/OVMF guest while keeping host setup fail closed.

**Architecture:** Reuse `run_arch_setup`, `SystemArchSetupBackend`, and `NativeArchCalls` through a feature-gated, unpackaged guest binary. The QEMU launcher supplies only a private disk and private OVMF variable store; the guest binary checks a QEMU fw_cfg acceptance marker before constructing native calls. The packaged host setup executable remains unchanged.

**Tech Stack:** Rust workspace, Arch Linux guest, QEMU/KVM, OVMF, mkinitcpio, GRUB.

**Spec:** [Minimal Arch direct boot](../specs/2026-10-02-minimal-arch-direct-boot.md), narrowed by the user's current M4 request to six boot checks.

## Global constraints

- No host EFI/NVRAM/ESP, GRUB, mkinitcpio, Boot####, BootOrder, BootNext, or reboot operation.
- Guest-only executable is excluded from installed package and polkit policy.
- No transaction journal, recovery, automatic uninstall, Windows guest, or Secure Boot matrix.
- Unknown mutation outcome stops with observations; no retry or rollback.
- Stop if a single disposable guest needs substantial new infrastructure or production redesign.

## Task 1 — Guest-only entry

**Files:** `crates/helper/Cargo.toml`, `crates/helper/src/bin/boothop-m4-guest-setup.rs`, a small guard/test module under `crates/helper`, package tests as needed.

- [x] RED: test that the guard rejects absent/wrong fw_cfg marker and host-like evidence, and that the package excludes the guest binary while the host CLI still exits unavailable.
- [x] GREEN: feature-gate the separate binary; validate existing root-only CLI args and guest evidence before `NativeArchCalls::open`, then call the existing native backend and runner once, reporting success/failure without retry.
- [x] Verify targeted tests, workspace tests, formatting, Clippy, and package smoke; get independent review before any guest execution.

## Task 2 — Disposable acceptance

**Files:** disposable assets outside host boot mounts, `docs/acceptance/minimal-arch-m4-readiness.md`, and a compact evidence report under `docs/acceptance/`.

- [x] Obtain only the QEMU/OVMF and Arch guest assets required for one VM; ensure the launch command contains no host disk, directory, or efivarfs passthrough.
- [x] In the guest, establish Boot0000 as GRUB and record BootOrder; ordinary boot must reach GRUB.
- [x] Install BootHop's guest-only binary and fixed publisher in the guest; run setup there, recording the created BootHop entry and the original BootOrder prefix.
- [x] Set BootNext in guest; reboot guest; demonstrate direct UKI to Arch and BootNext consumption.
- [x] Reboot guest again; demonstrate normal GRUB path and preserved Boot0000/BootOrder.
- [x] If any prerequisite fails, record the exact blocker and leave all unrun checks NOT RUN. Do not claim PASS from fake or firmware readbacks alone.

Completed 2026-10-04 after the user-authorized minimal missing-parent metadata
fix. Earlier failed attempts stopped and were recorded; the post-fix attempt
passed. See [final acceptance evidence](../../acceptance/minimal-arch-m4-boot-acceptance.md).

## Completion gate

Independent review of the guest entry and whole diff, local checks, commit and push, inspect Linux/Windows CI. Do not perform host provision. Use the machine's actual local time and trusted usage telemetry for the user's restricted poweroff rule.
