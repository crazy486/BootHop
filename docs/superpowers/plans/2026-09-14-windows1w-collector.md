# Windows1W Read-Only Research Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a tested and statically audited Windows1W read-only collector artifact without executing any real firmware or privilege API.

**Architecture:** Add a standalone `tools/windows1w-collector` package with a pure orchestration library behind a closed fakeable call boundary and a Windows-only native backend. Tests construct only fakes; the release binary contains the future real backend but is never run during this phase.

**Tech Stack:** Rust 1.98.1, `boothop-core`, exact RustCrypto SHA-256, `serde`/`serde_json`, minimal `windows-sys` Win32 bindings, MSVC, and `dumpbin`.

**Spec:** `docs/superpowers/specs/2026-09-14-windows1w-collector-design.md`

## Global Constraints

- Never execute the collector or any real firmware, UAC, privilege-adjustment, BCD, helper, shutdown, or reboot path in this phase.
- Fixed GUID: `{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}`; fixed privilege: `SeSystemEnvironmentPrivilege`.
- Native API surface is limited to the spec allowlist; no dynamic loading or child process creation.
- No arbitrary firmware GUID or variable-name input; discovery is control variables plus referenced `Boot%04X` only.
- Payload limit is 1 MiB per variable; errors and sequential-read limitations are preserved without overclaiming.
- Private evidence remains below the verified gitignored Windows1W path and raw evidence is never committed.
- No existing milestone tags or acceptance status may be changed.
- Before implementation, verify branch `boothop-sdd` baseline `a751e09e82cddf263567552dcf62a96596350a6c`, origin/tags, tracked cleanliness, handoff state, and the isolated implementation worktree; keep Windows1W blocked and Stage 5 pending.
- The release target is Windows 11 x86-64 / `x86_64-pc-windows-msvc`; the read API minimum is Windows 8 desktop.

---

### Task 1: Pure orchestration, evidence model, and fake TDD

**Files:**
- Modify: `Cargo.toml`
- Create: `tools/windows1w-collector/Cargo.toml`
- Create: `tools/windows1w-collector/src/lib.rs`
- Create: `tools/windows1w-collector/src/model.rs`
- Create: `tools/windows1w-collector/src/collect.rs`
- Create: `tools/windows1w-collector/src/evidence.rs`
- Create: `tools/windows1w-collector/tests/collector.rs`
- Create: `tools/windows1w-collector/tests/support/mod.rs`

**Interfaces:**
- Produce a closed `VariableName` enum, narrow `WindowsCalls` trait, structured attempt/evidence/error types, `collect_with`, pure `parse_args`, and private evidence-path validation.
- `WindowsCalls` exposes only firmware type, privilege enable/restore, and bounded semantic variable reads; it has no write, process, BCD, or reboot method.

- [ ] Write tests first for firmware-type failure/non-UEFI short-circuiting; every privilege branch and original-state/restore behavior; restore-failure call-log termination; every required attempt field; immediate raw error retention; successful/malformed control reads; failed/missing BootNext without absence inference or discovery expansion; bounded resize/oversize; referenced-only union/deduplication; missing referenced entries; two-pass stability; exact acknowledgement; safe run IDs including traversal/absolute/reserved-name rejection; and safety call-log invariants.
- [ ] Run `cargo test -p boothop-windows1w-collector --test collector` and capture the expected RED caused by the missing wished-for API.
- [ ] Implement the smallest pure library and fake support that satisfies the tests, reusing `boothop_core::parse_load_option` while retaining raw bytes separately.
- [ ] Re-run the scoped tests to GREEN, then run package tests, fmt, and clippy without constructing the native backend.
- [ ] Commit as `feat(research): add Windows1W collector core` and write the task report with RED/GREEN commands and safety boundaries.

### Task 2: Windows backend, locked entry point, release artifact, and static audit

**Files:**
- Modify: `tools/windows1w-collector/Cargo.toml`
- Create: `tools/windows1w-collector/src/windows.rs`
- Create: `tools/windows1w-collector/src/main.rs`
- Create: `tools/windows1w-collector/tests/arguments.rs`
- Create: `docs/research/windows1w-collector.md`

**Interfaces:**
- Implement `WindowsCalls` with direct `windows-sys` calls using only the allowed API surface.
- Binary accepts only `--acknowledge=WINDOWS1W_NATIVE_READ_ONLY_AUTHORIZED` followed by a validated `--run-id=<id>`, uses the fixed private evidence root, and never elevates or launches another process.

- [ ] Write pure argument-parser and compile-only tests first for the exact ordered authorization interlock, safe run ID validation, closed input surface, and test-harness behavior that never invokes `main`, uses `Command`, spawns the binary, or constructs the native backend.
- [ ] Run scoped tests and capture RED before adding the binary/backend.
- [ ] Implement the narrow Windows backend with the current-process pseudo-handle, native result/handle/buffer validation, exactly-once token closure, explicit previous-state restoration, and immediate last-error capture; add no write, dynamic lookup, child, BCD, or reboot path.
- [ ] Run package tests, fmt, and clippy; compile the release artifact without executing it.
- [ ] Record artifact HEAD, size, and SHA-256; run `dumpbin /imports` and source/dependency prohibited-symbol audits, distinguishing ordinary Rust runtime imports from prohibited capability.
- [ ] Document the artifact and future authorization boundary, explicitly retaining Windows1W BLOCKED, Linux Stage 5 pending, and Windows production not started; commit as `build(research): prepare audited Windows1W collector`, and write the task report.

### Task 3: Independent review and final verification

**Files:**
- Modify only if reviewers identify required fixes in Tasks 1-2 files.
- Create local ignored review packages/reports under this plan's SDD workspace.

**Interfaces:**
- Produce independent spec-compliance, quality, and security verdicts plus one final combined verification record.

- [ ] Dispatch fresh independent spec, quality, and security reviewers against the complete diff and task reports.
- [ ] Route every Critical/Important finding through a fix and scoped re-review; do not request real execution while any remains open.
- [ ] Run final package tests, relevant workspace checks, fmt, clippy, source audit, PE import audit, hash verification, private-path ignore verification, and tracked-worktree verification.
- [ ] Commit only review-required tracked fixes/documentation; do not create Windows1W or Stage 5 tags.
