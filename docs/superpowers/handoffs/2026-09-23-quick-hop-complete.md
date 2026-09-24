# BootHop Quick Hop completion handoff

Stop time: 2026-09-23 00:37:26 +08:00  
Branch: `boothop-simple`  
Implementation HEAD: `f5c6d4fab850ad907fcdef3890a9302599ac7d9d`  
GitHub Actions: run `35753623045`, successful for the exact implementation HEAD

## Later acceptance update — 2026-09-24

The current branch subsequently completed one real Linux → Windows passwordless Quick Hop on the Arch Linux + KDE Plasma + Wayland UEFI machine. The exact release was `13dfe10de4b0acb4dcf7f11d677aadb91a2bb36a`; the ordinary desktop entry was activated once, no polkit password prompt or normal main GUI appeared, the production Switch path set and read back the Windows BootNext, rebooted normally, and the user confirmed arrival at Windows 11.

Current status:

- Completed: Arch → Windows Quick Hop real-machine acceptance.
- Completed: active Linux graphical-session passwordless authorization for the fixed BootHop helper.
- Still pending: Windows → Linux symmetric switching acceptance.
- Still pending: Windows UAC/no-prompt work and final cross-platform MVP acceptance.

This update does not claim that all firmware validation is complete and does not replace the earlier historical records below.

## Completed

- Preserved `boothop-sdd` at `4fc07695ea231b75642da7697276b58b35da727d` as the prior SDD/acceptance baseline.
- Added the short Quick Hop product amendment and minimal implementation plan.
- Added a platform-neutral startup mode to the existing GUI controller.
- An ordinary configured launch uses the untrusted local cache only as a routing hint, sends exactly one fixed-opposite-OS `Switch`, and creates no Slint window when the existing helper/core contract reports `RebootAccepted`.
- Missing or unreadable cache, wrong-OS cache, setup/settings mode, deterministic failure, and unknown-after-send outcomes show the existing setup/error UI and never retry automatically.
- `--setup` and `--settings` force the visible setup/reconfiguration path.
- Existing protected record, live firmware identity validation, BootNext conflict/readback, rollback limits, authenticated helper boundary, and normal reboot rules remain unchanged.
- Added fake/controller and static entry-point coverage for the new routing and no-window boundary.
- Independent read-only review found no blocking safety or logic issue.

## Verification

- Local `cargo +1.98.1 check --workspace --all-targets --locked`: PASS.
- Local GUI fake/controller/client/cache/static tests passed before the final test-binary hash was blocked by the known Smart App Control policy.
- Local `cargo fmt` and Clippy execution: environment BLOCKED by known Win32 4551, not treated as a code failure.
- GitHub Actions run `35753623045` for `f5c6d4f`: PASS.
  - Linux: workspace tests, formatting, Clippy, isolation checks, fake packaging, and package smoke test passed.
  - Windows: formatting, Clippy, workspace tests, release build, fake packaging, staged package checks, and capability audit passed.
- The first implementation run `35753184756` failed only formatting; the formatting-only follow-up produced the passing exact implementation HEAD above.

## Permission conclusion

- Linux passwordless daily Switch is not safely achieved by changing the existing shared polkit action to blanket `allow_active=yes`, because that would also relax Configure. An operation-specific authorization split needs separate review.
- Reliable Windows no-UAC daily Switch requires an install-time protected broker/service or equivalent integration. That architecture was intentionally deferred.
- The current minimal product therefore keeps the existing one-shot `pkexec` and Windows `runas` helpers.
- Smart App Control / Win32 4551 remains a signing or compliant-host acceptance blocker, not a core/Switch defect.

## Remaining work and blockers

- No real-system Quick Hop acceptance was performed. A future explicitly authorized session still needs a trusted signed helper or a compliant Windows acceptance host for real Windows validation.
- Passwordless Linux and no-UAC Windows daily use remain deferred architecture work; neither blocks the completed minimal “double-click directly attempts Switch” software path.
- No old GUI deletion or large controller refactor is recommended unless it directly reduces the setup/error surface without changing safety semantics.

## Safety and worktree state

- No real helper was launched.
- No firmware API, BootNext, BootOrder, Boot####, BCD, privilege-policy change, real Switch, or reboot occurred during development or automated verification.
- Existing untracked directories `trusted-target-task1/` and `trusted-target-task1-round2/` were not modified, tracked, or pushed.
- Tracked worktree was clean before this handoff file was created.

## Resume

Run:

```text
git switch boothop-simple
git pull --ff-only origin boothop-simple
```

Then read this handoff and `docs/superpowers/specs/2026-09-23-quick-hop-amendment.md`. Do not resume the older W3/W4/W5 acceptance sequence or run a real Switch without a new explicit authorization and a trusted helper execution path.
