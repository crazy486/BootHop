# Linux passwordless Quick Hop acceptance — 2026-09-24

## Result

**FAIL — the single authorized attempt did not reach Windows.** No retry was
performed.

## Attempt record

- Branch: `boothop-simple`
- Exact HEAD: `2b2abe876d4734e45670bbad8809f35b756a6327`
- Origin branch matched the same HEAD before launch.
- Launch path: ordinary desktop entry `org.boothop.desktop` via
  `gtk-launch`; no `--setup` or `--settings` arguments and no direct helper
  invocation.
- Desktop launcher exit: `0` (launcher acceptance only, not a BootHop result).
- Existing GUI process before launch: none.
- Polkit/admin prompt: none observed.
- Normal main GUI after launch: none observed.
- Quick Hop/Switch count: one launch attempt; no retry.
- Helper terminal report: unavailable because the desktop entry detached the
  process; no raw helper error or terminal stage report was captured.

## Firmware and reboot observations

- Post-attempt read-only check found no `BootNext` variable.
- `BootNext` write/read-back success: **not evidenced**.
- Reboot request accepted: **not evidenced**.
- The machine remained in the Arch Wayland session after the attempt and did
  not reach Windows during the observation window.
- Actual Windows arrival: **NO**.
- BootOrder/Boot####/BCD were not intentionally modified by this attempt.

This record is intentionally conservative: a desktop-launcher exit code is
not treated as a helper result, and absence of a post-attempt `BootNext` does
not establish which pre-reboot stage failed. Do not retry Quick Hop from this
state without a separately authorized diagnostic plan.

## Diagnostic follow-up

The available journal and process evidence does not identify whether the
desktop launcher failed to start `boothop-gui`, whether `pkexec`/the helper
was launched, or whether `Request::Switch` reached the helper. The controller
contract still requires a failed Switch to show the normal window; only a
validated `RebootAccepted` result exits without a window. Therefore the
observed “no window, no reboot” outcome remains an unresolved startup/launch
failure rather than evidence of a firmware or helper stage.

A minimal diagnostic-only patch now records a bounded, non-sensitive
`startup-v1.json` beside the existing user cache during a future ordinary
Quick Hop. It records only `Started`, `BeforeSend`, `UnknownAfterSend`,
`Domain`, `RebootRequested`, or `ShowWindow` plus the existing bounded
controller diagnostic. It does not change authorization, Switch behavior,
firmware access, reboot behavior, or retry policy. No second Quick Hop was
performed while preparing this diagnostic patch.

## Successful follow-up — 2026-09-24

The later single authorized attempt used the exact `13dfe10de4b0acb4dcf7f11d677aadb91a2bb36a` release on the same Arch Linux + KDE Plasma + Wayland UEFI machine. The installed GUI, helper, and policy matched that release.

- Active graphical session passwordless authorization: **PASS**; no polkit/admin password prompt appeared.
- Launch path: ordinary `org.boothop.desktop` entry; no `--setup`, `--settings`, or direct helper invocation.
- Normal main GUI appeared: **NO**.
- Switch count: **exactly one**.
- Windows target validation and BootNext write/read-back: **PASS** through the production Quick Hop path.
- Normal reboot: **PASS**.
- Actual Windows arrival: **PASS**; the user confirmed reaching Windows 11.

**Linux passwordless Quick Hop real-machine acceptance: PASS.** This records only the observed Quick Hop path and does not claim that all firmware or cross-platform validation is complete.
