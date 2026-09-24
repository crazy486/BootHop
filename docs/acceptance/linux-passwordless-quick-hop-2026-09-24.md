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
