# GUI acceptance matrix

Status: **NOT ACCEPTED**. The current Linux development build selects Slint
1.17.1 with Winit + FemtoVG and supports only Linux wiring. This does not prove
renderer quality, desktop-session compatibility, or Windows support. Every
cell below requires an attached screenshot and a run log; “build succeeded” is
not a GUI result.

The Windows GUI executable is now a compile-time and fake-test artifact only.
Its staged manifest requests `asInvoker`; only the fixed helper requests
`requireAdministrator`. No UAC prompt, helper launch, firmware operation,
shutdown, reboot, installation, or real Windows desktop session was exercised.
Windows1W read-only research and Linux Stage 5 post-boot closure remain
separate evidence streams and do not establish Windows GUI acceptance.

| Environment | Scale | Unicode target descriptions | Result / evidence |
|---|---:|---|---|
| Windows 11, normal desktop session | 100% | Chinese and another non-ASCII description | **Not run** |
| Windows 11, normal desktop session | 150% | Chinese and another non-ASCII description | **Not run** |
| Windows 11, normal desktop session | 200% | Chinese and another non-ASCII description | **Not run** |
| Linux Wayland (Arch reference) | 100% | Chinese and another non-ASCII description | **Not run** |
| Linux Wayland (Arch reference) | 150% | Chinese and another non-ASCII description | **Not run** |
| Linux Wayland (Arch reference) | 200% | Chinese and another non-ASCII description | **Not run** |
| Linux X11 (Ubuntu 24.04 reference) | 100% | Chinese and another non-ASCII description | **Not run** |
| Linux X11 (Ubuntu 24.04 reference) | 150% | Chinese and another non-ASCII description | **Not run** |
| Linux X11 (Ubuntu 24.04 reference) | 200% | Chinese and another non-ASCII description | **Not run** |
| OVMF/UEFI virtual machine (Wayland or X11 noted) | 100/150/200% | Actual startup-item descriptions | **Not run** |

For each run record OS/build, desktop/session type, display scale, monitor
dimensions, locale/font configuration, OVMF and guest details when applicable,
package checksum, exact startup-item descriptions (including characters that
are not ASCII), and the screenshot path. Verify truncation, selection,
confirmation, diagnostics, and the warning “点击后将立即重启，请先保存工作”.

## Renderer decision gate

FemtoVG is the currently selected renderer in code; that is a configuration,
not an acceptance result. If a run fails, attach the complete stderr/log and a
screenshot labelled with the matrix cell before considering any renderer
change. Skia is **not evaluated or selected** until a reproducible FemtoVG
failure has been recorded and reviewed. No ordinary test may require a desktop
session or start an event loop.
