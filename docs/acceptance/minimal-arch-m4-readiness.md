# Minimal Arch direct boot: M4 readiness

Decision on 2026-10-04 (Secure Boot firmware continuation): **BLOCKED by an
unexpected guest BootOrder mutation**. The original OVMF code image does not
support Secure Boot and exposed no `SecureBoot` variable. Switching to the
Secure Boot capable code image from the same local package, with the existing
private guest disk and variable store, exposed `SecureBoot=0` and booted the
original `Boot0000` GRUB entry. However, the firmware changed the guest
BootOrder from `0000,0001,0002,0003,0004,0005,0006,0007,0008` to
`0000,0001,0002,0003,0004,0005,0006,0007` before BootHop setup. The cause
of the missing `0008` entry is not established. The guest was stopped without
running setup, setting BootNext, retrying, or restoring the variable store.
See [the continuation evidence](minimal-arch-m4-enablement.md#2026-10-04-secure-boot-firmware-continuation).

Decision on 2026-10-04: **BLOCKED at guest preflight**. The existing OVMF
guest has no `SecureBoot` EFI variable. The production setup policy treats
that as an unknown state and refuses to plan setup. No setup, BootHop Boot####,
BootNext, or follow-on boot was attempted. The guest was shut down without
retry or firmware repair. See the [2026-10-04 acceptance evidence](minimal-arch-m4-enablement.md#2026-10-04-continuation).

Decision on 2026-10-02: **BLOCKED**. The first normal boot check has now passed
in a disposable Arch QEMU/OVMF guest. Guest setup and the BootNext sequence
were not run. See [the M4 enablement report](minimal-arch-m4-enablement.md).

M1–M3 have fake and CI verification, but neither those checks nor EFI variable
readbacks demonstrate a bootable UKI. The packaged `boothop-arch-setup` executable
still exits unavailable after validating root and arguments, so it cannot set up
an isolated guest yet.

QEMU and OVMF are unpacked into a user-owned cache; no system packages were
installed. A checksum-verified Arch ISO, private qcow2 disk, and private OVMF
variable store now exist there. The guest booted through its `Boot0000` GRUB
entry and reached Arch. Its firmware and ESP are independent of the host.

A feature-gated, unpackaged M4 guest setup entry now reuses the same production
adapters. The packaged host setup CLI remains fail closed. A guest-discovered
`findmnt` flag incompatibility was fixed and independently reviewed. No guest
setup was run: trusted usage telemetry fell to 14% weekly remaining, so the
unattended stop rule required safe wrap-up before the next mutation step.

On continuation, verify the guest setup path inside this VM, then test one-shot
BootNext direct boot and consumption, return to GRUB, and preserved original
Boot0000/BootOrder. No host EFI/NVRAM/ESP, GRUB/mkinitcpio, or reboot operation
was performed. The earlier plan's interrupted-setup and update scenarios are
outside this round's narrowed scope.
