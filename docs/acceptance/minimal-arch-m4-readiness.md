# Minimal Arch direct boot: M4 readiness

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
