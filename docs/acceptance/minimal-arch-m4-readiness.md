# Minimal Arch direct boot: M4 readiness

Decision on 2026-10-02: **BLOCKED**. The requested minimal M4 boot acceptance
was not run, so none of its five boot criteria can be marked PASS.

M1–M3 have fake and CI verification, but neither those checks nor EFI variable
readbacks demonstrate a bootable UKI. The packaged `boothop-arch-setup` executable
still exits unavailable after validating root and arguments, so it cannot set up
an isolated guest yet.

The current workspace has no `qemu-system-x86_64`, `qemu-img`, or OVMF firmware
in the standard `/usr/share/OVMF`, `/usr/share/ovmf`, or `/usr/share/edk2`
locations. The available `/dev/kvm` and disk space are sufficient to attempt a
VM, and the QEMU/OVMF packages are available from the configured repositories.
But no Arch installer or disposable Arch guest image is present. The only local
ISO found is GParted Live, which cannot demonstrate an Arch UKI boot.

The latest M4 request permits the minimum QEMU/OVMF packages and disposable
guest assets. This does not remove the setup blocker: the packaged setup CLI
intentionally exits before connecting its production adapters. Manually adding
an EFI entry in a guest would demonstrate generic firmware behavior but would
skip BootHop's setup path. A credible acceptance run would therefore require
acquiring and preparing an Arch guest, isolated OVMF variables and ESP, and
separately verifying and connecting the setup adapter. That is more than the
minimal environment preparation authorized for this round. We stopped before
installing packages or downloading an image; no guest was created.

M4 remains blocked until a disposable Arch guest and an independently reviewed
in-guest setup path are available. Then test normal GRUB boot, one-shot BootNext
direct boot and consumption, return to GRUB, and unchanged Boot0000/BootOrder.
The optional UKI rebuild check remains deferred. No host EFI/NVRAM/ESP,
GRUB/mkinitcpio, or reboot operation was performed. The earlier plan's
interrupted-setup scenario is outside this round's explicitly narrowed scope.
