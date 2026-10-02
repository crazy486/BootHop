# Minimal Arch direct boot: M4 readiness

Decision on 2026-10-02: **BLOCKED**.

M1–M3 have fake and CI verification, but neither those checks nor EFI variable
readbacks demonstrate a bootable UKI. The packaged `boothop-arch-setup` executable
still exits unavailable after validating root and arguments, so it cannot set up
an isolated guest yet.

The current workspace has no `qemu-system-x86_64`, `qemu-img`, or OVMF firmware
in the standard `/usr/share/OVMF`, `/usr/share/ovmf`, or `/usr/share/edk2`
locations. No package was installed and no disposable guest was created.

M4 requires a disposable QEMU/OVMF guest and a separately reviewed way to run
the setup path *inside that guest*. Only then can it check normal GRUB boot,
one-shot BootNext direct boot and consumption, return to GRUB, update boot,
and interruption without changing Boot0000. This decision authorizes no setup,
firmware write, ESP write, host preset edit, or reboot on the real machine.
