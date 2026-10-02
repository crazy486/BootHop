# M4 disposable guest enablement — 2026-10-02

**M4: BLOCKED.** Trusted Codex telemetry reported 14% weekly remaining at
22:06 CST, triggering the unattended stop rule before guest setup. No setup
mutation, BootHop entry creation, or BootNext experiment was started.

| Check | Result | Evidence |
| --- | --- | --- |
| QEMU/OVMF environment | READY | QEMU 11.1.1 ran with KVM, private qcow2 and private OVMF_VARS; Arch 7.2.8 guest booted. |
| Guest-only setup | BLOCKED | Feature-gated binary built and independently reviewed; actual setup was not run before quota stop. |
| Normal boot → GRUB | PASS | OVMF printed `starting Boot0000 "Arch GRUB"`; GNU GRUB menu appeared; Arch login followed. |
| BootNext → UKI → Arch | NOT RUN | Guest setup and BootNext were not attempted. |
| BootNext consumed | NOT RUN | BootNext was not set. |
| Next normal boot → GRUB | NOT RUN | No post-BootNext boot occurred. |
| Original Boot0000/BootOrder preserved | NOT RUN | Baseline captured, but no setup or later boot was performed. |

The official `archlinux-2026.10.01-x86_64.iso` was verified with SHA-256
`684ded26c63240ff4a41e8c25ee84ea6da233f557364821f13d12c2b0a9059a5`.
QEMU packages were extracted under `/home/mani/.cache/boothop-m4/root`, not
installed system-wide. The guest uses a private 8 GiB qcow2, a private writable
OVMF_VARS copy, read-only OVMF_CODE, and no host block device, mount, directory,
or efivarfs passthrough. The installer made a 512 MiB FAT ESP and Arch root
inside `/dev/vda`, the VM's private disk. Guest `Boot0000` is `Arch GRUB`, and
its initial load-option SHA-256 was
`d4283290d50f8a90927619517c5d6680e1db1d72b55139c766d01e5154fbfbc9`.
OVMF added other boot options on first disk boot, so the post-boot BootOrder
baseline begins `0000,0001,0002,0003,0004,0005,0006,0007,0008`.

The dedicated guest binary is enabled only by Cargo feature
`m4-guest-setup`; the installed `boothop-arch-setup` stays fail closed and the
package excludes the guest binary. Its guard checks the QEMU fw_cfg marker,
QEMU DMI vendor, UEFI platform size, and efivarfs before opening native calls.
An independent review found and fixed a failure-path lock leak. A read-only
guest preflight also exposed incompatible `findmnt --list --pairs` arguments;
the adapter now uses a `--pairs` invocation confirmed by a read-only command
on host and guest. Rust tests that directly exercised protected native calls
were removed because the Linux isolation gate rejects such tests; the gate
was not weakened. The guest's mkinitcpio
package hook and script digests matched the adapter's pinned values.

The VM was powered off cleanly and the temporary transfer server was stopped.
No host EFI/NVRAM/ESP, host GRUB/mkinitcpio, or host reboot operation occurred.
Local workspace and feature-enabled tests, formatting, Clippy, Linux isolation,
installer fake tests, and package smoke passed. CI must be inspected after this
report is pushed; none of these checks proves the remaining UEFI boot semantics.
