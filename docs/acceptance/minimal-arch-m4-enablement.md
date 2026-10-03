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

## 2026-10-04 continuation

**M4 remains BLOCKED.** Reused the same qcow2, OVMF_VARS, QEMU binary, and
Arch guest. The previously pushed `5658445` Linux and Windows CI completed
successfully. No asset was downloaded or rebuilt.

The ordinary boot again showed OVMF starting `Boot0000 "Arch GRUB"`, the GNU
GRUB menu, and an Arch 7.2.8 serial login. Immediately before the planned
guest setup, `efibootmgr` reported `BootCurrent: 0000`, no BootNext, and
`BootOrder: 0000,0001,0002,0003,0004,0005,0006,0007,0008`. `Boot0000` still
had SHA-256 `d4283290d50f8a90927619517c5d6680e1db1d72b55139c766d01e5154fbfbc9`.
The fixed fw_cfg guest marker matched; the ESP was `/dev/vda1` mounted as
`vfat` at `/boot`; both pinned mkinitcpio package-route digests matched.
No existing identity marker, BootHop UKI, post hook, pacman lock, or BootNext
was present. The guest-only binary and publisher were transferred with matching
SHA-256 values and installed inside the guest with required root ownership and
permissions.

The read-only preflight failed because
`/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c`
does not exist in this OVMF guest. `SystemArchSetupBackend::secure_boot_state`
maps anything other than an explicit disabled value to `Unknown`; the setup
planner rejects that state. Following the stop-on-failure rule, **the setup
binary was not run**. No SecureBoot variable was synthesized, and no firmware
mutation, retry, rollback, or OVMF replacement was attempted. The guest was
powered off cleanly and the temporary transfer server was stopped.

| Check | Latest result |
| --- | --- |
| QEMU/OVMF environment | READY for ordinary Arch boot; BLOCKED for this setup policy by missing SecureBoot state |
| Guest-only setup | BLOCKED — not run after failed preflight |
| Normal boot → GRUB | PASS |
| BootNext → UKI → Arch | NOT RUN |
| BootNext consumed | NOT RUN |
| Next normal boot → GRUB | NOT RUN |
| Original Boot0000/BootOrder preserved after setup | NOT RUN — setup did not occur |

No host EFI/NVRAM/ESP, BootOrder, BootNext, GRUB, or mkinitcpio operation and
no host reboot occurred. The remaining M4 checks require an isolated OVMF
environment that explicitly reports Secure Boot disabled; preparing that is a
separate decision, outside this stop-on-failure run.

## 2026-10-04 Secure Boot firmware continuation

**M4: BLOCKED.** Investigation of the missing `SecureBoot` variable identified
the selected firmware build as the cause. The local `edk2-ovmf-202608-1`
package's firmware descriptors identify `OVMF_CODE.4m.fd` as the ordinary
build and `OVMF_CODE.secboot.4m.fd` as the Secure Boot and SMM build. Both
descriptors name the same `OVMF_VARS.4m.fd` template. The package's OVMF
README says Secure Boot requires a build with `SECURE_BOOT_ENABLE`; no keys
are installed by default. The previous launch used the ordinary code image.
The production backend's absent-variable → `Unknown` → reject behavior was
left unchanged.

One launch used the already installed guest disk and its existing private
OVMF variable store, changing only the QEMU firmware code path to the local
Secure Boot capable image and enabling Q35 SMM/secure pflash. No asset was
downloaded, and the guest was not rebuilt. Before launch, the private
variable store's SHA-256 was
`8cc79b1837204552fd12ed26006ad1902fd92037f02d6091e8d6d1f7b3b49291`;
an evidence copy of those original bytes was saved as
`/home/mani/.cache/boothop-m4/ovmf-vars.pre-secboot-evidence.fd` and was
**not** used for rollback.

The guest booted through `Boot0000 "Arch GRUB"`, displayed GRUB, and reached
Arch. Inside the guest, the `SecureBoot` efivar bytes were `06 00 00 00 00`
(attributes 6, payload 0, explicitly disabled). `BootCurrent` remained
`0000`, and `Boot0000` still had the original SHA-256
`d4283290d50f8a90927619517c5d6680e1db1d72b55139c766d01e5154fbfbc9`.

The same read-only observation showed an unexpected firmware mutation:
`BootOrder` was `0000,0001,0002,0003,0004,0005,0006,0007`, whereas its
pre-switch baseline was `0000,0001,0002,0003,0004,0005,0006,0007,0008`.
The guest's `efibootmgr -v` output no longer listed `Boot0008`. Its absence
has not been explained or accepted as safe. Following the stop-on-unknown-
mutation rule, the guest was immediately powered off. **No guest-only BootHop
setup or BootNext write was attempted.** The variable store was not restored;
there was no retry or rollback. After shutdown, the changed private variable
store's SHA-256 was
`601bcb1f3f56beca34e1b5041aaa99388cbd1ea3c64aa706c2b855f828e4585d`.

| Check | Result |
| --- | --- |
| QEMU/OVMF environment | Secure Boot disabled was read explicitly; original BootOrder preservation BLOCKED by firmware change |
| Guest-only setup | NOT RUN |
| BootHop Boot#### created | NOT RUN |
| Normal boot → GRUB | PASS |
| BootNext → UKI → Arch | NOT RUN |
| BootNext consumed | NOT RUN |
| Next normal boot → GRUB | NOT RUN |
| Original Boot0000/BootOrder preserved | Boot0000 unchanged; BootOrder changed before setup, so FAIL |

No host EFI/NVRAM/ESP, host Boot####/BootOrder/BootNext, GRUB, or mkinitcpio
operation occurred. The host was not rebooted. The disposable guest alone
was shut down. An independent read-only review confirmed that the production
Secure Boot check still rejects absent, malformed, enabled, and unknown
values, and that the unexplained BootOrder change requires this M4 stop.
