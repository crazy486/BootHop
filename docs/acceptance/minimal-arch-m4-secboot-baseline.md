# M4 Secure Boot firmware baseline — 2026-10-04

**Environment READY for setup.** M4 boot acceptance remains unrun: this round
did not run BootHop setup or write BootNext. It reused the existing Arch disk,
created a new private variable store, and used Secure Boot capable OVMF from
that store's first boot. Two subsequent ordinary guest boots preserved the
complete baseline.

## Pre-switch Boot0008 evidence

Read-only parsing of `ovmf-vars.pre-secboot-evidence.fd` (SHA-256
`8cc79b1837204552fd12ed26006ad1902fd92037f02d6091e8d6d1f7b3b49291`)
found an active authenticated-store record at offset `0x304c`:

- Name: `Boot0008`; variable attributes: `7`; record state: `0x3f`.
- Load-option attributes: `0x101` (active firmware application).
- Description: `EFI Internal Shell`.
- Device path: firmware volume `7cb8bdc9-f8eb-4f34-aaea-3ee4af6516a1`,
  firmware file `7c04a583-9e3e-4f1c-ad65-e05268d0b4d1`, then end node.
- No disk, ESP, or GRUB path; no optional data.
- Reconstructed efivarfs SHA-256:
  `e37626dc384ff8ed730bcecd3cbd4ea8f28f42072f57763cd79548adfb8ada57`.

This is OVMF's internal shell utility, not the guest's Arch boot entry.
The evidence does not establish a temporary lifetime, nor every internal
step that removed it during the firmware switch. `Boot0000` at offset
`0x16a8` independently names `Arch GRUB` and points to the existing guest
ESP's `\EFI\GRUB\grubx64.efi`; reconstructing its efivarfs bytes matched
the previously observed SHA-256. The old `BootOrder` active record at
`0x2fe8` contains `0000,0001,0002,0003,0004,0005,0006,0007,0008`.
Neither the old nor the firmware-switched variable store is the new baseline.

## Fresh fixture provenance

The unchanged guest disk is `/home/mani/.cache/boothop-m4/arch-guest.qcow2`.
The new store is `/home/mani/.cache/boothop-m4/ovmf-vars.secboot-baseline.fd`.
It began with the local package's empty `OVMF_VARS.4m.fd` template, SHA-256
`5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e`.
Only the verified original `Boot0000` GRUB load-option payload and a fresh
`BootOrder=[0000]` were preseeded into it. No firmware utility entries,
Secure Boot variables, or other state were copied from either old store.
Its pre-first-boot SHA-256 was
`bf1e2ba1bea04494a5f7ef6a091dcdc24cbb302a445cf3ad5e163817462986a3`.

All three boots used `OVMF_CODE.secboot.4m.fd`, SHA-256
`cc150d941d4f1d39e596dedc545384a66ccfb3c9ba5cf9bc3a54d8d427d4d88f`,
Q35 with SMM, secure pflash, the existing private disk, and the fixed guest
marker. The code image was read-only. No host block device, host directory,
or efivarfs was passed through. No download or guest rebuild occurred.
The expected first-boot creation of firmware utility/network options was
recorded as initialization; subsequent comparisons use that observed baseline.

## Boot observations

| Observation | Initial baseline boot | Ordinary boot 1 | Ordinary boot 2 |
| --- | --- | --- | --- |
| OVMF Boot0000 → visible GRUB → Arch | PASS | PASS | PASS |
| BootCurrent | 0000 | 0000 | 0000 |
| SecureBoot efivar bytes | 06 00 00 00 00 | 06 00 00 00 00 | 06 00 00 00 00 |
| Complete BootOrder | 0000,0001,0002,0003,0004,0005,0006,0007 | same | same |
| All Boot0000–Boot0007 bytes | recorded below | identical | identical |
| BootNext | absent | absent | absent |
| Arch boot ID | 28be0f5f-93b6-4669-ba88-2b1c78582f1c | f57a3e41-87e3-4848-a50b-cc555ee143c7 | fe79cfca-165e-4b64-8608-cf7e5d16fb9c |

`SecureBoot` attributes were `6` and its one-byte payload was `0`, supplied
by the firmware and accepted as disabled by the unchanged production policy.
This demonstrates disabled state, not Secure Boot signing acceptance.
The only guest commands between observations were ordinary guest reboots
and read-only EFI/hash queries. The guest was powered off cleanly afterward.

| Baseline variable | Description | SHA-256 of complete efivarfs bytes |
| --- | --- | --- |
| Boot0000 | Arch GRUB | d4283290d50f8a90927619517c5d6680e1db1d72b55139c766d01e5154fbfbc9 |
| Boot0001 | BootManagerMenuApp | e543575559504be8df6f2f6010b37b8244fa8ad5c02d03f14ab20ab130c30c20 |
| Boot0002 | EFI Firmware Setup | 7830a2c75b5c38c336ba7764a62e90dc4787094cbc047af00b7abd7e628e8a6b |
| Boot0003 | UEFI Misc Device | e78e63dac47c1afea01b77081a011f6336bae03cc55f7999810b657c5ddcbff0 |
| Boot0004 | UEFI PXEv4 | 3bcb807989353a1005bc368586d6000c3f3d7a6694fd29fdf5b7ae9ec752670c |
| Boot0005 | UEFI PXEv6 | 905bfd3cce953a5b00825fb20ab1ec2d920630ca852b47b283f9a12a98b9960e |
| Boot0006 | UEFI HTTPv4 | 9677201537ce4cd30550c20a1fb685838ecc9d271f3e6f4e93cb610aa8eab3a3 |
| Boot0007 | UEFI HTTPv6 | 6f66f6731b2b2fd79dca01e68f06c9e2cf4c6642bb8cd1464dfd7c16564183e5 |
| BootOrder | complete order above | 3024e0cd4128a9fe2ac83be06670aea230a042e727ee82536b0b6468916c3793 |

After final guest shutdown, the new private store's SHA-256 was
`d164dff834149e3375f92ee910dfa74c7e84708fc54dc87cffe7bf563ed18f9b`.
The original evidence copy remained unchanged. No unknown Boot#### or
BootOrder mutation occurred after establishing the new baseline. This does
not claim that all unrelated OVMF variable bytes are immutable across boots.

## Continuation fixture

Use this new store with the same Secure Boot capable code image for any
later authorized setup acceptance. Do not use `ovmf-vars.fd` or reseed this
initialized baseline. The launcher used here was:

```bash
asset_root=/home/mani/.cache/boothop-m4
LD_LIBRARY_PATH="$asset_root/root/usr/lib" "$asset_root/root/usr/bin/qemu-system-x86_64" \
  -L "$asset_root/root/usr/share/qemu" -machine q35,accel=kvm,smm=on \
  -global driver=cfi.pflash01,property=secure,value=on -cpu host -m 3072 -smp 2 \
  -drive if=pflash,format=raw,unit=0,readonly=on,file="$asset_root/root/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd" \
  -drive if=pflash,format=raw,unit=1,file="$asset_root/ovmf-vars.secboot-baseline.fd" \
  -drive if=virtio,format=qcow2,file="$asset_root/arch-guest.qcow2" \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -fw_cfg name=opt/org.boothop/m4-guest,file="$asset_root/fwcfg-marker" \
  -nographic -monitor none -serial stdio
```

Production code and Secure Boot policy were not modified. No host
EFI/NVRAM/ESP, Boot####/BootOrder/BootNext, GRUB, or mkinitcpio operation and
no host reboot occurred. Guest-only BootHop setup and BootNext acceptance
remain **NOT RUN** by this round's explicit scope.

Independent read-only review re-decoded the original shell entry and the
final active Boot0000–Boot0007/BootOrder records, and confirmed their hashes
against this report. Historical boot outcomes are serial-console observations,
not inferred from the final store. Formatting, workspace tests, and
`git diff --check` passed before committing this documentation.
