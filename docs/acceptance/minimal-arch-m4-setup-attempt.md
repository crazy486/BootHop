# M4 guest setup attempt — 2026-10-04

**M4: BLOCKED at InitialState.** The existing guest-only setup was executed
once and failed before entry allocation or setup configuration writes. The
guest was stopped after recording read-only evidence. No retry, rollback,
BootNext write, or post-setup boot test occurred.

## Fixture and pre-setup checks

The run reused the existing Arch qcow2 and
`/home/mani/.cache/boothop-m4/ovmf-vars.secboot-baseline.fd`, with the same
Secure Boot capable OVMF/Q35/SMM launcher documented in
[the stable baseline report](minimal-arch-m4-secboot-baseline.md).
The variable store matched the recorded SHA-256 before launch:
`d164dff834149e3375f92ee910dfa74c7e84708fc54dc87cffe7bf563ed18f9b`.
Nothing was rebuilt, redownloaded, reseeded, or replaced.

The ordinary boot again showed OVMF starting `Boot0000 "Arch GRUB"`, a
visible GNU GRUB menu, and Arch 7.2.8 login. Guest boot ID:
`646976c2-1b95-4ada-a516-cfaf54935780`. Before setup:

- `BootCurrent: 0000`.
- Complete `BootOrder: 0000,0001,0002,0003,0004,0005,0006,0007`.
- All Boot0000–Boot0007 hashes and the BootOrder hash matched the stable report.
- `SecureBoot` bytes: `06 00 00 00 00` (attributes 6, disabled payload 0).
- BootNext absent.
- Existing guest-only binary SHA-256:
  `4181e8ee9f05de196d7cc00824c48a4657adf134678c1cda10e89c87c71674ee`.
- Existing publisher SHA-256:
  `c73c34f8172a58bf032833e864dd4780b4a88d3b2566fb2ec8a0be07e0deb09a`.

## Single setup invocation and failure

Inside the disposable guest only:

```text
/usr/lib/boothop/boothop-m4-guest-setup --kernel linux --apply
Arch setup failed: SetupFailure {
    stage: InitialState,
    problem: Backend,
    candidate_id: None,
    observed: SetupObservations {
        preset_stanza: Known(None),
        hook_exact: Known(false),
        artifact_present: Unknown,
        entry_exact: Known(None),
        boot_order: Known([BootId(0), BootId(1), BootId(2), BootId(3),
                           BootId(4), BootId(5), BootId(6), BootId(7)]),
        boot_next: Known(None)
    }
}
setup exit=1
```

Read-only post-failure queries confirmed all eight original entry hashes and
the complete BootOrder were unchanged. Boot0000 retained SHA-256
`d4283290d50f8a90927619517c5d6680e1db1d72b55139c766d01e5154fbfbc9`;
BootOrder retained
`3024e0cd4128a9fe2ac83be06670aea230a042e727ee82536b0b6468916c3793`.
No BootHop entry or BootNext was listed. Guest filesystem observations:

- `/boot/EFI` exists and is a root-owned directory.
- `/boot/EFI/BootHop` and `/boot/EFI/BootHop/arch.efi` are absent.
- `/var/lib/boothop/arch-direct.identity` is absent.
- `/etc/initcpio/post/boothop-uki` is absent.

Source tracing is consistent with the missing parent being the blocker:
`verify_initial_absence` requests metadata for the final UKI path;
`file_metadata` first calls `check_parent_chain`, which propagates a missing
parent error before its leaf-file `NotFound` → absence handling. That produces
a Backend failure and an unknown artifact observation for a fresh guest
without `/boot/EFI/BootHop`. No fix or guest directory workaround was attempted
in this stop-on-failure run. `NativeArchCalls::open` acquires temporary guest
operation/pacman locks, so the setup invocation is not described as purely
read-only; InitialState precedes setup configuration and EFI writes.

## Acceptance status

| Check | Result |
| --- | --- |
| Existing QEMU/OVMF baseline | READY; unchanged protected boot variables observed before and after attempt |
| Normal boot → GRUB → Arch | PASS |
| Guest-only setup | FAIL — exit 1, InitialState/Backend |
| BootHop Boot#### created | NOT RUN — stopped before allocation |
| BootOrder append-only and original entries preserved after successful setup | NOT RUN — setup failed; observed original order remained unchanged |
| BootNext → UKI → Arch | NOT RUN |
| BootNext consumed | NOT RUN |
| Next normal boot → GRUB | NOT RUN |
| Final post-BootNext Boot0000/BootOrder/BootHop check | NOT RUN |

The guest was powered off cleanly. Its private variable store's final SHA-256
was `e0ba7133a536968c4965f9ec247715b319a92a8f055febeab086a809e65c7c0f`;
this is not a claim that unrelated firmware variable bytes never change on
ordinary boots. No unknown Boot####/BootOrder mutation was observed.
No host EFI/NVRAM/ESP, Boot####/BootOrder/BootNext, GRUB, or mkinitcpio
operation occurred, and the host was not rebooted. Production code was not
modified; this round contains acceptance documentation only.

Independent read-only review confirmed the source trace and reconstructed
all active original boot variables from the final private store; their hashes
still match the stable baseline. Native backend Drop attempts to sync and
remove its temporary pacman lock; cleanup was not separately queried in the
guest after failure. Historical SecureBoot bytes and the visible GRUB boot
are serial-console observations, not inferred from the final variable store.
