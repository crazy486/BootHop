# Minimal M4 boot acceptance — 2026-10-04

**M4: PASS.** The requested disposable guest boot sequence passed after the
minimal native metadata fix in `5ab4caf`. No additional boot/update/matrix
testing or real-machine provisioning follows this result.

## Fix and verification

The native metadata read now returns absent when a fixed parent component is
ENOENT, after validating every preceding existing ancestor. Root ownership,
directory type, no symlink, and safe mode checks remain. Other errors propagate.
Strict write callers still require all parents to exist. The change is local
to `arch_setup_native.rs`; the production Secure Boot policy and packaged host
setup fail-closed entry are unchanged.

The missing-parent regression was observed failing before the behavior change
and passing afterward. Three injected tests cover missing parent, existing
trusted parent, and unsafe/symlink parents with non-ENOENT errors. They use
synthetic fixture paths, not protected host paths. A Sol High independent
review approved the production fix before the new guest attempt. Reviewer
cleanup notes were addressed: the unrelated mount fixture edit was reverted,
and the unsafe-mode fixture asserts root ownership to avoid masking that check.

Formatting, workspace tests including the guest feature, Clippy with warnings
denied, Linux isolation, the isolation checker adversarial fixture, installer
fake tests (8 passed), and development package smoke all passed. An initial
isolation check rejected protected path literals in injected tests; those tests
were changed to synthetic paths, with no isolation rule change. A temporary
unrelated mount fixture edit failed its existing test and was restored; the
complete suite then passed. These checks establish code/packaging verification,
not the boot outcome, which comes from the observations below.

## Existing fixture and successful guest setup

The same Arch guest disk and existing `ovmf-vars.secboot-baseline.fd` were used
with the unchanged Secure Boot capable OVMF launcher from
[the stable baseline](minimal-arch-m4-secboot-baseline.md). Neither guest nor
firmware baseline was rebuilt or replaced. Before the attempt, all original
Boot0000–Boot0007 hashes and the complete order `0000,0001,0002,0003,0004,0005,0006,0007`
matched that report, BootNext was absent, and SecureBoot bytes were
`06 00 00 00 00` (disabled).

The updated guest-only binary was transferred with SHA-256
`eb03e9381a7382fa0e7868cdb8bd95523583757846358166699c265b6417cf71`.
The existing publisher was reused. No guest directory workaround was applied.
The one new, post-fix invocation was:

```text
/usr/lib/boothop/boothop-m4-guest-setup --kernel linux --apply
Arch setup completed; created Boot0008
setup exit=0
```

Setup built and published `\EFI\BootHop\arch.efi`, created `Boot0008 BootHop Arch`,
and appended `0008` to the complete original order:
`0000,0001,0002,0003,0004,0005,0006,0007,0008`.
All eight original entry hashes remained unchanged. The identity marker was
present, and the temporary pacman lock was observed released.

## Core boot observations

| Criterion | Result | Evidence |
| --- | --- | --- |
| Normal boot → GRUB | PASS | Initial OVMF Boot0000 startup, visible GNU GRUB menu, then Arch login. |
| Guest-only setup and BootHop entry | PASS | Exit 0; Boot0008 points to the guest ESP's `\EFI\BootHop\arch.efi`. |
| Original Boot0000/BootOrder preserved | PASS | Original eight entry bytes unchanged; new entry appended only at the end; final order unchanged from post-setup. |
| BootNext → UKI → Arch | PASS | Guest `efibootmgr --bootnext 0008` exited 0; OVMF directly started Boot0008 UKI, then Arch Linux, without GRUB/menu input; BootCurrent 0008. |
| BootNext consumed | PASS | BootNext had bytes `07 00 00 00 08 00` before the reboot and was absent after direct UKI boot. |
| Next normal boot → GRUB | PASS | With BootNext absent, second guest reboot displayed the original GRUB menu, then Arch login; BootCurrent 0000. |
| Final BootHop entry | PASS | Same Boot0008 bytes and UKI hash as after setup. |

Boot IDs observed:

- Setup boot: `142c4929-f3c7-4a44-b6d3-236d0f06495a`.
- Direct UKI boot: `b36f7324-c488-4d61-8feb-7336d9c1c0cf`.
- Subsequent GRUB boot: `613320a6-b230-4ae1-a520-bca2f19e7046`.

The direct boot reached Arch Linux (`ID=arch`), kernel `7.2.8-arch1-2`, with
the intended guest root UUID and console command line:
`root=UUID=ae4e46a0-af10-4808-b3e1-94cc7b3e7428 rw console=ttyS0,115200`.
OVMF's direct boot output named `Boot0008 "BootHop Arch"` and
`\EFI\BootHop\arch.efi`; no manual boot selection was made.
The BootNext write was performed with guest efibootmgr to establish firmware
semantics; this acceptance does not claim Windows guest/application coverage.

Key SHA-256 values matched after setup, after UKI boot, and at the final
ordinary boot where queried:

| Artifact | SHA-256 |
| --- | --- |
| Original Boot0000 efivarfs bytes | d4283290d50f8a90927619517c5d6680e1db1d72b55139c766d01e5154fbfbc9 |
| New Boot0008 efivarfs bytes | 3b955d2201e0d0c042fe3345a7672f63c773d467f0b22fe25db837a522363f58 |
| Complete appended BootOrder efivarfs bytes | 7b5b10d1e94796dc6e7093bb96f2f921ac5e45205d2f873c920aa74b7daadeb2 |
| Published UKI (after setup and final boot) | 51b75827becb8b53c42055c73b09dc670901328581967195c0d9c95b3035d3d3 |
| Installed identity (after setup) | 23f34cd025f1b3aaf9980314749d3014d4d85ac3ecdcfbd6ff55597765d533ac |

The final read-only query also rechecked all eight original entry hashes
against the stable baseline. BootNext remained absent. No unknown protected
boot-variable mutation occurred; only the expected new entry, order append,
BootNext write/consumption, and per-boot BootCurrent changes were observed.

## Stop and isolation

The disposable guest was powered off cleanly; the temporary loopback transfer
server was stopped. The final private OVMF store SHA-256 is
`45bf0f35595b23469ab461bccad61b32b07a5b7916365141c0e169e4e8f643ae`.
This final store is already provisioned; do not treat it as a fresh setup fixture.

Host EFI/NVRAM/ESP touched: **NO**. Host Boot####/BootOrder/BootNext,
GRUB, and mkinitcpio changes: **NO**. Host reboot: **NO**.
All boot mutations, mkinitcpio builds, setup execution, and reboots occurred
inside the marked disposable guest. No transaction journal, recovery state
machine, automatic uninstall, or Windows EFI-volume reader was added.
The user-requested minimal M4 boot acceptance is complete; production host
provisioning remains outside this acceptance and its packaged entry fails closed.
