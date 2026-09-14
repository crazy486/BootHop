# BootHop Windows Development Handoff

Date: 2026-09-13

## Repository state

- Source branch: `boothop-sdd`
- Product HEAD used for the first real Linux -> Windows Switch: `40f76282c9489ae97d8a3c874a6a0370095c1863`
- Origin: `https://github.com/crazy486/BootHop.git`
- Current milestone tags and peeled commits:
  - `shared-linux-software-verified-2026-09-12` -> `0150f3631d74dd412213d817fcc33baa2f6e24f2`
  - `linux-real-stage2-inspect-verified-2026-09-12` -> `b8b11495110814e67c0ba894a08cce48a4f12566`
  - `linux-real-stage3-configure-verified-2026-09-12` -> `b8b11495110814e67c0ba894a08cce48a4f12566`
  - `linux-real-stage4-preswitch-verified-2026-09-13` -> `40f76282c9489ae97d8a3c874a6a0370095c1863`
- Stage 4 verified tag/commit: `linux-real-stage4-preswitch-verified-2026-09-13` -> `40f76282c9489ae97d8a3c874a6a0370095c1863`.

## Acceptance status

- Shared/Linux software verification: PASS.
- Linux Stage 1 GUI: PASS.
- Linux Stage 2 read-only privileged Inspect: PASS.
- Linux Stage 3 Configure: PASS.
- Linux Stage 4 pre-switch read-only acceptance: PASS.
- Stage 5 production Switch was actually executed. BootNext write/readback and the reboot path occurred, and the user manually confirmed arrival in Windows 11. The single authorized Windows-side evidence run observed stable unchanged `BootOrder=[0000,0003]`, stable `BootCurrent=0000`, and stable BootNext Win32 error 203. Because BootCurrent did not corroborate direct `Boot0003` selection and the firmware API contract does not explicitly guarantee 203 as missing-variable semantics, Stage 5 remains pending and must not be called PASS.
- Windows1W native read evidence is `PASS_WITH_LIMITATION`: real UEFI reads, attributes, shared-parser compatibility, and sequential stability were verified. Firmware type and privilege enable/restore are attested by the reviewed collector control flow rather than direct evidence fields. This releases the Windows1W research gate for future Windows production implementation, but no Windows production work has started.

## Safety state

- Do not repeat the Linux Switch.
- Do not manually clear BootNext.
- Do not change BootOrder.
- Do not use `bcdedit` or `efibootmgr` to repair anything.
- Do not begin Windows -> Linux Switch.
- Windows production work may start only under a new explicit scope; the Windows1W research gate is released with the limitations recorded in `docs/research/windows1w-real-evidence-2026-09-14.md`.

## Windows resume point

Resume in this exact safe order:

1. Verify the clone branch, HEAD, and tags.
2. Read the design, specification, plan, and this handoff.
3. Restore the SDD controller context.
4. Keep Stage 5 pending.
5. Do not repeat the completed one-time Windows1W collector run. Any additional Windows firmware API access requires a new explicit user authorization.

## Remaining gates

- Windows1W is no longer a blocking research gate; its direct-result logging limitations remain tracked for production design.
- Stage 5 Windows-side BootOrder/BootNext closure.
- Windows storage/adapter.
- UAC/helper.
- Windows GUI integration.
- Windows packaging.
- Windows -> Linux real Switch.
- Final bidirectional/cross-platform MVP acceptance.

## Local-only state audit

The ignored progress ledger, Stage 1-5 reports, and private evidence do not clone. Raw UEFI bytes, private captures, sensitive complete device paths, screenshots not already tracked, secrets, and personal data must not enter Git. This tracked handoff is the safe resume summary; detailed evidence remains only on the machine where it was captured (Linux for pre-switch artifacts and Windows for the one authorized Windows1W run).
