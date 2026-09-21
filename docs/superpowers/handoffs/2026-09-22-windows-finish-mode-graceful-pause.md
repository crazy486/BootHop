# Windows finish-mode graceful pause — 2026-09-22

## Stop reason and time

- Stop reason: 5-hour Codex quota remaining was explicitly reported as 3% (97% used), which is at or below the authorized 10% graceful-pause threshold.
- Stop time: 2026-09-22T00:23:42+08:00.
- No new development, artifact installation, or real-system acceptance step may start after this checkpoint.

## Git checkpoint

- Branch: `boothop-sdd`.
- Local HEAD: `3ca7f0bebd1a4399781d2b27099037f151f47bd9` before this handoff commit.
- `origin/boothop-sdd` and `ls-remote origin refs/heads/boothop-sdd` matched that HEAD before this handoff commit.
- The two coherent implementation checkpoints were committed and pushed normally:
  - `1c57379fb0294f1845102a8753a6a0e20df95ef6` — build a valid named-pipe DACL;
  - `3ca7f0bebd1a4399781d2b27099037f151f47bd9` — make each GUI target the opposite host OS.
- Tracked files were clean before adding this handoff.
- Intentional pre-existing untracked directories remain untouched: `trusted-target-task1/` and `trusted-target-task1-round2/`. They were not committed or pushed.
- Private/ignored SDD evidence remains local and untracked.

## Completed implementation

1. Root-caused the real Windows GUI pre-UAC failure `NativeIo { stage: PipeSecurityBuild, raw_code: 1804 }` to an extra `)` in the generated named-pipe SDDL.
2. Corrected the DACL suffix and strengthened the regression test to require the exact valid SDDL, including the user, SYSTEM, and Administrators ACEs.
3. Found and fixed a second acceptance blocker: the Windows GUI was still hard-coded to configure and switch to Windows. The controller now receives an explicit target OS; Linux targets Windows and Windows targets Linux. GUI labels and confirmation text follow that target.
4. Added a direction-specific controller test proving a Linux-target controller rejects Windows Configure, accepts Linux Configure, and emits Linux Switch.

## Verification

- Local `cargo +1.98.1 fmt --all -- --check`: PASS.
- Local GUI unit/integration state-machine tests: 47 controller tests and all earlier executable GUI tests passed.
- The final `ui_static` executable was built but its execution was blocked by the already documented Windows Smart App Control error 4551; this is an environment BLOCKED result, not a test assertion failure.
- Exact final candidate HEAD `3ca7f0bebd1a4399781d2b27099037f151f47bd9` GitHub Actions run `35623591637`:
  - Linux job: PASS;
  - Windows job: PASS, including fmt, clippy, workspace tests, release build, package/fake checks, capability audit, provenance generation, and acceptance-artifact upload.

## Incomplete work and current installed state

- The audited Windows acceptance artifact from run `35623591637` has not been downloaded or installed because the quota stop condition triggered immediately after CI completion.
- `C:\Program Files\BootHop` still contains the previously audited artifact from commit `55188b2e7815bcdb7c3d1ee117e4ff8b5347181d`.
- The production GUI from that older artifact was still open at checkpoint time and must be closed before shutdown/artifact replacement.
- No W1 production Inspect completed. No Configure, pre-switch, Switch, BootNext write, or reboot occurred.

## Review findings and blockers

- The invalid DACL and wrong-direction GUI target were genuine correctness blockers and are fixed in the final candidate HEAD.
- Remaining blocker is operational only: obtain and install the exact audited artifact for `3ca7f0b`, then resume real-system acceptance.
- Local SAC 4551 remains an environment limitation. Do not modify or bypass Windows security policy.

## Exact resume instructions

1. Start in `C:\Users\Solis\BootHop` and run `git fetch origin --tags --prune`.
2. Verify `git rev-parse HEAD`, `git rev-parse origin/boothop-sdd`, and `git ls-remote origin refs/heads/boothop-sdd` all identify the post-handoff tip whose parent candidate is `3ca7f0bebd1a4399781d2b27099037f151f47bd9`; verify tracked status is clean and preserve both untracked trusted-target directories.
3. Reconfirm GitHub Actions run `35623591637` has Linux and Windows PASS for exact candidate `3ca7f0b`.
4. Download the audited artifact named `boothop-windows-acceptance-3ca7f0bebd1a4399781d2b27099037f151f47bd9`, verify `provenance.json`, package checks, SHA-256, sizes, architecture, and source commit, and store it only under the existing ignored private artifact structure.
5. Ensure no `boothop-gui` or `boothop-helper` process is running. Use the existing ignored `private/w1/update-installed-artifacts.ps1` in one elevated session to replace only the exact Program Files artifacts and record private evidence. Re-verify installed hashes and confirm `targets.json` remains absent.
6. Launch the newly installed GUI. Confirm the UI says `重启进入 Linux` and `我确认所选目标是 Linux` before any Configure action.
7. Run production Inspect with UAC and collect private evidence. If Inspect succeeds, identify the live Linux candidate; do not Configure an uncertain or Windows candidate.
8. Continue Configure → pre-switch validation → Switch only if every existing safety gate passes. Stop immediately on identity mismatch, BootNext conflict/unresolved read semantics, failed readback, or unsafe rollback conditions.

The first recommended command after resume is:

`git fetch origin --tags --prune`

## Real-system safety gates at pause

- No firmware API call was made during this development turn.
- No privilege adjustment or UAC prompt was triggered during this development turn.
- No SetFirmwareEnvironmentVariable call, BootNext/BootOrder/Boot#### write, BCD mutation, Configure, Switch, reboot, or security-policy change occurred.
- Firmware mutation remains limited to the previously authorized production Switch path only after successful Inspect/Configure/pre-switch gates; none of those gates has been reached with the fixed artifact.
