# Windows real-system acceptance blocker — 2026-09-22

## Stop reason and safe state

- Stop time: `2026-09-22T22:42:34.6198051+08:00`.
- Stop reason: the exact-head production helper is blocked before process entry by the host's enforced Smart App Control policy. Continuing would require a trusted production signature, a different compliant host, or a prohibited security-policy workaround.
- The blocked action was production **Inspect only**. The GUI reported `BeforeSend: Launch`; no helper process started and no firmware API was reached.
- Do not repeat Configure. Do not enter Switch. No BootNext, BootOrder, Boot####, BCD, reboot, shutdown, or security-policy mutation occurred after this blocker.

## Git and artifact checkpoint

- Branch: `boothop-sdd`.
- Code HEAD before this handoff commit: `80f14ea79cb8895401fde4b993e01bfc81bda4c1`.
- Local HEAD and `origin/boothop-sdd` matched before this handoff.
- Commit `80f14ea` fixes the real Configure failure by opening the protected BootHop directory with write capability required by `FlushFileBuffers`; record files remain read-only when opened for inspection.
- Local fmt/check/strict Clippy passed. Executed core/platform tests passed; the remaining local workspace run stopped only when Smart App Control returned Win32 4551 for a newly built GUI cache test executable.
- Exact-head GitHub Actions run `35739158329`: Linux PASS and Windows PASS, including workspace tests, release build, fake package checks, staging, package validation, PE capability audit, provenance generation, and artifact upload.
- Audited artifact ID: `10699159603`; archive SHA-256: `4296db915d9cf9aef1135216f6bfc65599943cd32e514824e0ee74d60542a626`.
- Installed GUI SHA-256: `54ae45854a66bdac603def9303463eb3b742472febcd1ec3011120f0df5852a9`.
- Installed helper SHA-256: `2330c26d6ce55c2f763ad37d2e10a7003fec1ddaa61f6732643d0e3a086cf264`.
- The updater verified the installed hashes and confirmed that the existing protected `targets.json` remained present. Raw protected-record and firmware data remain private and untracked.

## Acceptance chronology and status

1. W0 provisioning completed for the earlier exact `f26faaa` artifact and again for exact `80f14ea`; Program Files artifacts and ProgramData layout were preserved and hash-verified.
2. Production W1 Inspect completed successfully on exact `f26faaa`: GUI → UAC/helper → native read-only firmware path discovered `Boot0000 GRUB` and `Boot0003 Windows Boot Manager`; no BootNext read or firmware write was part of W1.
3. Configure selected the live Linux `Boot0000` candidate. The helper validated and wrote the protected record, then returned `StoreDurabilityUnknown: errno=5` at the final directory flush. The UI correctly prohibited automatic retry and Switch.
4. Inspection of the native store implementation identified a read-only directory handle followed by `FlushFileBuffers`. Commit `80f14ea` supplies the required write-capable directory handle without broadening record reads or firmware capabilities.
5. After exact `80f14ea` CI PASS and installation, the required Inspect-only recovery attempt did not reach UAC/helper. Code Integrity events 3033/3077 identify `VerifiedAndReputableDesktop` / Smart App Control as the blocker for the new unsigned helper hash.

Current verdicts:

- Windows production software: **IMPLEMENTED / SOFTWARE VERIFIED / INTEGRATED**.
- W0 provisioning: **PASS** for exact `80f14ea` artifact identity and layout.
- W1 production Inspect: **PASS on exact `f26faaa`; exact `80f14ea` regression recheck BLOCKED before helper entry by host application control**.
- W2 Configure: **DURABILITY UNKNOWN** for the existing protected record; the code defect is fixed and CI-verified, but the required post-fix Inspect has not run.
- W3 pre-switch, W4 Switch/reboot, W5 Linux post-boot: **NOT STARTED**.
- Linux Stage 5: **PENDING**.
- Windows1W: **PASS_WITH_LIMITATION**.
- Windows → Linux and final bidirectional MVP: **NOT COMPLETE**.

## Blocker evidence and interpretation

- `Get-MpComputerStatus` reported Smart App Control `On`.
- Code Integrity event 3077 named policy `VerifiedAndReputableDesktop`, policy GUID `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`, status `0xc0e90002`, requested signing level 2, validated signing level 1, and the exact installed helper flat SHA-256.
- CI provenance reports both PE files as `NotSigned`. The installed files have no Zone.Identifier stream, so `Unblock-File` is neither relevant nor an acceptable workaround.
- This is a host application-control/signing blocker, not evidence that the durability fix failed. The fix cannot be real-system verified until the helper is permitted to execute normally.

## Exact resume conditions and instructions

Resume only when one of these compliant conditions exists:

1. provide an Authenticode signing path whose certificate and trust chain satisfy the host's normal Smart App Control policy, then produce a new exact-head CI artifact with recorded provenance; or
2. move the exact audited artifact and private acceptance state to a Windows 11 acceptance host whose existing policy normally permits the artifact, without weakening that host's security policy.

Do not disable Smart App Control, alter Code Integrity policy, install a self-signed trust root merely for this test, rename/mutate the binary to seek a different reputation outcome, or use a LOLBin/process-launch bypass.

After a compliant artifact can launch, the first real-system action is exactly one production **Inspect**. If it loads the existing Ready Linux record and live identity matches Boot0000, record the durability-unknown recovery as resolved by explicit read. Only then proceed to the separately gated pre-switch BootNext conflict read. Any unresolved BootNext result, including Win32 203, remains a hard stop before firmware write.

The first recommended command after resume is:

`git fetch origin --tags --prune`

## Quota-pause update — 2026-09-22

- Stop reason: five-hour Codex quota remaining reached 2%, below the authorized 10% graceful-pause threshold. Per the user's latest instruction, **do not shut down this computer**.
- A fresh serialized (`-j1`) release build was attempted under the ignored private tree as a policy-compliant diagnostic. It progressed beyond the previously observed ICU build-script point but was still blocked by Smart App Control error 4551 at the `getrandom` build script. The blocked hash was not retried and no reputation/policy workaround was attempted.
- Commit `9614a4aa12691bc7918055fd35bcffbe037f9293` preserves a failed `ShellExecuteExW` code as `BeforeSend: NativeIo { stage: HelperLaunch, raw_code: ... }` instead of collapsing it to `BeforeSend: Launch`. This retains 4551 for bounded diagnosis and does not retry or send a helper request.
- Local verification for that commit: fmt PASS, GUI check PASS, strict GUI Clippy PASS, and all 48 controller tests PASS.
- Exact-head GitHub Actions run `35744635424`: Linux PASS and Windows PASS, including release/package/capability/provenance gates.
- The installed acceptance artifact remains the hash-verified `80f14ea` candidate. Do not install another unsigned artifact merely to seek a different SAC reputation outcome.
- Current task after resume: obtain a normal trusted Authenticode signing path or a compliant acceptance host. Do not resume real-system Inspect until an exact candidate can start without weakening application-control policy.
