# Release readiness record

Status: **DEVELOPMENT PACKAGE ONLY — NOT A RELEASE**. This record separates
local build facts from the still-missing signing, installation, GUI and
real firmware evidence.

## Locked inputs

| Item | Value / status |
|---|---|
| BootHop version | `0.1.0` (workspace manifests) |
| Rust toolchain | Exact repository pin `1.98.1` (`rust-toolchain.toml`); CI action ref `dtolnay/rust-toolchain@1.98.1`; dependencies locked by `Cargo.lock` |
| Slint / slint-build | 1.17.1 / 1.17.1; attribution review **not completed** |
| Linux package | tarball build recipe exists; release artifact **not measured** |
| Windows package stage | deterministic non-installing stage and static package/PE gates exist; MSI/installer **not implemented or built** |
| Windows signing | **Unsigned placeholder only; no certificate or release signature** |
| Source/release commit | Record the commit and SHA-256 for each candidate |

The Linux package recipe uses a private staging directory, fixed helper path
`/usr/lib/boothop/boothop-helper`, fixed state path `/var/lib/boothop`, and a
non-privileged desktop entry. It never auto-configures a target. Uninstall
removes known package files but retains the protected record and
`operation.lock`; an unknown record is never overwritten.

The Windows stage uses fixed `Program Files\\BootHop` GUI/helper paths and
`ProgramData\\BootHop` policy metadata, records SHA-256 hashes, architecture,
execution levels, and protocol v2, and writes an explicit `NON-PRODUCTION`
marker. It does not install, mutate ACLs/registry/services/autostart/BCD,
launch either binary, or request firmware/shutdown/reboot. Distribution stays
blocked until an atomic installer, interrupted-upgrade recovery, downgrade
prevention, code signing, and signed-release process are implemented and
verified.

## Release checklist

- [ ] Re-run `cargo test --workspace --locked`, `cargo fmt --check`, and
  `cargo clippy --workspace --all-targets --locked -- -D warnings` in the task-local
  toolchain, and archive complete output.
- [ ] Build the Linux tarball in a clean staging directory; record archive
  SHA-256, compressed/uncompressed bytes, installed file list, and additional
  runtime dependencies. Do not call the package an installed-system result.
- [ ] Keep the compiler pin (`rust-toolchain.toml`) distinct from the GitHub
  Actions action reference: the former selects Rust 1.98.1, while the latter
  selects the action implementation and is not a claim that runner OS or action
  internals are reproducible.
- [ ] Recheck all Slint attribution/license notices against the exact locked
  dependency tree and include them in release materials.
- [ ] Publish a download page with a truthful development/acceptance badge;
  never use a “supported” badge while firmware, GUI, or installation evidence
  is missing.
- [ ] Authorized package install/upgrade/uninstall tests: verify root:root
  0700 state directory, root:root 0600 regular persistent lock, preserved lock
  inode on upgrade, no prewritten `targets.json`, and retention on uninstall.
- [ ] Windows signing certificate, Windows MSI/ACL evidence, and Windows 11
  firmware/GUI runs are **not available** for this task. CI runner execution
  and fake/static package checks are not installation or acceptance evidence.
- [ ] Linux real efivarfs, polkit, logind inhibitor and reboot evidence is
  **not available** for this task; fake tests do not satisfy it.

## Support matrix at this point

| Target | Build | Package/install | GUI | Firmware/reboot | Public support |
|---|---|---|---|---|---|
| Linux development environment | Built by CI | Fake/staging only | Not accepted | Not accepted | No |
| Linux Arch Wayland reference | Code target only | Not installed | Not run | Not run | No |
| Ubuntu 24.04 Wayland/X11 or OVMF | Code/reference only | Not installed | Not run | Not run | No |
| Windows 11 x86-64 | Not implemented in 11L | MSI not built | 1W blocked | 1W blocked | No |

No signature, runner, artifact-size, additional-dependency, or real-machine
field above may be inferred from a successful fake build.
