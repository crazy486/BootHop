# BootHop

BootHop is a deliberately conservative boot-target switcher. The repository
currently contains a Linux development build, integrated Windows production
software with compile/static/fake verification, and mock/fake tests. It is not
a cross-platform release and does not claim that a machine has booted another
OS.

## Current status

- Linux packaging, static test-isolation checks, and explicit acceptance
  run-sheets are included in Task 11L.
- The package installer uses fixed `/usr/lib/boothop/boothop-helper` and
  `/var/lib/boothop` locations. It precreates a root-owned 0700 state directory
  and persistent root-owned 0600 `operation.lock` during a real package install;
  the fake tests use only a temporary staging directory.
- Install/upgrade never configure a target or overwrite an unknown record;
  uninstall retains the record and lock. The desktop entry is not privileged;
  policy authentication is restricted to the fixed helper.
- Windows production source now has a deterministic, non-installing package
  stage under `packaging/windows`. It records fixed Program Files/ProgramData
  layout metadata, protocol-v2 binary hashes, execution-level manifests, and
  an explicit `NON-PRODUCTION` marker. It never installs, changes ACLs,
  registry/services/autostart/BCD, launches a binary, touches firmware, or
  requests shutdown/reboot. Windows1W research remains separate from W1--W5;
  Linux Stage 5 and Windows real-system acceptance remain pending.

## Ordinary checks

Run from the repository with the task-local Cargo/Rustup toolchain configured:

```sh
cargo test --workspace --locked
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
packaging/linux/check-isolation.sh
packaging/linux/tests/installer_fake.sh
pwsh -NoProfile -File packaging/windows/tests/package_fake.ps1
```

These commands must remain fake-only: they do not install a package, write
`/var/lib/boothop`, access firmware variables, call system D-Bus/pkexec, start
the GUI event loop, or reboot. To produce a development tarball, pass an
explicit private output directory to `packaging/linux/build-package.sh`; the
script stages files and prints the archive path without installing it.

## Acceptance and release gates

Read [Windows real-system acceptance](docs/acceptance/windows-real-system.md),
[firmware acceptance](docs/acceptance/firmware.md),
[GUI acceptance](docs/acceptance/gui.md), and
[release readiness](docs/acceptance/release.md) before any separately
authorized real-system run. Missing evidence stays **NOT ACCEPTED**; fake tests
and package builds must never be recorded as real firmware or Windows success.

On Windows CI, the ordered gate is format, clippy, workspace tests, release
build, fake package tests, non-installing stage, package check, and source/PE
capability audit. `dumpbin.exe` is resolved through `vswhere.exe`; missing
`dumpbin` or either produced PE fails the job. The job never executes BootHop
binaries or performs UAC, ACL, firmware, BCD, service, shutdown, or reboot
actions.
