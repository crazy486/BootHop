# BootHop

BootHop is a deliberately conservative boot-target switcher. The repository
currently contains a Linux development build and mock-only tests. It is not a
cross-platform release and does not claim that a machine has booted another OS.

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
- Windows implementation/package and Windows 11 evidence remain outside 11L
  and blocked by the 1W real-machine gate. Linux fake/build success is not
  firmware, renderer, GUI-session, or cross-platform acceptance.

## Ordinary checks

Run from the repository with the task-local Cargo/Rustup toolchain configured:

```sh
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
packaging/linux/check-isolation.sh
packaging/linux/tests/installer_fake.sh
```

These commands must remain fake-only: they do not install a package, write
`/var/lib/boothop`, access firmware variables, call system D-Bus/pkexec, start
the GUI event loop, or reboot. To produce a development tarball, pass an
explicit private output directory to `packaging/linux/build-package.sh`; the
script stages files and prints the archive path without installing it.

## Acceptance and release gates

Read [firmware acceptance](docs/acceptance/firmware.md), [GUI acceptance](docs/acceptance/gui.md),
and [release readiness](docs/acceptance/release.md) before any separately
authorized real-system run. Missing evidence stays **NOT ACCEPTED**; fake tests
and package builds must never be recorded as real firmware or Windows success.
