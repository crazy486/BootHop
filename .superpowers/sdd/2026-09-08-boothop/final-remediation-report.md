# Shared/Linux final remediation

Status: **DONE**

Base: `82a70ee`

This remediation is limited to the two load-bearing findings left by the
scoped re-review. No real installation, root helper, pkexec, system D-Bus,
GUI event loop, efivarfs/firmware, or reboot was run.

## 1. Bounded FlowFailure cause preservation

RED: the oversized mutation fallback always replaced `FlowFailure.cause`
with `ResourceLimit`. An oversized Configure failure whose terminal cause was
`StoreDurabilityUnknown { raw_code: 28 }` therefore lost the durable-state
classification and errno; the same happened to `RebootRejected` and bounded
`PlatformIo` causes.

GREEN: `budgeted_response` now uses a strict bounded cause compactor. It
preserves all fixed-size core error variants and raw codes, preserves
allowlisted fixed operation labels for `PlatformIo`, preserves bounded
residual-read causes, and downgrades recursive `FlowFailure`, unknown
operation strings, and other free-form payloads to `ResourceLimit`. Diagnostics
are still removed, stages are bounded without adding `ResidualPossible`, and
the canonical wire encoder and 64 KiB budget remain unchanged.

Regression coverage includes oversized Configure durability failure (raw
errno preserved and no fabricated residual stage), oversized RebootRejected,
the previous oversized mutation failure, and recursive/nested cause and
residual evidence. All fallback frames are asserted to fit the total 64 KiB
hello-plus-response budget; no replay behavior remains covered by the existing
GUI tests.

Files: `crates/protocol/src/lib.rs`, `crates/helper/tests/protocol.rs`.

## 2. Installer parent and uninstall trust

RED: uninstall could follow a symlinked `usr` or deep package parent and
remove files from its target. Existing production layout validation also did
not apply root ownership and group/other-write checks to pre-existing
`var`/`var/lib` descendants.

GREEN: production directory validation now checks every component of
`destdir/var` and `destdir/var/lib` for directory type, no symlink, root
ownership, and non-group/other-writable mode. A single package-parent-chain
validator covers `usr`, `usr/bin`, `usr/lib`, `usr/lib/boothop`, `usr/share`,
and metadata descendants for install/upgrade/inspect/uninstall. Uninstall
performs that complete check before any `rm`; missing or linked parents fail
closed, retaining `operation.lock` and records. The existing shell root-root
TOCTOU boundary is unchanged.

The temporary-only fake suite now proves both top-level and deep symlink
parents cannot cause outside deletion, and that a missing parent fails closed
while retaining the lock. No root or real path was touched.

Files: `packaging/linux/install.sh`, `packaging/linux/tests/installer_fake.sh`.

## Verification

TDD RED evidence:

```text
oversized mutation/configure/reboot tests: failed because cause decoded as ResourceLimit
installer fake: failed because uninstall accepted a symlinked usr parent
```

Fresh GREEN evidence:

```text
cargo test --workspace --locked --offline       passed
cargo fmt --all -- --check                     passed
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
                                                passed
cargo test -p boothop-helper --test protocol   17 passed, 0 failed
cargo test -p boothop-gui --test controller    39 passed, 0 failed
packaging/linux/tests/installer_fake.sh         7 passed
packaging/linux/check-isolation.sh              passed
packaging/linux/package-smoke.sh                passed
bash -n packaging/linux/*.sh packaging/linux/tests/*.sh
                                                passed
git diff --check                                passed
```

Remaining concerns are unchanged from `final-fix-report.md`: static isolation
audit limits, Slint-owned Winit/zbus dependency, deferred shell TOCTOU, and
unexecuted real Linux/firmware/GUI-session/reboot acceptance gates.
