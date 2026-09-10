# Task 3 report: canonical identity and shared target validation

## Status

DONE. Implementation and local verification are complete; the manifest remains unchanged/PENDING until the controller's independent review.

## Changes

- Added the pure-memory `canonicalize`, `classify`, and `validate_target` APIs.
- Added public canonical identity components and `TargetRecord`, including ordered structured HD/FilePath/EndEntire nodes and `OpaqueExactV1 { algorithm: Sha256, byte_length, digest }`.
- Revalidated `LoadOption` rather than trusting typed parser output alone:
  - exact active/optional-hidden load attributes and bounded reconstructed outer size;
  - valid description UTF-16;
  - exactly one path, one instance, and HD+FilePath+EndEntire in that order;
  - exact node headers, lengths, raw payloads, and typed/raw consistency;
  - GPT/GUID requirements, nonzero partition fields/signature, and checked geometry;
  - exact absolute UTF-16 file path rules without normalization.
- Hashed every byte of the untouched OptionalData only after structural validation. No load-option-wide hash, trimming, decoding, NUL removal, or BCD extraction was added.
- Pinned the mature RustCrypto `sha2` release exactly at `0.11.0` and updated `Cargo.lock`. The official RustCrypto repository identifies `0.11.0` and Rust 1.85 as its supported release/toolchain floor; this task used Rust 1.98.1:
  - <https://github.com/RustCrypto/hashes/blob/master/sha2/Cargo.toml>
  - <https://docs.rs/crate/sha2/0.11.0>
- Added synthetic-only identity tests for approved fixture relationships, exact SHA-256 vectors (empty and `abc`), deterministic components, binary OptionalData, every specified opaque mutation class, strict GPT/path validation, raw/typed consistency, description/hidden non-identity changes, classification, and target mismatch behavior.
- Corrected the parser-contract status sentence so implementation results remain authoritative in the manifest/controller ledger and later identity work is not marked complete by the research document.
- Added no firmware/platform I/O, privilege, reboot, persistence serialization, enumeration, similar-ID search, or workflow services.

## TDD evidence

All commands used the task-local toolchain:

```text
CARGO_HOME=/home/mani/Projects/BootHop/.worktrees/boothop-sdd/.superpowers/sdd/2026-09-08-boothop/tools/cargo
RUSTUP_HOME=/home/mani/Projects/BootHop/.worktrees/boothop-sdd/.superpowers/sdd/2026-09-08-boothop/tools/rustup
PATH=$CARGO_HOME/bin:$PATH
```

### RED (before production implementation)

Command:

```text
cargo test -p boothop-core --test identity
```

Result: exit 101. Compilation failed with unresolved imports for `Classification`, `TargetRecord`, `canonicalize`, `classify`, and `validate_target`, and missing `Error::UnsupportedFormat` / `Error::IdentityMismatch`. This was the expected failure because the wished-for Task 3 API and error behavior did not exist.

### GREEN (identity + parser)

Command:

```text
cargo test -p boothop-core --test identity --test parse
```

Initial result after implementation: exit 0, 15/15 identity and 35/35 parser tests passed. The run exposed one unused test constant warning; it was removed during self-review. After splitting tests to preserve the brief's exact `opaque_non_utf16_can_register`, `same_buffer_identity_deterministic`, and `opaque_exact_change_rejected` cases, the final full core suite below passed 16 identity tests.

## Final verification

- `cargo fmt --all -- --check` — exit 0, no output.
- `cargo clippy -p boothop-core --all-targets -- -D warnings` — exit 0, no warnings.
- `cargo test -p boothop-core` — exit 0; 16/16 identity and 35/35 parser integration tests passed, with unit and doc-test targets also passing. Output was pristine.
- `git diff --check` — exit 0 before report creation; no whitespace errors.

## Files changed

- `Cargo.lock`
- `crates/core/Cargo.toml`
- `crates/core/src/error.rs`
- `crates/core/src/identity.rs`
- `crates/core/src/lib.rs`
- `crates/core/src/model.rs`
- `crates/core/tests/identity.rs`
- `docs/research/shared-linux-prerequisites.md`
- `.superpowers/sdd/2026-09-08-boothop/task-3-report.md`

## Self-review

- Corrected an early test weakness where several valid GPT changes also changed the signature; each stable GPT field now varies independently from the saved identity.
- Separated valid parsed-field changes (which must produce `IdentityMismatch`) from forged typed/raw inconsistencies and invalid GPT constants (which must produce `UnsupportedFormat`).
- Added an explicit outer `file_path_list_length` mismatch case and literal checks for preserved canonical GPT and path fields.
- Confirmed `classify` delegates to structural canonicalization, and `validate_target` canonicalizes the current option before comparing, so neither name/manual classification nor a matching opaque digest bypasses validity.
- Mutation check: wrong node/order/header/payload, omitted validity checks, changed identity field, partial OptionalData hashing, name-based OS inference, and returning success on mismatch are each covered by at least one synthetic test.
- Confirmed the diff contains no private/raw firmware data and no platform calls.

## Concerns and boundaries

No Task 3 correctness concerns found. Missing-original-ID handling and variable enumeration/attributes are intentionally left to the Task 5 workflow boundary established by the brief; Task 3 exposes only the specified pure identity/validation APIs. Record JSON representation remains Task 4's responsibility.
