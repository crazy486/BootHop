#!/usr/bin/env bash
set -euo pipefail

# Build only: this produces a tarball and never installs it. The output
# directory is explicit so a release job cannot accidentally write to /var.
[[ $# -eq 1 ]] || {
  echo "usage: $0 OUTPUT-DIRECTORY" >&2
  exit 64
}
out=$1
[[ "$out" != "/" && -n "$out" ]] || { echo "refusing live root" >&2; exit 2; }
root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$out"
stage=$(mktemp -d "${TMPDIR:-/tmp}/boothop-package-stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT

# In the task worktree these exact local homes are available. On a clean CI
# runner, preserve the toolchain environment supplied by the runner instead.
local_cargo="$root/.superpowers/sdd/2026-09-08-boothop/tools/cargo"
local_rustup="$root/.superpowers/sdd/2026-09-08-boothop/tools/rustup"
if [[ -z "${CARGO_HOME:-}" && -d "$local_cargo" ]]; then export CARGO_HOME="$local_cargo"; fi
if [[ -z "${RUSTUP_HOME:-}" && -d "$local_rustup" ]]; then export RUSTUP_HOME="$local_rustup"; fi
if [[ -n "${CARGO_HOME:-}" ]]; then export PATH="$CARGO_HOME/bin:$PATH"; fi
export BOOTHOP_TEST_STAGING=1

cargo build --workspace --release --locked
"$root/packaging/linux/install.sh" install --destdir "$stage" \
  --payload "$root/target/release" --test-staging

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/crates/core/Cargo.toml" | head -n 1)
printf 'BootHop Linux development package\nversion=%s\ncommit=%s\n' \
  "$version" "$(git -C "$root" rev-parse HEAD)" > "$stage/BOOT-HOP-PACKAGE.txt"
archive="$out/boothop-linux-${version:-unknown}.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner -czf "$archive" -C "$stage" .
printf '%s\n' "$archive"
