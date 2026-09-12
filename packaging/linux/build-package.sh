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

# CI supplies these exact task-local locations. Defaults keep the script
# usable from this worktree without changing a user's global Cargo install.
export CARGO_HOME="${CARGO_HOME:-$root/.superpowers/sdd/2026-09-08-boothop/tools/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$root/.superpowers/sdd/2026-09-08-boothop/tools/rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

cargo build --workspace --release
"$root/packaging/linux/install.sh" install --destdir "$stage" \
  --payload "$root/target/release" --test-staging

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/crates/core/Cargo.toml" | head -n 1)
printf 'BootHop Linux development package\nversion=%s\ncommit=%s\n' \
  "$version" "$(git -C "$root" rev-parse HEAD)" > "$stage/BOOT-HOP-PACKAGE.txt"
archive="$out/boothop-linux-${version:-unknown}.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner -czf "$archive" -C "$stage" .
printf '%s\n' "$archive"
