#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
export CARGO_HOME="${CARGO_HOME:-$root/.superpowers/sdd/2026-09-08-boothop/tools/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$root/.superpowers/sdd/2026-09-08-boothop/tools/rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

for package in boothop-core boothop-platform boothop-helper; do
  tree=$(cargo tree -p "$package")
  if grep -Eiq '(^|[[:space:]])(slint|boothop-gui)([[:space:]]|$)' <<<"$tree"; then
    echo "$package must not depend on GUI/Slint" >&2
    exit 1
  fi
done

test_files=$(rg --files crates -g '*/tests/*' -g '*.rs' | paste -sd ' ' -)
[[ -n "$test_files" ]] || { echo "no test fixtures found" >&2; exit 1; }
if rg -n 'SystemLinuxCalls|LinuxStore::open|LinuxPlatform::system|SystemProcess::system|production\s*\(' crates/*/tests; then
  echo "tests must not construct production adapters or installed helpers" >&2
  exit 1
fi
if rg -n 'write[^\n]*(BootOrder|BootCurrent)|(?:BootOrder|BootCurrent)[^\n]*write' crates/*/tests; then
  echo "fake write assertions may target BootNext only" >&2
  exit 1
fi
if rg -ni 'pkexec|sudo|runas' packaging/linux/boothop.desktop; then
  echo "desktop launch must not be privileged" >&2
  exit 1
fi
rg -q '/usr/lib/boothop/boothop-helper' packaging/linux/org.boothop.helper.policy || {
  echo "policy must name only the fixed helper" >&2
  exit 1
}
echo "Linux dependency and fake-fixture isolation checks passed"
