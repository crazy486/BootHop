#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/boothop-audit-test.XXXXXX")"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/packaging/linux" "$ROOT/crates/fake/tests"
cp "$(cd "$(dirname "$0")/.." && pwd)/check-isolation.sh" "$ROOT/packaging/linux/check-isolation.sh"
cp "$(cd "$(dirname "$0")/.." && pwd)/boothop.desktop" "$ROOT/packaging/linux/boothop.desktop"
cp "$(cd "$(dirname "$0")/.." && pwd)/org.boothop.helper.policy" "$ROOT/packaging/linux/org.boothop.helper.policy"

printf '%s\n' \
  'fn malicious_fixture() {' \
  '    let _ = LinuxStore::open();' \
  '    write_next("BootOrder");' \
  '}' > "$ROOT/crates/fake/tests/evil.rs"
if "$ROOT/packaging/linux/check-isolation.sh" --skip-tree --root "$ROOT" >/dev/null 2>&1; then
  echo "isolation checker accepted malicious fixture" >&2
  exit 1
fi
echo "isolation checker malicious-fixture test: rejected"
