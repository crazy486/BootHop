#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/boothop-audit-test.XXXXXX")"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/packaging/linux" "$ROOT/crates/fake/tests" "$ROOT/crates/fake/src"
cp "$(cd "$(dirname "$0")/.." && pwd)/check-isolation.sh" "$ROOT/packaging/linux/check-isolation.sh"
cp "$(cd "$(dirname "$0")/.." && pwd)/boothop.desktop" "$ROOT/packaging/linux/boothop.desktop"
cp "$(cd "$(dirname "$0")/.." && pwd)/org.boothop.helper.policy" "$ROOT/packaging/linux/org.boothop.helper.policy"

printf '%s\n' \
  'fn benign_fixture() {}' > "$ROOT/crates/fake/tests/evil.rs"
printf '%s\n' \
  '#[cfg(test)]' \
  'mod first_tests {' \
  '    #[test]' \
  '    fn malicious_cfg_test() {' \
  '        let _ = SystemLinuxCalls::new();' \
  '    }' \
  '}' \
  '#[cfg(test)]' \
  'mod second_tests {' \
  '    #[test]' \
  '    fn benign_cfg_test() {}' \
  '}' > "$ROOT/crates/fake/src/lib.rs"
if "$ROOT/packaging/linux/check-isolation.sh" --skip-tree --root "$ROOT" >/dev/null 2>&1; then
  echo "isolation checker accepted malicious cfg(test) source" >&2
  exit 1
fi
printf '%s\n' \
  'fn malicious_fixture() {' \
  '    let _ = LinuxStore::open();' \
  '    write_next("BootOrder");' \
  '}' > "$ROOT/crates/fake/tests/evil.rs"
if "$ROOT/packaging/linux/check-isolation.sh" --skip-tree --root "$ROOT" >/dev/null 2>&1; then
  echo "isolation checker accepted malicious test fixture" >&2
  exit 1
fi
echo "isolation checker malicious-fixture test: rejected"
