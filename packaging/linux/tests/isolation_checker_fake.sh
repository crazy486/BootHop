#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/boothop-audit-test.XXXXXX")"
trap 'rm -rf "$ROOT"' EXIT
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
export BOOTHOP_ISOLATION_AUDIT_MANIFEST="$REPO/tools/isolation-audit/Cargo.toml"
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

# Alias and nested-module cases are intentionally more expressive than the
# historical grep checker.  Keep each case in a separate source so a future
# checker cannot accidentally pass only because an earlier failing case stops
# the audit.
printf '%s\n' \
  'use std::{path::Path as P, process as proc};' \
  'use std::process::Command as Spawn;' \
  '' \
  'fn process_alias_bypass() {' \
  '    let _ = Spawn::new("/usr/bin/pkexec").status();' \
  '    let _ = proc::Command::new("/usr/lib/boothop/boothop-helper").output();' \
  '}' \
  '' \
  'fn path_alias_bypass() {' \
  '    let root = "/sys";' \
  '    let path = format!("{root}/firmware/efi/efivars");' \
  '    let _ = P::new(&path);' \
  '    let _ = std::fs::read(path);' \
  '}' > "$ROOT/crates/fake/tests/alias.rs"
if "$ROOT/packaging/linux/check-isolation.sh" --skip-tree --root "$ROOT" >/dev/null 2>&1; then
  echo "isolation checker accepted aliased process/path fixture" >&2
  exit 1
fi

printf '%s\n' \
  'use libc as c;' \
  'use zbus::blocking::connection::Builder as BusBuilder;' \
  '' \
  'fn system_alias_bypass() {' \
  '    let _ = BusBuilder::system().build();' \
  '    let _ = c::syscall(0);' \
  '}' > "$ROOT/crates/fake/tests/system_alias.rs"
if "$ROOT/packaging/linux/check-isolation.sh" --skip-tree --root "$ROOT" >/dev/null 2>&1; then
  echo "isolation checker accepted aliased system fixture" >&2
  exit 1
fi

printf '%s\n' \
  'trait FakePlatform {' \
  '    fn reboot(&mut self);' \
  '}' \
  'struct Fake;' \
  'impl FakePlatform for Fake {' \
  '    fn reboot(&mut self) {}' \
  '}' \
  "fn expected_helper_path() -> &'static str { \"/usr/bin/pkexec\" }" \
  "fn expected_firmware_path() -> &'static str { \"/sys/firmware/efi/efivars\" }" > "$ROOT/crates/fake/tests/safe_dto.rs"
rm "$ROOT/crates/fake/tests/evil.rs" "$ROOT/crates/fake/tests/alias.rs" "$ROOT/crates/fake/tests/system_alias.rs"
printf '%s\n' \
  'fn path_backed_malicious() {' \
  '    let _ = std::process::Command::new("helper").status();' \
  '}' > "$ROOT/crates/fake/src/path_tests.rs"
printf '%s\n' \
  '#[cfg(test)]' \
  'mod first_tests {' \
  '    #[test]' \
  '    fn benign_cfg_test() {}' \
  '}' \
  '#[cfg(test)]' \
  'mod second_tests {' \
  '    #[test]' \
  '    fn another_benign_cfg_test() {}' \
  '}' \
  '#[cfg(any(test, feature = "fixture"))]' \
  '#[path = "path_tests.rs"]' \
  'mod path_tests;' > "$ROOT/crates/fake/src/lib.rs"
if "$ROOT/packaging/linux/check-isolation.sh" --skip-tree --root "$ROOT" >/dev/null 2>&1; then
  echo "isolation checker accepted malicious path-backed cfg(test) source" >&2
  exit 1
fi

printf '%s\n' \
  'trait FakePlatform {' \
  '    fn reboot(&mut self);' \
  '}' \
  'struct Fake;' \
  'impl FakePlatform for Fake {' \
  '    fn reboot(&mut self) {}' \
  '}' \
  "fn expected_path() -> &'static str { \"/sys/firmware/efi/efivars\" }" > "$ROOT/crates/fake/src/path_tests.rs"
if ! "$ROOT/packaging/linux/check-isolation.sh" --skip-tree --root "$ROOT" >/dev/null 2>&1; then
  echo "isolation checker rejected benign DTO/fake-method fixture" >&2
  exit 1
fi

printf '%s\n' \
  'fn malicious_fixture() {' \
  '    let _ = LinuxStore::open();' \
  '    let target = "BootOrder";' \
  '    write_next(target);' \
  '}' > "$ROOT/crates/fake/tests/evil.rs"
if "$ROOT/packaging/linux/check-isolation.sh" --skip-tree --root "$ROOT" >/dev/null 2>&1; then
  echo "isolation checker accepted malicious test fixture" >&2
  exit 1
fi
echo "isolation checker malicious-fixture test: rejected"
