#!/usr/bin/env bash
set -euo pipefail

# All checks run below a temporary staging root.  This script must never touch
# /var/lib/boothop or invoke a package manager.
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/boothop-package-test.XXXXXX")"
trap 'rm -rf "$ROOT"' EXIT
INSTALLER="$(cd "$(dirname "$0")/.." && pwd)/install.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "expected '$2', got '$1'"; }

installer_precreates_layout_first_inspect_reports_missing_record() {
  "$INSTALLER" install --destdir "$ROOT" --test-staging
  [[ -d "$ROOT/var/lib/boothop" ]] || fail "protected directory missing"
  [[ ! -e "$ROOT/var/lib/boothop/targets.json" ]] || fail "installer wrote a record"
  assert_eq "$(stat -c '%a' "$ROOT/var/lib/boothop")" "700"
  assert_eq "$(stat -c '%a' "$ROOT/var/lib/boothop/operation.lock")" "600"
  local result
  result=$("$INSTALLER" inspect --destdir "$ROOT" --test-staging)
  assert_eq "$result" "Missing"
}

upgrade_preserves_lock_inode() {
  local before after
  before=$(stat -c '%i' "$ROOT/var/lib/boothop/operation.lock")
  printf '%s' '{"version":999}' > "$ROOT/var/lib/boothop/targets.json"
  "$INSTALLER" upgrade --destdir "$ROOT" --test-staging
  after=$(stat -c '%i' "$ROOT/var/lib/boothop/operation.lock")
  assert_eq "$after" "$before"
  assert_eq "$(<"$ROOT/var/lib/boothop/targets.json")" '{"version":999}'
}

installer_precreates_layout_first_inspect_reports_missing_record
upgrade_preserves_lock_inode
echo "installer fake tests: 2 passed"
