#!/usr/bin/env bash
set -euo pipefail

# All checks run below a temporary staging root.  This script must never touch
# /var/lib/boothop or invoke a package manager.
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/boothop-package-test.XXXXXX")"
trap 'rm -rf "$ROOT"' EXIT
INSTALLER="$(cd "$(dirname "$0")/.." && pwd)/install.sh"
export BOOTHOP_TEST_STAGING=1

INITIAL_PAYLOAD="$ROOT/initial-payload"
mkdir "$INITIAL_PAYLOAD"
printf helper > "$INITIAL_PAYLOAD/boothop-helper"
printf gui > "$INITIAL_PAYLOAD/boothop-gui"

fail() { echo "FAIL: $*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "expected '$2', got '$1'"; }

installer_precreates_layout_first_inspect_reports_missing_record() {
  "$INSTALLER" install --destdir "$ROOT" --payload "$INITIAL_PAYLOAD" --test-staging
  [[ -d "$ROOT/var/lib/boothop" ]] || fail "protected directory missing"
  [[ ! -e "$ROOT/var/lib/boothop/targets.json" ]] || fail "installer wrote a record"
  assert_eq "$(stat -c '%a' "$ROOT/var/lib/boothop")" "700"
  assert_eq "$(stat -c '%a' "$ROOT/var/lib/boothop/operation.lock")" "600"
  local result
  result=$("$INSTALLER" inspect --destdir "$ROOT" --test-staging)
  assert_eq "$result" "Absent"
}

upgrade_preserves_lock_inode() {
  local before after
  before=$(stat -c '%i' "$ROOT/var/lib/boothop/operation.lock")
  printf '%s' '{"version":999}' > "$ROOT/var/lib/boothop/targets.json"
  "$INSTALLER" upgrade --destdir "$ROOT" --payload "$INITIAL_PAYLOAD" --test-staging
  after=$(stat -c '%i' "$ROOT/var/lib/boothop/operation.lock")
  assert_eq "$after" "$before"
  assert_eq "$(<"$ROOT/var/lib/boothop/targets.json")" '{"version":999}'
}

parent_symlinks_are_rejected_without_touching_the_target() {
  local outside="$ROOT/outside"
  mkdir "$outside"
  ln -s "$outside" "$ROOT/escape"
  if "$INSTALLER" install --destdir "$ROOT/escape" --test-staging >/dev/null 2>&1; then
    fail "destination symlink was accepted"
  fi
  [[ ! -e "$outside/var" ]] || fail "destination symlink target was modified"

  mkdir "$ROOT/parent-escape"
  mkdir "$ROOT/parent-outside"
  ln -s "$ROOT/parent-outside" "$ROOT/parent-escape/var"
  if "$INSTALLER" install --destdir "$ROOT/parent-escape" --test-staging >/dev/null 2>&1; then
    fail "parent symlink was accepted"
  fi
  [[ ! -e "$ROOT/parent-outside/lib" ]] || fail "parent symlink target was modified"
}

payload_must_contain_two_regular_binaries() {
  local payload="$ROOT/payload"
  mkdir "$payload"
  if "$INSTALLER" install --destdir "$ROOT" --payload "$payload" --test-staging >/dev/null 2>&1; then
    fail "empty payload was accepted"
  fi
  printf helper > "$payload/boothop-helper"
  ln -s "$payload/boothop-helper" "$payload/boothop-gui"
  if "$INSTALLER" install --destdir "$ROOT" --payload "$payload" --test-staging >/dev/null 2>&1; then
    fail "payload binary symlink was accepted"
  fi
}

test_staging_marker_cannot_be_used_as_install_mode() {
  local unmarked="$ROOT/unmarked"
  mkdir "$unmarked"
  if env -u BOOTHOP_TEST_STAGING "$INSTALLER" install --destdir "$unmarked" \
    --payload "$INITIAL_PAYLOAD" --test-staging >/dev/null 2>&1; then
    fail "unmarked staging bypass was accepted"
  fi
  [[ ! -e "$unmarked/var" ]] || fail "unmarked staging was modified"
}

installer_precreates_layout_first_inspect_reports_missing_record
upgrade_preserves_lock_inode
parent_symlinks_are_rejected_without_touching_the_target
payload_must_contain_two_regular_binaries
test_staging_marker_cannot_be_used_as_install_mode
echo "installer fake tests: 5 passed"
