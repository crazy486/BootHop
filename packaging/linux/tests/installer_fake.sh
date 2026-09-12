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

destination_security_checks_are_read_only() {
  local writable="$ROOT/writable-parent"
  "$INSTALLER" check-destdir --destdir "$ROOT" --test-staging >/dev/null \
    || fail "safe staging destination was rejected"
  for alias in /. //; do
    if "$INSTALLER" check-destdir --destdir "$alias" --production >/dev/null 2>&1; then
      fail "live-root alias was accepted: $alias"
    fi
    if "$INSTALLER" check-destdir --destdir "$alias" --test-staging >/dev/null 2>&1; then
      fail "live-root alias was accepted in staging mode: $alias"
    fi
  done
  mkdir "$writable"
  chmod 777 "$writable"
  if "$INSTALLER" check-destdir --destdir "$writable" --production >/dev/null 2>&1; then
    fail "writable production destination was accepted"
  fi
  [[ ! -e "$writable/var" ]] || fail "security check modified writable destination"
}

live_root_opt_in_is_explicit_and_non_root_mutation_is_rejected() {
  "$INSTALLER" check-destdir --destdir / --production --live-root >/dev/null \
    || fail "explicit production live-root check was rejected"

  if "$INSTALLER" check-destdir --destdir / --production >/dev/null 2>&1; then
    fail "bare production live-root destination was accepted"
  fi
  for alias in /. //; do
    if "$INSTALLER" check-destdir --destdir "$alias" --production --live-root >/dev/null 2>&1; then
      fail "live-root alias was accepted: $alias"
    fi
  done
  if "$INSTALLER" check-destdir --destdir / --production --test-staging --live-root >/dev/null 2>&1; then
    fail "live-root test-staging combination was accepted"
  fi
  if "$INSTALLER" check-destdir --destdir "$ROOT" --production --live-root >/dev/null 2>&1; then
    fail "live-root non-root destination was accepted"
  fi

  local fakebin="$ROOT/fake-bin" mutation_log="$ROOT/live-mutation.log"
  mkdir "$fakebin"
  printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ ${1:-} == -u ]]; then echo 1000; else /usr/bin/id "$@"; fi' \
    > "$fakebin/id"
  chmod 755 "$fakebin/id"
  for command in mkdir chmod chown install rm; do
    printf '%s\n' '#!/usr/bin/env bash' \
      "printf '%s\\n' '$command' >> '$mutation_log'" \
      'exit 99' > "$fakebin/$command"
    chmod 755 "$fakebin/$command"
  done
  if PATH="$fakebin:$PATH" "$INSTALLER" install --destdir / --production --live-root \
      --payload "$INITIAL_PAYLOAD" >/dev/null 2>&1; then
    fail "non-root live-root mutation was accepted"
  fi
  [[ ! -e "$mutation_log" ]] || fail "non-root live-root mutation reached a filesystem writer"
}

uninstall_rejects_symlinked_package_parents_before_removal() {
  local dest="$ROOT/uninstall-symlink-usr" outside="$ROOT/uninstall-outside"
  mkdir "$dest" "$outside"
  "$INSTALLER" install --destdir "$dest" --payload "$INITIAL_PAYLOAD" --test-staging
  mkdir -p "$outside/bin" "$outside/lib/boothop" "$outside/share/applications" \
    "$outside/share/polkit-1/actions"
  printf sentinel > "$outside/bin/boothop-gui"
  printf sentinel > "$outside/lib/boothop/boothop-helper"
  printf sentinel > "$outside/share/applications/org.boothop.desktop"
  printf sentinel > "$outside/share/polkit-1/actions/org.boothop.helper.policy"
  mv "$dest/usr" "$dest/usr-real"
  ln -s "$outside" "$dest/usr"
  if "$INSTALLER" uninstall --destdir "$dest" --test-staging >/dev/null 2>&1; then
    fail "uninstall accepted a symlinked usr parent"
  fi
  [[ -e "$outside/bin/boothop-gui" ]] || fail "symlink target GUI was removed"
  [[ -e "$outside/lib/boothop/boothop-helper" ]] || fail "symlink target helper was removed"
  [[ -e "$outside/share/applications/org.boothop.desktop" ]] || fail "symlink target desktop was removed"
  [[ -e "$outside/share/polkit-1/actions/org.boothop.helper.policy" ]] || fail "symlink target policy was removed"

  local deep="$ROOT/uninstall-symlink-deep" deep_outside="$ROOT/uninstall-deep-outside"
  mkdir "$deep" "$deep_outside"
  "$INSTALLER" install --destdir "$deep" --payload "$INITIAL_PAYLOAD" --test-staging
  mkdir -p "$deep_outside/boothop"
  printf sentinel > "$deep_outside/boothop/boothop-helper"
  mv "$deep/usr/lib" "$deep/usr/lib-real"
  ln -s "$deep_outside" "$deep/usr/lib"
  if "$INSTALLER" uninstall --destdir "$deep" --test-staging >/dev/null 2>&1; then
    fail "uninstall accepted a symlinked deep package parent"
  fi
  [[ -e "$deep_outside/boothop/boothop-helper" ]] || fail "deep symlink target helper was removed"

  local missing="$ROOT/uninstall-missing-parent"
  mkdir "$missing"
  "$INSTALLER" install --destdir "$missing" --payload "$INITIAL_PAYLOAD" --test-staging
  rm "$missing/usr/lib/boothop/boothop-helper"
  rmdir "$missing/usr/lib/boothop"
  if "$INSTALLER" uninstall --destdir "$missing" --test-staging >/dev/null 2>&1; then
    fail "uninstall accepted a missing package parent"
  fi
  [[ -f "$missing/var/lib/boothop/operation.lock" ]] || fail "lock was not retained after validation failure"
}

installer_precreates_layout_first_inspect_reports_missing_record
upgrade_preserves_lock_inode
parent_symlinks_are_rejected_without_touching_the_target
payload_must_contain_two_regular_binaries
test_staging_marker_cannot_be_used_as_install_mode
destination_security_checks_are_read_only
live_root_opt_in_is_explicit_and_non_root_mutation_is_rejected
uninstall_rejects_symlinked_package_parents_before_removal
echo "installer fake tests: 8 passed"
