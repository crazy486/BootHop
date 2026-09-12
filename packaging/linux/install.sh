#!/usr/bin/env bash
set -euo pipefail

# A deliberately small, fail-closed layout installer. Package builders pass a
# private DESTDIR; no command in this file invokes a package manager or configures
# a target. The repository's build path always uses a temporary staging directory.
usage() {
  echo "usage: $0 {install|upgrade|inspect|uninstall|check-destdir} --destdir DIR [--payload DIR] [--test-staging|--production]" >&2
  exit 64
}

[[ $# -ge 3 ]] || usage
action=$1
shift
destdir=
payload=
test_staging=0
production_check=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --destdir)
      [[ $# -ge 2 ]] || usage
      destdir=$2
      shift 2
      ;;
    --payload)
      [[ $# -ge 2 ]] || usage
      payload=$2
      shift 2
      ;;
    --test-staging)
      test_staging=1
      shift
      ;;
    --production)
      production_check=1
      shift
      ;;
    *) usage ;;
  esac
done

[[ -n "$destdir" && "$destdir" != "/" ]] || {
  echo "refusing an empty or live-root destination" >&2
  exit 2
}
case "$action" in install|upgrade|inspect|uninstall|check-destdir) ;; *) usage ;; esac

die() { echo "boothop installer: $*" >&2; exit 1; }

# Walk every supplied path component without resolving symlinks. A symlink in
# DESTDIR or a package parent is an escape from the intended root.
assert_no_symlink_components() {
  local supplied=$1 absolute component current
  case "$supplied" in
    /*) absolute=$supplied ;;
    *) absolute="$PWD/$supplied" ;;
  esac
  current=/
  local -a components
  IFS=/ read -ra components <<< "${absolute#/}"
  for component in "${components[@]}"; do
    [[ -z "$component" || "$component" == "." ]] && continue
    [[ "$component" != ".." ]] || die "parent traversal is not allowed"
    current="$current/$component"
    [[ ! -L "$current" ]] || die "symlink path component is not allowed: $current"
  done
}

assert_no_symlink_components "$destdir"
[[ -d "$destdir" && ! -L "$destdir" ]] || die "destination must be an existing directory"
canonical_destdir=$(realpath -e -- "$destdir") || die "destination cannot be canonicalized"
[[ "$canonical_destdir" != "/" ]] || die "live root destination is not allowed"
if (( test_staging )); then
  # This escape hatch is exclusively for unprivileged temporary fake tests.
  [[ ${BOOTHOP_TEST_STAGING:-} == 1 && $(id -u) -ne 0 ]] || die "test staging is not a package-install mode"
fi
if (( production_check && test_staging )); then
  die "production and test staging modes are mutually exclusive"
fi
if [[ "$action" == install || "$action" == upgrade ]]; then
  [[ -n "$payload" ]] || die "a complete payload directory is required"
fi

layout="$destdir/var/lib/boothop"
lock="$layout/operation.lock"
record="$layout/targets.json"

validate_trusted_components() {
  local supplied=$1 absolute component current canonical permissions
  canonical=$(realpath -e -- "$supplied") || die "destination cannot be canonicalized"
  [[ "$canonical" != "/" ]] || die "live root destination is not allowed"
  case "$supplied" in
    /*) absolute=$supplied ;;
    *) absolute="$PWD/$supplied" ;;
  esac
  current=/
  local -a components
  IFS=/ read -ra components <<< "${absolute#/}"
  for component in "${components[@]}"; do
    [[ -z "$component" || "$component" == "." ]] && continue
    current="$current/$component"
    [[ -e "$current" && ! -L "$current" ]] || die "destination component is missing"
    [[ $(stat -c '%u:%g' -- "$current") == 0:0 ]] || die "destination component is not root-owned"
    permissions=$(stat -c '%A' -- "$current")
    [[ ${permissions:5:1} != w && ${permissions:8:1} != w ]] || die "destination component is group/other writable"
  done
}

if [[ "$action" == check-destdir ]]; then
  if (( test_staging )); then
    [[ ${BOOTHOP_TEST_STAGING:-} == 1 && $(id -u) -ne 0 ]] || die "test staging is not a package-install mode"
  else
    validate_trusted_components "$destdir"
  fi
  echo valid
  exit 0
fi
if (( ! test_staging )); then
  validate_trusted_components "$destdir"
fi

set_root_owner() {
  (( test_staging )) && return 0
  [[ $(id -u) -eq 0 ]] || die "root ownership requires a privileged package install"
  chown root:root "$1" || die "cannot set root ownership on $1"
}

mode_is() {
  local path=$1 expected=$2
  [[ -e "$path" && ! -L "$path" ]] || die "missing or linked path: $path"
  [[ $(stat -c '%a' -- "$path") == "$expected" ]] || die "unexpected mode on $path"
}

ensure_directory() {
  local path=$1 mode=${2:-755}
  assert_no_symlink_components "$path"
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -d "$path" && ! -L "$path" ]] || die "path is not a directory: $path"
  else
    mkdir "$path" || die "cannot create directory: $path"
    chmod "$mode" "$path" || die "cannot set directory mode: $path"
  fi
}

require_directory() {
  local path=$1
  assert_no_symlink_components "$path"
  [[ -d "$path" && ! -L "$path" ]] || die "directory is missing or linked: $path"
}

validate_layout() {
  require_directory "$destdir/var"
  require_directory "$destdir/var/lib"
  [[ -d "$layout" && ! -L "$layout" ]] || die "protected layout is missing"
  mode_is "$layout" 700
  if (( ! test_staging )); then
    [[ $(stat -c '%u:%g' -- "$layout") == 0:0 ]] || die "layout is not root-owned"
  fi
  [[ -f "$lock" && ! -L "$lock" ]] || die "persistent operation.lock is missing"
  mode_is "$lock" 600
  if (( ! test_staging )); then
    [[ $(stat -c '%u:%g' -- "$lock") == 0:0 ]] || die "operation.lock is not root-owned"
  fi
}

create_layout() {
  [[ ! -e "$layout" && ! -L "$layout" ]] || {
    validate_layout
    return 0
  }
  ensure_directory "$destdir/var"
  ensure_directory "$destdir/var/lib"
  mkdir "$layout"
  chmod 700 "$layout"
  set_root_owner "$layout"

  # noclobber + a separate existence check prevents an upgrade race from
  # truncating a lock another process already created.
  [[ ! -e "$lock" && ! -L "$lock" ]] || die "refusing to replace operation.lock"
  ( umask 077; set -C; : > "$lock" ) || die "cannot create operation.lock"
  chmod 600 "$lock"
  set_root_owner "$lock"
  validate_layout
}

copy_payload() {
  assert_no_symlink_components "$payload"
  [[ -d "$payload" && ! -L "$payload" ]] || die "payload directory is missing"
  for name in boothop-gui boothop-helper; do
    [[ -f "$payload/$name" && ! -L "$payload/$name" ]] || die "payload binary is missing or linked: $name"
  done
  ensure_directory "$destdir/usr"
  ensure_directory "$destdir/usr/bin"
  ensure_directory "$destdir/usr/lib"
  ensure_directory "$destdir/usr/lib/boothop"
  ensure_directory "$destdir/usr/share"
  ensure_directory "$destdir/usr/share/applications"
  ensure_directory "$destdir/usr/share/polkit-1"
  ensure_directory "$destdir/usr/share/polkit-1/actions"
  for name in boothop-gui boothop-helper; do
    local destination
    if [[ "$name" == boothop-gui ]]; then
      destination="$destdir/usr/bin/$name"
    else
      destination="$destdir/usr/lib/boothop/$name"
    fi
    [[ ! -L "$destination" ]] || die "package destination is linked: $destination"
    install -m 755 "$payload/$name" "$destination"
  done
  local desktop="$destdir/usr/share/applications/org.boothop.desktop"
  local policy="$destdir/usr/share/polkit-1/actions/org.boothop.helper.policy"
  [[ ! -L "$desktop" && ! -L "$policy" ]] || die "package metadata destination is linked"
  install -m 644 "$(dirname "$0")/boothop.desktop" "$desktop"
  install -m 644 "$(dirname "$0")/org.boothop.helper.policy" "$policy"
}

case "$action" in
  install)
    if [[ -e "$layout" || -L "$layout" ]]; then
      validate_layout
    else
      create_layout
    fi
    copy_payload
    ;;
  upgrade)
    validate_layout
    copy_payload
    ;;
  inspect)
    validate_layout
    [[ -f "$record" ]] && echo Present || echo Absent
    ;;
  uninstall)
    validate_layout
    # Records and the persistent lock are deliberately retained. Only known
    # package-owned files are removed; unknown files are left for inspection.
    rm -f -- "$destdir/usr/bin/boothop-gui" \
      "$destdir/usr/lib/boothop/boothop-helper" \
      "$destdir/usr/share/applications/org.boothop.desktop" \
      "$destdir/usr/share/polkit-1/actions/org.boothop.helper.policy"
    ;;
esac
