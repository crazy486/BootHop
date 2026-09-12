#!/usr/bin/env bash
set -euo pipefail

# A deliberately small, fail-closed layout installer. Package builders pass a
# private DESTDIR; no command in this file invokes a package manager or configures
# a target. The repository's build path always uses a temporary staging directory.
usage() {
  echo "usage: $0 {install|upgrade|inspect|uninstall} --destdir DIR [--payload DIR] [--test-staging]" >&2
  exit 64
}

[[ $# -ge 3 ]] || usage
action=$1
shift
destdir=
payload=
test_staging=0
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
    *) usage ;;
  esac
done

[[ -n "$destdir" && "$destdir" != "/" ]] || {
  echo "refusing an empty or live-root destination" >&2
  exit 2
}
case "$action" in install|upgrade|inspect|uninstall) ;; *) usage ;; esac

layout="$destdir/var/lib/boothop"
lock="$layout/operation.lock"
record="$layout/targets.json"

die() { echo "boothop installer: $*" >&2; exit 1; }

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

validate_layout() {
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
  mkdir -p "$destdir/var/lib"
  chmod 755 "$destdir/var" "$destdir/var/lib" 2>/dev/null || true
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
  [[ -z "$payload" ]] && return 0
  [[ -d "$payload" ]] || die "payload directory is missing"
  install -d -m 755 "$destdir/usr/bin" "$destdir/usr/lib/boothop" \
    "$destdir/usr/share/applications" "$destdir/usr/share/polkit-1/actions"
  [[ -f "$payload/boothop-gui" ]] && install -m 755 "$payload/boothop-gui" "$destdir/usr/bin/boothop-gui"
  [[ -f "$payload/boothop-helper" ]] && install -m 755 "$payload/boothop-helper" "$destdir/usr/lib/boothop/boothop-helper"
  install -m 644 "$(dirname "$0")/boothop.desktop" "$destdir/usr/share/applications/org.boothop.desktop"
  install -m 644 "$(dirname "$0")/org.boothop.helper.policy" "$destdir/usr/share/polkit-1/actions/org.boothop.helper.policy"
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
    [[ -f "$record" ]] && echo Ready || echo Missing
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
