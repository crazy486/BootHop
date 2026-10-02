#!/usr/bin/env bash
set -euo pipefail

out=$(mktemp -d "${TMPDIR:-/tmp}/boothop-package-smoke.XXXXXX")
trap 'rm -rf "$out"' EXIT
script=$(cd "$(dirname "$0")" && pwd)
archive=$("$script/build-package.sh" "$out" | tail -n 1)
[[ -f "$archive" ]] || { echo "package archive was not produced" >&2; exit 1; }
listing=$(tar -tzf "$archive")
if grep -Eq 'boothop-m4-guest-setup|m4-guest' <<<"$listing"; then
  echo "package must not contain the M4 guest setup binary or marker assets" >&2
  exit 1
fi
for required in \
  ./usr/bin/boothop-gui \
  ./usr/lib/boothop/boothop-helper \
  ./usr/lib/boothop/boothop-arch-setup \
  ./usr/lib/boothop/boothop-uki-publish \
  ./usr/share/applications/org.boothop.desktop \
  ./usr/share/polkit-1/actions/org.boothop.helper.policy \
  ./var/lib/boothop/operation.lock; do
  grep -Fxq "$required" <<<"$listing" || { echo "missing package member: $required" >&2; exit 1; }
done
details=$(tar -tvzf "$archive")
grep -Eq '^-rwx------ 0/0 .* ./usr/lib/boothop/boothop-arch-setup$' <<<"$details" || {
  echo "setup binary must be root-owned and mode 700" >&2
  exit 1
}
grep -Eq '^-rwxr-xr-x 0/0 .* ./usr/lib/boothop/boothop-uki-publish$' <<<"$details" || {
  echo "publisher must be root-owned and mode 755" >&2
  exit 1
}
policies=$(grep -E '^\./usr/share/polkit-1/actions/.*\.policy$' <<<"$listing")
if [[ "$policies" != './usr/share/polkit-1/actions/org.boothop.helper.policy' ]]; then
  echo "package contains an unexpected polkit action" >&2
  exit 1
fi
if grep -Fxq './var/lib/boothop/targets.json' <<<"$listing"; then
  echo "package must not contain targets.json" >&2
  exit 1
fi
echo "package smoke: required members present; targets.json absent"
