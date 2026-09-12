#!/usr/bin/env bash
set -euo pipefail

out=$(mktemp -d "${TMPDIR:-/tmp}/boothop-package-smoke.XXXXXX")
trap 'rm -rf "$out"' EXIT
script=$(cd "$(dirname "$0")" && pwd)
archive=$("$script/build-package.sh" "$out" | tail -n 1)
[[ -f "$archive" ]] || { echo "package archive was not produced" >&2; exit 1; }
listing=$(tar -tzf "$archive")
for required in \
  ./usr/bin/boothop-gui \
  ./usr/lib/boothop/boothop-helper \
  ./usr/share/applications/org.boothop.desktop \
  ./usr/share/polkit-1/actions/org.boothop.helper.policy \
  ./var/lib/boothop/operation.lock; do
  grep -Fxq "$required" <<<"$listing" || { echo "missing package member: $required" >&2; exit 1; }
done
if grep -Fxq './var/lib/boothop/targets.json' <<<"$listing"; then
  echo "package must not contain targets.json" >&2
  exit 1
fi
echo "package smoke: required members present; targets.json absent"
