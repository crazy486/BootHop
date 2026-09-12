#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
skip_tree=0
if [[ ${1:-} == --skip-tree ]]; then skip_tree=1; shift; fi
if [[ ${1:-} == --root ]]; then [[ $# -ge 2 ]] || exit 64; root=$2; shift 2; fi
[[ $# -eq 0 ]] || exit 64
cd "$root"
if (( ! skip_tree )); then
  # Do not invent a CARGO_HOME on clean CI runners. Only use the task-local
  # home when it is already present; callers may always provide their own.
  local_cargo="$root/.superpowers/sdd/2026-09-08-boothop/tools/cargo"
  local_rustup="$root/.superpowers/sdd/2026-09-08-boothop/tools/rustup"
  if [[ -z "${CARGO_HOME:-}" && -d "$local_cargo" ]]; then export CARGO_HOME="$local_cargo"; fi
  if [[ -z "${RUSTUP_HOME:-}" && -d "$local_rustup" ]]; then export RUSTUP_HOME="$local_rustup"; fi
  if [[ -n "${CARGO_HOME:-}" ]]; then export PATH="$CARGO_HOME/bin:$PATH"; fi
fi

if (( ! skip_tree )); then
  for package in boothop-core boothop-platform boothop-helper; do
    tree=$(cargo tree -p "$package" --locked)
    if grep -Eiq '(^|[[:space:]])(slint|boothop-gui)([[:space:]]|$)' <<<"$tree"; then
      echo "$package must not depend on GUI/Slint" >&2
      exit 1
    fi
  done
fi

mapfile -t test_files < <(find "$root/crates" -type f -path '*/tests/*' -name '*.rs' -print)
mapfile -t cfg_test_files < <(rg -l '#\[cfg\(test\)\]' "$root/crates" -g '*.rs' || true)
[[ ${#test_files[@]} -gt 0 ]] || { echo "no test fixtures found" >&2; exit 1; }
printf 'Audited test fixtures (%s) and cfg(test) sources (%s)\n' "${#test_files[@]}" "${#cfg_test_files[@]}"
if rg -n 'SystemLinuxCalls|LinuxStore::open|LinuxPlatform::system|SystemProcess::system|production\s*\(|std::process::Command::new|/sys/firmware/efi|zbus::blocking::Connection' "${test_files[@]}"; then
  echo "tests must not construct production adapters or installed helpers" >&2
  exit 1
fi

# A file can contain production code followed by a cfg(test) module. Extract
# only the final cfg(test) section (the last marker is the module under test)
# so production D-Bus types in the same source file are not misclassified.
cfg_extract=$(mktemp "${TMPDIR:-/tmp}/boothop-cfg-audit.XXXXXX")
cfg_code=$(mktemp "${TMPDIR:-/tmp}/boothop-cfg-code.XXXXXX")
trap 'rm -f "$cfg_extract" "$cfg_code"' EXIT
for file in "${cfg_test_files[@]}"; do
  start=$(rg -n '#\[cfg\(test\)\]' "$file" | tail -n 1 | cut -d: -f1)
  [[ -n "$start" ]] || continue
  sed -n "${start},\$p" "$file" >> "$cfg_extract"
done
grep -Ev '^[[:space:]]*//' "$cfg_extract" > "$cfg_code" || true
if [[ -s "$cfg_code" ]] && rg -n 'SystemLinuxCalls|LinuxStore::open|LinuxPlatform::system|SystemProcess::system|production\s*\(|std::process::Command::new|/sys/firmware/efi|zbus::blocking::Connection' "$cfg_code"; then
  echo "cfg(test) sources must not construct production adapters or installed helpers" >&2
  exit 1
fi
if rg -n -U 'Boot(Order|Current)[\s\S]{0,120}(write_next|\.write\(|write\()|(?:write_next|\.write\(|write\()[\s\S]{0,120}Boot(Order|Current)' "${test_files[@]}" "$cfg_extract"; then
  echo "fake write assertions may target BootNext only" >&2
  exit 1
fi
if rg -ni 'pkexec|sudo|runas' packaging/linux/boothop.desktop; then
  echo "desktop launch must not be privileged" >&2
  exit 1
fi
python3 - packaging/linux/org.boothop.helper.policy <<'PY'
import sys
import xml.etree.ElementTree as ET

path = sys.argv[1]
root = ET.parse(path).getroot()
actions = root.findall("action")
if len(actions) != 1 or actions[0].get("id") != "org.boothop.helper":
    raise SystemExit("policy must contain exactly one fixed action")
paths = [node.text for node in actions[0].findall("annotate")
         if node.get("key") == "org.freedesktop.policykit.exec.path"]
if paths != ["/usr/lib/boothop/boothop-helper"]:
    raise SystemExit("policy executable path is not the fixed helper")
PY
echo "Linux dependency and fake-fixture isolation checks passed"
