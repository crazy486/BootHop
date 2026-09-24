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
  gui_tree=$(cargo tree -p boothop-gui --locked)
  if grep -Eiq '(^|[[:space:]])(boothop-helper|boothop-platform)([[:space:]]|$)' <<<"$gui_tree"; then
    echo "boothop-gui must depend only on boothop-protocol, not helper/platform" >&2
    exit 1
  fi
fi

audit_manifest="${BOOTHOP_ISOLATION_AUDIT_MANIFEST:-}"
if [[ -n "$audit_manifest" ]]; then
  cargo run --manifest-path "$audit_manifest" --locked -- --root "$root"
else
  [[ -f "$root/Cargo.toml" ]] || {
    echo "isolation audit requires a workspace Cargo.toml or BOOTHOP_ISOLATION_AUDIT_MANIFEST" >&2
    exit 1
  }
  cargo run -p boothop-isolation-audit --locked -- --root "$root"
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
expected = {
    "allow_any": "auth_admin",
    "allow_inactive": "auth_admin",
    "allow_active": "yes",
}
seen = set()
for defaults in actions[0].find("defaults"):
    if defaults.text and "keep" in defaults.text:
        raise SystemExit("policy must not keep authorization")
    if defaults.tag in expected:
        if defaults.text != expected[defaults.tag]:
            raise SystemExit(
                f"policy {defaults.tag} must be {expected[defaults.tag]}"
            )
        seen.add(defaults.tag)
if seen != set(expected):
    raise SystemExit("policy must declare all three authorization defaults")
PY
echo "Linux dependency and fake-fixture isolation checks passed"
