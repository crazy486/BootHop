#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
publisher="$repo_root/packaging/linux/boothop-uki-publish.sh"
tmp_root="$(mktemp -d)"
trap 'rm -rf -- "$tmp_root"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

expect_failure() {
    local label="$1"
    shift
    if BOOTHOP_TESTING=1 BOOTHOP_TEST_ROOT="$fixture_root" "$publisher" "$@" >/dev/null 2>&1; then
        fail "$label unexpectedly succeeded"
    fi
}

new_fixture() {
    fixture_root="$tmp_root/$1"
    esp="$fixture_root/esp"
    mkdir -p "$esp/EFI/BootHop" "$fixture_root/var/lib/boothop" "$fixture_root/build"
    printf kernel > "$fixture_root/build/vmlinuz"
    printf initramfs > "$fixture_root/build/initramfs.img"
    stage="$esp/EFI/BootHop/arch.efi.tmp"
    final="$esp/EFI/BootHop/arch.efi"
    marker="$fixture_root/var/lib/boothop/arch-direct.identity"
}

write_valid_uki() {
    python3 - "$stage" <<'PY'
import struct
import sys

image = bytearray(1024)
image[:2] = b"MZ"
struct.pack_into("<I", image, 0x3C, 0x80)
image[0x80:0x84] = b"PE\0\0"
struct.pack_into("<HHIIIHH", image, 0x84, 0x8664, 4, 0, 0, 0, 240, 0x22)
optional = 0x98
struct.pack_into("<H", image, optional, 0x20B)
struct.pack_into("<H", image, optional + 68, 10)
sections = optional + 240
for index, (name, offset, raw_size) in enumerate(((b".linux", 512, 16), (b".initrd", 528, 16), (b".cmdline", 544, 16), (b".bss", 0, 0))):
    header = sections + index * 40
    image[header:header + len(name)] = name
    struct.pack_into("<I", image, header + 8, raw_size)
    struct.pack_into("<I", image, header + 12, offset)
    struct.pack_into("<I", image, header + 16, raw_size)
    struct.pack_into("<I", image, header + 20, offset)
    if raw_size:
        image[offset:offset + raw_size] = bytes([index + 1]) * raw_size
with open(sys.argv[1], "wb") as output:
    output.write(image[:560])
PY
}

write_marker() {
    printf 'BOOTHOP_ARCH_V1\nboot_id=1234\noption_sha256=%064d\npath=EFI/BootHop/arch.efi\n' 0 > "$marker"
    chmod 600 "$marker"
}

run_publisher() {
    local mode="$1"
    local output="$2"
    BOOTHOP_TESTING=1 BOOTHOP_TEST_ROOT="$fixture_root" "$publisher" \
        "$mode" "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$output"
}

# Invalid and truncated images fail before any final path is created.
new_fixture invalid-uki
printf 'MZ' > "$stage"
expect_failure 'truncated UKI' --initial "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ ! -e "$final" ]] || fail 'truncated UKI created the final path'

new_fixture invalid-pe
printf 'not an executable' > "$stage"
expect_failure 'invalid UKI' --initial "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"

# Initial mode requires both final and marker to be absent.
new_fixture initial-existing-final
write_valid_uki
printf prior > "$final"
expect_failure 'initial mode with final file' --initial "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ "$(cat "$final")" == prior ]] || fail 'initial mode changed a pre-existing final file'

new_fixture initial-existing-marker
write_valid_uki
write_marker
expect_failure 'initial mode with marker' --initial "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ -f "$marker" && ! -e "$final" ]] || fail 'initial mode changed marker or created a final UKI'

new_fixture initial-success
write_valid_uki
run_publisher --initial "$stage"
[[ -f "$final" && ! -e "$stage" ]] || fail 'initial mode did not rename the staged UKI'

# An absent or malformed marker blocks updates and keeps the old artifact intact.
new_fixture update-absent-marker
write_valid_uki
printf old-final > "$final"
expect_failure 'update without marker' --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ "$(cat "$final")" == old-final ]] || fail 'missing marker changed the old final UKI'

new_fixture update-corrupt-marker
write_valid_uki
printf old-final > "$final"
printf 'foreign marker\n' > "$marker"
chmod 600 "$marker"
expect_failure 'update with corrupt/foreign marker' --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ "$(cat "$final")" == old-final ]] || fail 'corrupt marker changed the old final UKI'

new_fixture update-foreign-marker
write_valid_uki
printf old-final > "$final"
printf 'owned elsewhere\n' > "$fixture_root/foreign-marker"
chmod 600 "$fixture_root/foreign-marker"
ln -s "$fixture_root/foreign-marker" "$marker"
expect_failure 'update with foreign marker symlink' --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ "$(cat "$final")" == old-final ]] || fail 'foreign marker changed the old final UKI'

new_fixture update-wrong-marker-mode
write_valid_uki
printf old-final > "$final"
write_marker
chmod 644 "$marker"
expect_failure 'update with writable marker' --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ "$(cat "$final")" == old-final ]] || fail 'writable marker changed the old final UKI'

new_fixture update-success
write_valid_uki
printf old-final > "$final"
write_marker
run_publisher --update "$stage"
[[ -f "$final" && ! -e "$stage" ]] || fail 'update mode did not rename the staged UKI'
python3 - "$final" <<'PY'
import sys
with open(sys.argv[1], "rb") as image:
    data = image.read()
assert data[:2] == b"MZ" and len(data) == 560
PY

# Hook calls without the third UKI argument cannot consume stale staging residue.
new_fixture stale-stage
write_valid_uki
printf old-final > "$final"
write_marker
BOOTHOP_TESTING=1 BOOTHOP_TEST_ROOT="$fixture_root" "$publisher" \
    --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img"
[[ "$(cat "$final")" == old-final ]] || fail 'stale staging residue replaced the old final UKI'

# Any failure during stage validation leaves the previous final artifact intact.
new_fixture failed-staging
printf 'truncated' > "$stage"
printf old-final > "$final"
write_marker
expect_failure 'failed stage validation' --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ "$(cat "$final")" == old-final ]] || fail 'failed staging replaced the old final UKI'

# The third hook argument must name the single fixed output; all path components are checked.
new_fixture wrong-output
write_valid_uki
expect_failure 'wrong output path' --initial "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$esp/EFI/BootHop/other.efi.tmp"

new_fixture symlinked-stage
write_valid_uki
mv "$stage" "$stage.real"
ln -s "$stage.real" "$stage"
expect_failure 'symlinked stage' --initial "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"

new_fixture symlinked-parent
write_valid_uki
mv "$esp/EFI/BootHop" "$esp/EFI/BootHop.real"
ln -s "$esp/EFI/BootHop.real" "$esp/EFI/BootHop"
expect_failure 'symlinked ESP parent' --initial "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"

new_fixture symlinked-final
write_valid_uki
write_marker
printf old-final > "$final.real"
ln -s "$final.real" "$final"
expect_failure 'symlinked final' --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ "$(cat "$final.real")" == old-final ]] || fail 'symlinked final target was changed'

printf 'boothop-uki-publish fixtures passed\n'
