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
    mkdir -p "$esp/EFI/BootHop" "$fixture_root/var/lib/boothop" "$fixture_root/build" "$fixture_root/run/lock"
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

image = bytearray(3072)
image[:2] = b"MZ"
struct.pack_into("<I", image, 0x3C, 0x80)
image[0x80:0x84] = b"PE\0\0"
struct.pack_into("<HHIIIHH", image, 0x84, 0x8664, 5, 0, 0, 0, 240, 0x22)
optional = 0x98
struct.pack_into("<H", image, optional, 0x20B)
struct.pack_into("<I", image, optional + 16, 0x1000)
struct.pack_into("<Q", image, optional + 24, 0x100000)
struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
struct.pack_into("<II", image, optional + 56, 0x6000, 0x400)
struct.pack_into("<H", image, optional + 68, 10)
struct.pack_into("<I", image, optional + 108, 16)
sections = optional + 240
for index, (name, virtual_address, offset, raw_size, characteristics) in enumerate((
    (b".text", 0x1000, 1024, 512, 0x60000020),
    (b".linux", 0x2000, 1536, 512, 0x40000040),
    (b".initrd", 0x3000, 2048, 512, 0x40000040),
    (b".cmdline", 0x4000, 2560, 512, 0x40000040),
    (b".bss", 0x5000, 0, 0, 0xC0000080),
)):
    header = sections + index * 40
    image[header:header + len(name)] = name
    struct.pack_into("<II", image, header + 8, 16, virtual_address)
    struct.pack_into("<I", image, header + 16, raw_size)
    struct.pack_into("<I", image, header + 20, offset)
    struct.pack_into("<I", image, header + 36, characteristics)
    if raw_size:
        image[offset:offset + raw_size] = bytes([index + 1]) * raw_size
with open(sys.argv[1], "wb") as output:
    output.write(image)
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

# Another publisher holding the fixed lock must prevent this invocation from
# validating and replacing the staged/final files concurrently.
new_fixture concurrent-publisher
write_valid_uki
printf old-final > "$final"
write_marker
lock_path="$fixture_root/run/boothop-uki-publish.lock"
: > "$lock_path"
chmod 600 "$lock_path"
(
    flock --exclusive 9
    touch "$fixture_root/lock-held"
    sleep 5
) 9>>"$lock_path" &
locker_pid=$!
for _ in {1..100}; do
    [[ -e "$fixture_root/lock-held" ]] && break
    sleep 0.01
done
[[ -e "$fixture_root/lock-held" ]] || fail 'could not establish concurrent publisher lock'
expect_failure 'concurrent publisher lock' --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
kill "$locker_pid" 2>/dev/null || true
wait "$locker_pid" 2>/dev/null || true
[[ "$(cat "$final")" == old-final && -f "$stage" ]] || fail 'locked publication changed either UKI path'

# Invalid and truncated images fail before any final path is created.
new_fixture invalid-uki
printf 'MZ' > "$stage"
expect_failure 'truncated UKI' --initial "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ ! -e "$final" ]] || fail 'truncated UKI created the final path'

new_fixture invalid-pe
printf 'not an executable' > "$stage"
expect_failure 'invalid UKI' --initial "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"

new_fixture zero-entrypoint
write_valid_uki
python3 - "$stage" <<'PY'
import sys
with open(sys.argv[1], "r+b") as image:
    image.seek(0x98 + 16)
    image.write(bytes(4))
PY
printf old-final > "$final"
write_marker
expect_failure 'zero UKI entry point' --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ "$(cat "$final")" == old-final ]] || fail 'zero entry point replaced the old final UKI'

new_fixture zero-image-size
write_valid_uki
python3 - "$stage" <<'PY'
import sys
with open(sys.argv[1], "r+b") as image:
    image.seek(0x98 + 56)
    image.write(bytes(4))
PY
printf old-final > "$final"
write_marker
expect_failure 'zero UKI image size' --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ "$(cat "$final")" == old-final ]] || fail 'zero image size replaced the old final UKI'

new_fixture short-optional-header
write_valid_uki
python3 - "$stage" <<'PY'
import struct
import sys

path = sys.argv[1]
with open(path, "r+b") as image:
    data = bytearray(image.read())
    old_section_table = 0x98 + 240
    new_section_table = 0x98 + 72
    table = bytes(data[old_section_table:old_section_table + 5 * 40])
    data[new_section_table:new_section_table + len(table)] = table
    struct.pack_into("<H", data, 0x84 + 20, 72)
    image.seek(0)
    image.write(data)
    image.truncate()
PY
printf old-final > "$final"
write_marker
expect_failure 'short PE32+ fixed optional header' --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ "$(cat "$final")" == old-final ]] || fail 'short optional header replaced the old final UKI'

new_fixture non-executable-entrypoint
write_valid_uki
python3 - "$stage" <<'PY'
import struct
import sys
with open(sys.argv[1], "r+b") as image:
    image.seek(0x98 + 240 + 36)
    image.write(struct.pack("<I", 0x40000040))
PY
printf old-final > "$final"
write_marker
expect_failure 'entry point outside executable section' --update "$stage" "$fixture_root/build/vmlinuz" "$fixture_root/build/initramfs.img" "$stage"
[[ "$(cat "$final")" == old-final ]] || fail 'non-executable entry point replaced the old final UKI'

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
assert data[:2] == b"MZ" and len(data) == 3072
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
