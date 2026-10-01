#!/usr/bin/env bash
set -euo pipefail

die() {
    printf 'boothop-uki-publish: %s\n' "$1" >&2
    exit 1
}

if [[ "${BOOTHOP_TESTING:-}" == 1 ]]; then
    [[ "$EUID" != 0 ]] || die 'test fixture mode is unavailable to root'
    [[ -n "${BOOTHOP_TEST_ROOT:-}" && -d "$BOOTHOP_TEST_ROOT" ]] || die 'test fixture root is missing'
    fixture_root="$(cd -- "$BOOTHOP_TEST_ROOT" && pwd -P)"
    marker_path="$fixture_root/var/lib/boothop/arch-direct.identity"
    lock_path="$fixture_root/run/boothop-uki-publish.lock"
    expected_marker_uid="$(id -u)"
else
    [[ -z "${BOOTHOP_TEST_ROOT:-}" ]] || die 'fixture paths are unavailable outside fixture mode'
    [[ "$EUID" == 0 ]] || die 'publisher must run as root'
    marker_path='/var/lib/boothop/arch-direct.identity'
    lock_path='/run/boothop-uki-publish.lock'
    expected_marker_uid=0
fi

[[ "$#" -ge 4 && "$#" -le 5 ]] || die 'expected mode, planned stage, kernel, initramfs, and optional UKI'
mode="$1"
expected_stage="$2"
kernel="$3"
initramfs="$4"
uki="${5:-}"
case "$mode" in
    --initial|--update) ;;
    *) die 'unsupported publication mode' ;;
esac

# mkinitcpio runs post hooks for every preset. Non-UKI presets have no third argument.
[[ -n "$uki" ]] || exit 0

[[ -f "$kernel" && ! -L "$kernel" ]] || die 'kernel argument is not a regular file'
[[ -f "$initramfs" && ! -L "$initramfs" ]] || die 'initramfs argument is not a regular file'
[[ "$expected_stage" == "$uki" ]] || die 'mkinitcpio output does not match the planned BootHop stage'
[[ "$uki" == /* ]] || die 'UKI output path is not absolute'
case "$uki" in
    *//*|*'/./'*|*'/../'*) die 'UKI output path is not normalized' ;;
esac

stage_path="$uki"
[[ "${stage_path##*/}" == 'arch.efi.tmp' ]] || die 'UKI output is not the fixed BootHop stage path'
uki_directory="${stage_path%/*}"
[[ "${uki_directory##*/}" == 'BootHop' ]] || die 'UKI output is outside EFI/BootHop'
efi_directory="${uki_directory%/*}"
[[ "${efi_directory##*/}" == 'EFI' ]] || die 'UKI output is outside EFI/BootHop'
final_path="$uki_directory/arch.efi"
[[ "$stage_path" != "$uki_directory" && "$final_path" != "$stage_path" ]] || die 'invalid UKI output path'

if [[ "${BOOTHOP_TESTING:-}" == 1 ]]; then
    case "$stage_path" in
        "$fixture_root"/esp/*) ;;
        *) die 'fixture publication escaped the temporary ESP' ;;
    esac
fi

check_no_symlink_components() {
    local path="$1" rest part current=''
    rest="${path#/}"
    while [[ -n "$rest" ]]; do
        if [[ "$rest" == */* ]]; then
            part="${rest%%/*}"
            rest="${rest#*/}"
        else
            part="$rest"
            rest=''
        fi
        [[ -n "$part" ]] || die 'path contains an empty component'
        current+="/$part"
        [[ ! -L "$current" ]] || die 'symlink path component is not allowed'
    done
}

check_normalized_path() {
    local path="$1"
    [[ "$path" == /* ]] || die 'path is not absolute'
    case "$path" in
        *//*|*'/./'*|*'/../'*) die 'path is not normalized' ;;
    esac
}

directory_snapshot() {
    stat -c '%d:%i:%u:%g:%a' -- "$1"
}

file_snapshot() {
    stat -c '%d:%i:%u:%g:%a:%s:%y:%z' -- "$1"
}

require_trusted_directory() {
    local path="$1" metadata owner mode
    [[ -d "$path" && ! -L "$path" ]] || die 'trusted directory is missing or is a symlink'
    metadata="$(stat -c '%u:%a' -- "$path")" || die 'cannot inspect trusted directory'
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    [[ "$owner" == 0 ]] || die 'publication directory is not root-owned'
    mode=$((8#$mode))
    (( (mode & 0022) == 0 )) || die 'publication directory is writable by group or other'
}

check_trusted_directory_chain() {
    local path="$1" rest part current=''
    rest="${path#/}"
    require_trusted_directory '/'
    while [[ -n "$rest" ]]; do
        if [[ "$rest" == */* ]]; then
            part="${rest%%/*}"
            rest="${rest#*/}"
        else
            part="$rest"
            rest=''
        fi
        current+="/$part"
        require_trusted_directory "$current"
    done
}

check_trusted_file() {
    local path="$1" metadata owner mode
    [[ -f "$path" && ! -L "$path" ]] || die 'publication file is not regular'
    metadata="$(stat -c '%u:%a' -- "$path")" || die 'cannot inspect publication file'
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    [[ "$owner" == 0 ]] || die 'publication file is not root-owned'
    mode=$((8#$mode))
    (( (mode & 0022) == 0 )) || die 'publication file is writable by group or other'
}

check_esp_mount() {
    local esp_root="$1" filesystem
    check_no_symlink_components "$esp_root"
    check_trusted_directory_chain "$esp_root"
    filesystem="$(findmnt --noheadings --mountpoint "$esp_root" --output FSTYPE 2>/dev/null | tr -d '[:space:]')" \
        || die 'cannot inspect EFI System Partition mount'
    [[ "$filesystem" == 'vfat' ]] || die 'UKI destination is not on a vfat mount point'
}

acquire_publication_lock() {
    check_normalized_path "$lock_path"
    check_no_symlink_components "${lock_path%/*}"
    [[ -d "${lock_path%/*}" ]] || die 'publisher lock directory is missing'
    if [[ "${BOOTHOP_TESTING:-}" != 1 ]]; then
        check_trusted_directory_chain "${lock_path%/*}"
    fi
    [[ ! -L "$lock_path" && ( ! -e "$lock_path" || -f "$lock_path" ) ]] || die 'publisher lock is not a regular file'
    command -v flock >/dev/null 2>&1 || die 'flock is required for safe UKI publication'
    umask 077
    exec {publisher_lock_fd}>>"$lock_path" || die 'cannot open publisher lock'
    [[ -f "$lock_path" && ! -L "$lock_path" ]] || die 'publisher lock is not a regular file'
    lock_metadata="$(stat -c '%u:%a' -- "$lock_path")" || die 'cannot inspect publisher lock'
    [[ "$lock_metadata" == "$expected_marker_uid:600" ]] || die 'publisher lock owner or mode is invalid'
    flock --exclusive --nonblock "$publisher_lock_fd" || die 'another UKI publication is in progress'
}

check_normalized_path "$stage_path"
check_normalized_path "$final_path"
acquire_publication_lock
lock_identity="$(file_snapshot "$lock_path")" || die 'cannot inspect publisher lock identity'
lock_directory_identity="$(directory_snapshot "${lock_path%/*}")" || die 'cannot inspect publisher lock directory'
check_no_symlink_components "$uki_directory"
check_no_symlink_components "$stage_path"
[[ -d "$uki_directory" ]] || die 'UKI output directory is missing'
[[ -f "$stage_path" && ! -L "$stage_path" ]] || die 'UKI stage is not a regular file'
check_normalized_path "$marker_path"
check_no_symlink_components "${marker_path%/*}"
[[ -d "${marker_path%/*}" ]] || die 'identity marker directory is missing'

esp_root="${efi_directory%/*}"
if [[ "${BOOTHOP_TESTING:-}" != 1 ]]; then
    check_esp_mount "$esp_root"
    check_trusted_directory_chain "$uki_directory"
    check_trusted_directory_chain "${marker_path%/*}"
    check_trusted_file "$stage_path"
fi

esp_root_identity="$(directory_snapshot "$esp_root")" || die 'cannot inspect ESP root'
efi_directory_identity="$(directory_snapshot "$efi_directory")" || die 'cannot inspect EFI directory'
uki_directory_identity="$(directory_snapshot "$uki_directory")" || die 'cannot inspect BootHop directory'
marker_directory_identity="$(directory_snapshot "${marker_path%/*}")" || die 'cannot inspect identity directory'
stage_identity="$(file_snapshot "$stage_path")" || die 'cannot inspect UKI stage'

if [[ "$mode" == '--initial' ]]; then
    final_state='absent'
    marker_state='absent'
    [[ ! -e "$final_path" && ! -L "$final_path" ]] || die 'initial publication requires an absent final UKI'
    [[ ! -e "$marker_path" && ! -L "$marker_path" ]] || die 'initial publication requires an absent identity marker'
else
    [[ -f "$final_path" && ! -L "$final_path" ]] || die 'update requires an existing regular final UKI'
    [[ -f "$marker_path" && ! -L "$marker_path" ]] || die 'update requires a regular identity marker'
    marker_metadata="$(stat -c '%u:%a' -- "$marker_path")" || die 'cannot inspect identity marker ownership'
    [[ "$marker_metadata" == "$expected_marker_uid:600" ]] || die 'identity marker owner or mode is invalid'
    if [[ "${BOOTHOP_TESTING:-}" != 1 ]]; then
        check_trusted_file "$final_path"
        check_trusted_file "$marker_path"
    fi
    final_state="$(file_snapshot "$final_path")" || die 'cannot inspect existing final UKI'
    marker_state="$(file_snapshot "$marker_path")" || die 'cannot snapshot identity marker'
    mapfile -t marker_lines < "$marker_path"
    [[ "${#marker_lines[@]}" == 4 ]] || die 'identity marker has an unsupported format'
    marker_last_byte="$(tail -c 1 -- "$marker_path" | od -An -tu1 | tr -d '[:space:]')"
    [[ "$marker_last_byte" == 10 ]] || die 'identity marker must end with one newline'
    [[ "${marker_lines[0]}" == 'BOOTHOP_ARCH_V1' ]] || die 'identity marker schema is unsupported'
    [[ "${marker_lines[1]}" =~ ^boot_id=[0-9A-F]{4}$ && "${marker_lines[1]}" != 'boot_id=0000' ]] || die 'identity marker Boot ID is invalid'
    [[ "${marker_lines[2]}" =~ ^option_sha256=[0-9a-f]{64}$ ]] || die 'identity marker digest is invalid'
    [[ "${marker_lines[3]}" == 'path=EFI/BootHop/arch.efi' ]] || die 'identity marker path is invalid'
    if ! printf 'BOOTHOP_ARCH_V1\n%s\n%s\npath=EFI/BootHop/arch.efi\n' \
        "${marker_lines[1]}" "${marker_lines[2]}" | cmp -s - "$marker_path"; then
        die 'identity marker bytes are not canonical'
    fi
fi

read_uint() {
    local width="$1" offset="$2" value
    value="$(od -An -tu"$width" --endian=little -j "$offset" -N "$width" -- "$stage_path" 2>/dev/null | tr -d '[:space:]')" || return 1
    [[ "$value" =~ ^[0-9]+$ ]] || return 1
    printf '%s' "$value"
}

read_hex() {
    local offset="$1" width="$2"
    dd if="$stage_path" bs=1 skip="$offset" count="$width" status=none 2>/dev/null \
        | od -An -tx1 \
        | tr -d '[:space:]'
}

validate_uki() {
    local size pe_offset machine section_count optional_size optional_offset section_table
    local entry_point section_alignment file_alignment image_size header_size directory_count coff_characteristics
    local section_offset section_name virtual_size virtual_address raw_size raw_offset characteristics
    local found_linux=0 found_initrd=0 found_cmdline=0 found_entrypoint=0 index
    size="$(stat -c '%s' -- "$stage_path")" || die 'cannot inspect UKI stage size'
    [[ "$size" =~ ^[0-9]+$ && "$size" -ge 512 ]] || die 'UKI stage is truncated'
    [[ "$(read_hex 0 2)" == '4d5a' ]] || die 'UKI stage has no DOS header'
    pe_offset="$(read_uint 4 60)" || die 'UKI stage has a truncated DOS header'
    (( pe_offset >= 64 && pe_offset <= 1048576 && pe_offset + 24 <= size )) || die 'UKI PE header offset is invalid'
    [[ "$(read_hex "$pe_offset" 4)" == '50450000' ]] || die 'UKI stage has no PE signature'
    machine="$(read_uint 2 "$((pe_offset + 4))")" || die 'UKI COFF header is truncated'
    section_count="$(read_uint 2 "$((pe_offset + 6))")" || die 'UKI COFF header is truncated'
    optional_size="$(read_uint 2 "$((pe_offset + 20))")" || die 'UKI COFF header is truncated'
    (( machine == 34404 && section_count >= 3 && section_count <= 96 )) || die 'UKI is not an x86_64 EFI image'
    (( optional_size >= 112 )) || die 'UKI PE32+ fixed optional header is truncated'
    optional_offset=$((pe_offset + 24))
    (( optional_offset + optional_size <= size )) || die 'UKI optional header is truncated'
    [[ "$(read_uint 2 "$optional_offset")" == 523 ]] || die 'UKI is not a PE32+ image'
    coff_characteristics="$(read_uint 2 "$((pe_offset + 22))")" || die 'UKI COFF header is truncated'
    (( (coff_characteristics & 2) != 0 )) || die 'UKI is not marked as an executable image'
    [[ "$(read_uint 2 "$((optional_offset + 68))")" == 10 ]] || die 'UKI is not an EFI application'
    entry_point="$(read_uint 4 "$((optional_offset + 16))")" || die 'UKI optional header is truncated'
    section_alignment="$(read_uint 4 "$((optional_offset + 32))")" || die 'UKI optional header is truncated'
    file_alignment="$(read_uint 4 "$((optional_offset + 36))")" || die 'UKI optional header is truncated'
    image_size="$(read_uint 4 "$((optional_offset + 56))")" || die 'UKI optional header is truncated'
    header_size="$(read_uint 4 "$((optional_offset + 60))")" || die 'UKI optional header is truncated'
    directory_count="$(read_uint 4 "$((optional_offset + 108))")" || die 'UKI optional header is truncated'
    (( entry_point > 0 && image_size > 0 && header_size > 0 )) || die 'UKI PE32+ image layout has zero required fields'
    (( file_alignment >= 512 && file_alignment <= 65536 && (file_alignment & (file_alignment - 1)) == 0 )) || die 'UKI file alignment is invalid'
    (( section_alignment >= file_alignment && (section_alignment & (section_alignment - 1)) == 0 )) || die 'UKI section alignment is invalid'
    (( header_size <= size && header_size % file_alignment == 0 && image_size >= header_size && image_size % section_alignment == 0 )) || die 'UKI image/header sizes are invalid'
    (( directory_count <= 16 && 112 + directory_count * 8 <= optional_size )) || die 'UKI data-directory table is truncated'
    section_table=$((optional_offset + optional_size))
    (( section_table + section_count * 40 <= header_size && section_table + section_count * 40 <= size )) || die 'UKI section table is truncated'

    for ((index = 0; index < section_count; index += 1)); do
        section_offset=$((section_table + index * 40))
        section_name="$(read_hex "$section_offset" 8)"
        virtual_size="$(read_uint 4 "$((section_offset + 8))")" || die 'UKI section header is truncated'
        virtual_address="$(read_uint 4 "$((section_offset + 12))")" || die 'UKI section header is truncated'
        raw_size="$(read_uint 4 "$((section_offset + 16))")" || die 'UKI section header is truncated'
        raw_offset="$(read_uint 4 "$((section_offset + 20))")" || die 'UKI section header is truncated'
        characteristics="$(read_uint 4 "$((section_offset + 36))")" || die 'UKI section header is truncated'
        (( virtual_address >= section_alignment && virtual_address % section_alignment == 0 && virtual_address < image_size )) || die 'UKI section virtual address is invalid'
        (( virtual_size > 0 && virtual_address + virtual_size <= image_size )) || die 'UKI section virtual range is invalid'
        if (( raw_size > 0 )); then
            (( raw_offset >= header_size && raw_offset % file_alignment == 0 && raw_size % file_alignment == 0 && raw_offset + raw_size <= size )) || die 'UKI section data is truncated or misaligned'
        fi
        if (( entry_point >= virtual_address && entry_point < virtual_address + virtual_size && entry_point - virtual_address < raw_size && (characteristics & 0x20000000) != 0 )); then
            found_entrypoint=1
        fi
        case "$section_name" in
            2e6c696e75780000)
                (( found_linux == 0 )) || die 'UKI contains a duplicate .linux section'
                (( raw_size > 0 && raw_offset > 0 && raw_offset + raw_size <= size )) || die 'UKI .linux data is missing or truncated'
                found_linux=1
                ;;
            2e696e6974726400)
                (( found_initrd == 0 )) || die 'UKI contains a duplicate .initrd section'
                (( raw_size > 0 && raw_offset > 0 && raw_offset + raw_size <= size )) || die 'UKI .initrd data is missing or truncated'
                found_initrd=1
                ;;
            2e636d646c696e65)
                (( found_cmdline == 0 )) || die 'UKI contains a duplicate .cmdline section'
                (( raw_size > 0 && raw_offset > 0 && raw_offset + raw_size <= size )) || die 'UKI .cmdline data is missing or truncated'
                found_cmdline=1
                ;;
            *)
                if (( raw_size > 0 )); then
                    (( raw_offset > 0 && raw_offset + raw_size <= size )) || die 'UKI section data is truncated'
                fi
                ;;
        esac
    done
    (( found_linux == 1 && found_initrd == 1 && found_cmdline == 1 )) || die 'UKI is missing a required BootHop section'
    (( found_entrypoint == 1 )) || die 'UKI entry point is outside an executable section'
}

validate_uki
recheck_publication_paths() {
    check_no_symlink_components "$esp_root"
    check_no_symlink_components "$uki_directory"
    check_no_symlink_components "$stage_path"
    check_no_symlink_components "$final_path"
    check_no_symlink_components "${marker_path%/*}"
    check_no_symlink_components "$marker_path"
    check_no_symlink_components "${lock_path%/*}"
    check_no_symlink_components "$lock_path"
    [[ "$(directory_snapshot "$esp_root")" == "$esp_root_identity" ]] || die 'ESP root changed during UKI validation'
    [[ "$(directory_snapshot "$efi_directory")" == "$efi_directory_identity" ]] || die 'EFI directory changed during UKI validation'
    [[ "$(directory_snapshot "$uki_directory")" == "$uki_directory_identity" ]] || die 'BootHop directory changed during UKI validation'
    [[ "$(directory_snapshot "${marker_path%/*}")" == "$marker_directory_identity" ]] || die 'identity directory changed during UKI validation'
    [[ "$(directory_snapshot "${lock_path%/*}")" == "$lock_directory_identity" ]] || die 'publisher lock directory changed during UKI validation'
    [[ -f "$lock_path" && ! -L "$lock_path" && "$(file_snapshot "$lock_path")" == "$lock_identity" ]] || die 'publisher lock changed during UKI validation'
    [[ -f "$stage_path" && ! -L "$stage_path" && "$(file_snapshot "$stage_path")" == "$stage_identity" ]] || die 'UKI stage changed during validation'
    if [[ "$mode" == '--initial' ]]; then
        [[ ! -e "$final_path" && ! -L "$final_path" ]] || die 'initial final path appeared during UKI validation'
        [[ ! -e "$marker_path" && ! -L "$marker_path" ]] || die 'initial identity marker appeared during UKI validation'
    else
        [[ -f "$final_path" && ! -L "$final_path" && "$(file_snapshot "$final_path")" == "$final_state" ]] || die 'existing final UKI changed during validation'
        [[ -f "$marker_path" && ! -L "$marker_path" && "$(file_snapshot "$marker_path")" == "$marker_state" ]] || die 'identity marker changed during validation'
    fi
    if [[ "${BOOTHOP_TESTING:-}" != 1 ]]; then
        check_esp_mount "$esp_root"
        check_trusted_directory_chain "$uki_directory"
        check_trusted_directory_chain "${marker_path%/*}"
        check_trusted_file "$stage_path"
        if [[ "$mode" == '--update' ]]; then
            check_trusted_file "$final_path"
            check_trusted_file "$marker_path"
        fi
    fi
}

recheck_publication_paths
mv -T --no-copy -- "$stage_path" "$final_path" || die 'atomic UKI rename failed'
[[ -f "$final_path" && ! -L "$final_path" && ! -e "$stage_path" ]] || die 'UKI rename did not complete exactly'
