#!/usr/bin/bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../../.." && pwd)
publisher="$repo_root/packaging/linux/boothop-uki-publish.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

mkdir -p "$work/bin" "$work/esp/EFI/BootHop"
export BOOT_HOP_ESP_MOUNT="$work/esp"
export BOOT_HOP_TEST_SIGN_LOG="$work/sign.log"
export PATH="$work/bin:$PATH"

cat >"$work/bin/findmnt" <<'EOF'
#!/usr/bin/bash
printf '%s %s\n' "${@: -1}" "${BOOT_HOP_TEST_FSTYPE:-vfat}"
EOF
cat >"$work/bin/objdump" <<'EOF'
#!/usr/bin/bash
image=${@: -1}
mode=$(<"$image")
case "$1" in
    -f)
        case "$mode" in
            NON_PE*) echo 'file format elf64-x86-64' ;;
            PE32*) echo 'file format pei-i386' ;;
            *) echo 'file format pei-x86-64' ;;
        esac
        ;;
    -p)
        case "$mode" in
            PE32*) echo 'Magic 010b (PE32)' ;;
            *) echo 'Magic 020b (PE32+)' ;;
        esac
        case "$mode" in
            WRONG_SUBSYSTEM*) echo 'Subsystem 00000003 (Windows CUI)' ;;
            *) echo 'Subsystem 0000000a (EFI application)' ;;
        esac
        ;;
    -h)
        case "$mode" in
            LINUX_SUFFIX*) printf '%s\n' '  1 .linuxfoo 0001 0000' ;;
            EMPTY_LINUX*) printf '%s\n' '  1 .linux 0000 0000' ;;
            *) printf '%s\n' '  1 .linux 0001 0000' ;;
        esac
        case "$mode" in
            WRONG_SECTION*) printf '%s\n' '  2 .initrdx 0001 0000' ;;
            EMPTY_INITRD*) printf '%s\n' '  2 .initrd 0000 0000' ;;
            *) printf '%s\n' '  2 .initrd 0001 0000' ;;
        esac
        case "$mode" in
            EMPTY_CMDLINE*) printf '%s\n' '  3 .cmdline 0000 0000' ;;
            *) printf '%s\n' '  3 .cmdline 0001 0000' ;;
        esac
        ;;
esac
EOF
cat >"$work/bin/sbsign" <<'EOF'
#!/usr/bin/bash
while (($#)); do
    case "$1" in
        --output) output=$2; shift 2 ;;
        --key|--cert) shift 2 ;;
        *) input=$1; shift ;;
    esac
done
cat -- "$input" >"$output"
printf 'signed\n' >>"$output"
touch "$BOOT_HOP_TEST_SIGN_LOG"
EOF
cat >"$work/bin/sbverify" <<'EOF'
#!/usr/bin/bash
exit 0
EOF
chmod +x "$work/bin/"*

stage="$BOOT_HOP_ESP_MOUNT/EFI/BootHop/arch.efi.staging"
final="$BOOT_HOP_ESP_MOUNT/EFI/BootHop/arch.efi"
prepare() {
    printf 'old stable\n' >"$final"
    printf 'PE32+\nstaged uki\n' >"$stage"
    BOOT_HOP_JOURNAL_STATE=Ready
    BOOT_HOP_JOURNAL_UKI_SHA256=$(sha256sum -- "$final" | awk '{print $1}')
    BOOT_HOP_JOURNAL_UKI_SIZE=$(stat --format='%s' -- "$final")
    export BOOT_HOP_JOURNAL_STATE BOOT_HOP_JOURNAL_UKI_SHA256 BOOT_HOP_JOURNAL_UKI_SIZE
    rm -f -- "$BOOT_HOP_TEST_SIGN_LOG"
}
assert_old_stable() {
    [[ $(<"$final") == 'old stable' ]]
}
expect_failure_preserves_stable() {
    prepare
    if "$publisher" /dev/null /tmp/initramfs "$stage"; then
        echo "publisher unexpectedly accepted invalid setup: $*" >&2
        exit 1
    fi
    assert_old_stable
}
expect_invalid_image_preserves_stable() {
    prepare
    printf '%s\n' "$1" >"$stage"
    if "$publisher" /dev/null /tmp/initramfs "$stage"; then
        echo "publisher unexpectedly accepted invalid image: $1" >&2
        exit 1
    fi
    assert_old_stable
    [[ $(<"$stage") == "$1" ]]
}

unset BOOT_HOP_SECURE_BOOT_REQUIRED
expect_failure_preserves_stable unset-secure-boot-state
BOOT_HOP_SECURE_BOOT_REQUIRED=maybe
export BOOT_HOP_SECURE_BOOT_REQUIRED
expect_failure_preserves_stable invalid-secure-boot-state

BOOT_HOP_SECURE_BOOT_REQUIRED=0
export BOOT_HOP_SECURE_BOOT_REQUIRED
prepare
printf 'PE32\nstaged uki\n' >"$stage"
"$publisher" /dev/null /tmp/initramfs "$stage"
[[ $(<"$final") == $'PE32\nstaged uki' ]]
[[ ! -e "$stage" && ! -e "$BOOT_HOP_TEST_SIGN_LOG" ]]

expect_ownership_failure() {
    scenario=$1
    prepare
    case "$scenario" in
        missing-state) unset BOOT_HOP_JOURNAL_STATE ;;
        malformed-state) BOOT_HOP_JOURNAL_STATE=Unknown ;;
        missing-digest) unset BOOT_HOP_JOURNAL_UKI_SHA256 ;;
        malformed-digest) BOOT_HOP_JOURNAL_UKI_SHA256=not-a-digest ;;
        missing-size) unset BOOT_HOP_JOURNAL_UKI_SIZE ;;
        malformed-size) BOOT_HOP_JOURNAL_UKI_SIZE=01x ;;
        hash-mismatch) BOOT_HOP_JOURNAL_UKI_SHA256=$(printf '0%.0s' {1..64}) ;;
        size-mismatch) BOOT_HOP_JOURNAL_UKI_SIZE=1 ;;
        provisioning-existing) BOOT_HOP_JOURNAL_STATE=Provisioning ;;
        ready-absent)
            rm -f -- "$final"
            ;;
    esac
    export BOOT_HOP_JOURNAL_STATE BOOT_HOP_JOURNAL_UKI_SHA256 BOOT_HOP_JOURNAL_UKI_SIZE || true
    stage_before=$(<"$stage")
    if "$publisher" /dev/null /tmp/initramfs "$stage"; then
        echo "publisher unexpectedly accepted ownership scenario: $scenario" >&2
        exit 1
    fi
    [[ $(<"$stage") == "$stage_before" ]]
    if [[ "$scenario" == ready-absent ]]; then
        [[ ! -e "$final" && ! -L "$final" ]]
    else
        assert_old_stable
    fi
}

for ownership_failure in missing-state malformed-state missing-digest malformed-digest \
    missing-size malformed-size hash-mismatch size-mismatch provisioning-existing ready-absent; do
    expect_ownership_failure "$ownership_failure"
done

prepare
BOOT_HOP_JOURNAL_STATE=Provisioning
export BOOT_HOP_JOURNAL_STATE
rm -f -- "$final"
"$publisher" /dev/null /tmp/initramfs "$stage"
[[ $(<"$final") == $'PE32+\nstaged uki' ]]
[[ ! -e "$stage" ]]

prepare
BOOT_HOP_JOURNAL_STATE=Ready
export BOOT_HOP_JOURNAL_STATE
"$publisher" /dev/null /tmp/initramfs "$stage"
[[ $(<"$final") == $'PE32+\nstaged uki' ]]
[[ ! -e "$stage" ]]

BOOT_HOP_SECURE_BOOT_REQUIRED=1
export BOOT_HOP_SECURE_BOOT_REQUIRED
BOOT_HOP_SIGNING_KEY="$work/key"
BOOT_HOP_SIGNING_CERT="$work/cert"
export BOOT_HOP_SIGNING_KEY BOOT_HOP_SIGNING_CERT
prepare
"$publisher" /dev/null /tmp/initramfs "$stage"
[[ $(<"$final") == $'PE32+\nstaged uki\nsigned' ]]
[[ -e "$BOOT_HOP_TEST_SIGN_LOG" ]]

prepare
sentinel="$work/signer-output-sentinel"
printf 'must stay unchanged\n' >"$sentinel"
ln -s "$sentinel" "$stage.signed"
"$publisher" /dev/null /tmp/initramfs "$stage"
[[ $(<"$sentinel") == 'must stay unchanged' ]]
[[ -L "$stage.signed" ]]
if compgen -G "$BOOT_HOP_ESP_MOUNT/EFI/BootHop/.boothop-uki.*" >/dev/null; then
    echo "signer temporary directory was not cleaned up" >&2
    exit 1
fi

expect_unsafe_final_object_rejected() {
    object_kind=$1
    prepare
    rm -f -- "$final"
    case "$object_kind" in
        directory)
            mkdir -- "$final"
            printf 'old stable marker\n' >"$final/stable-marker"
            ;;
        symlink)
            target="$work/final-symlink-target"
            printf 'old stable\n' >"$target"
            ln -s -- "$target" "$final"
            ;;
        dangling-symlink)
            ln -s -- "$work/missing-final-target" "$final"
            ;;
        fifo)
            mkfifo -- "$final"
            ;;
    esac
    stage_before=$(<"$stage")
    if "$publisher" /dev/null /tmp/initramfs "$stage"; then
        echo "publisher unexpectedly accepted final $object_kind" >&2
        exit 1
    fi
    [[ $(<"$stage") == "$stage_before" ]]
    case "$object_kind" in
        directory)
            [[ -d "$final" && $(<"$final/stable-marker") == 'old stable marker' ]]
            [[ ! -e "$final/arch.efi.staging" ]]
            ;;
        symlink)
            [[ -L "$final" && $(<"$target") == 'old stable' ]]
            ;;
        dangling-symlink)
            [[ -L "$final" ]]
            ;;
        fifo)
            [[ -p "$final" ]]
            ;;
    esac
    rm -rf -- "$final"
    [[ "$object_kind" != symlink ]] || rm -f -- "$target"
}

BOOT_HOP_SECURE_BOOT_REQUIRED=0
export BOOT_HOP_SECURE_BOOT_REQUIRED
for final_object_kind in directory symlink dangling-symlink fifo; do
    expect_unsafe_final_object_rejected "$final_object_kind"
done

expect_failure_preserves_stable_unset_esp() {
    prepare
    unset BOOT_HOP_ESP_MOUNT
    if "$publisher" /dev/null /tmp/initramfs "$stage"; then
        echo "publisher unexpectedly accepted missing ESP mount" >&2
        exit 1
    fi
    assert_old_stable
    export BOOT_HOP_ESP_MOUNT="$work/esp"
}
expect_failure_preserves_stable_unset_esp

BOOT_HOP_ESP_MOUNT="$work/esp/other"
export BOOT_HOP_ESP_MOUNT
expect_failure_preserves_stable mismatched-esp-path

BOOT_HOP_ESP_MOUNT="$work/esp"
BOOT_HOP_TEST_FSTYPE=ext4
export BOOT_HOP_ESP_MOUNT BOOT_HOP_TEST_FSTYPE
expect_failure_preserves_stable non-vfat-esp
unset BOOT_HOP_TEST_FSTYPE

BOOT_HOP_ESP_MOUNT="$work/esp/../esp"
export BOOT_HOP_ESP_MOUNT
expect_failure_preserves_stable non-normalized-esp-path

BOOT_HOP_ESP_MOUNT="$work/esp"
export BOOT_HOP_ESP_MOUNT
expect_invalid_image_preserves_stable 'NON_PE invalid'
expect_invalid_image_preserves_stable 'WRONG_SUBSYSTEM invalid'
expect_invalid_image_preserves_stable 'LINUX_SUFFIX invalid'
expect_invalid_image_preserves_stable 'WRONG_SECTION invalid'
expect_invalid_image_preserves_stable 'EMPTY_LINUX invalid'
expect_invalid_image_preserves_stable 'EMPTY_INITRD invalid'
expect_invalid_image_preserves_stable 'EMPTY_CMDLINE invalid'

echo "UKI publisher tests passed"
