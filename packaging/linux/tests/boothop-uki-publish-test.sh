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
