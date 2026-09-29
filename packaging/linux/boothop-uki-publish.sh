#!/usr/bin/bash
# Install this executable in mkinitcpio's post-hook search path only after confirming the
# selected kernel update path runs post hooks. mkinitcpio calls hooks with KERNELIMAGE, image,
# then (when built) UKI. A kernel-install invocation disables post hooks.
set -euo pipefail

if (( $# < 3 )); then
    # Ordinary split-image builds are outside this hook's scope.
    exit 0
fi

staged_uki=$3
case "$staged_uki" in
    */EFI/BootHop/arch.efi.staging) ;;
    *) exit 0 ;;
esac

secure_boot_required=${BOOT_HOP_SECURE_BOOT_REQUIRED-}
case "$secure_boot_required" in
    0|1) ;;
    *) echo "BOOT_HOP_SECURE_BOOT_REQUIRED must be explicitly set to 0 or 1" >&2; exit 1 ;;
esac

esp_mount=${BOOT_HOP_ESP_MOUNT-}
if [[ -z "$esp_mount" || "$esp_mount" != /* || "$esp_mount" == / \
    || "$esp_mount" == */ || "$esp_mount" == *//* \
    || "$esp_mount" == */./* || "$esp_mount" == */. \
    || "$esp_mount" == */../* || "$esp_mount" == */.. ]]; then
    echo "BOOT_HOP_ESP_MOUNT must be an explicit normalized absolute mount path" >&2
    exit 1
fi
mount_info=$(findmnt --raw --noheadings --output TARGET,FSTYPE --mountpoint "$esp_mount") || {
    echo "configured BootHop ESP path is not a mounted filesystem" >&2
    exit 1
}
read -r mounted_target filesystem <<<"$mount_info"
if [[ "$mounted_target" != "$esp_mount" || "$filesystem" != vfat ]]; then
    echo "configured BootHop ESP path is not an exact vfat mount point" >&2
    exit 1
fi

expected_staged_uki="$esp_mount/EFI/BootHop/arch.efi.staging"
if [[ "$staged_uki" != "$expected_staged_uki" ]]; then
    echo "mkinitcpio UKI output does not match the configured BootHop ESP staging path" >&2
    exit 1
fi

directory="$esp_mount/EFI/BootHop"
final_uki="$directory/arch.efi"
[[ -d "$directory" && ! -L "$directory" && ! -L "$esp_mount/EFI" \
    && ! -L "$esp_mount" && ! -L "$staged_uki" ]] || {
    echo "BootHop UKI directory or ESP path is missing or redirected" >&2
    exit 1
}
[[ -f "$staged_uki" ]] || { echo "staged BootHop UKI is missing" >&2; exit 1; }

validate_uki() {
    local image=$1 sections
    sections=$(objdump -h -- "$image") || return 1
    grep -q '[.]linux' <<<"$sections" || return 1
    grep -q '[.]initrd' <<<"$sections" || return 1
    grep -q '[.]cmdline' <<<"$sections" || return 1
}

validate_uki "$staged_uki" || {
    echo "staged BootHop image is not a complete UKI" >&2
    exit 1
}

if [[ "$secure_boot_required" == 1 ]]; then
    : "${BOOT_HOP_SIGNING_KEY:?Secure Boot requires an already-configured signing key}"
    : "${BOOT_HOP_SIGNING_CERT:?Secure Boot requires an already-configured signing certificate}"
    signed_uki="$staged_uki.signed"
    trap 'rm -f -- "$signed_uki"' EXIT
    sbsign --key "$BOOT_HOP_SIGNING_KEY" --cert "$BOOT_HOP_SIGNING_CERT" \
        --output "$signed_uki" "$staged_uki"
    sbverify --cert "$BOOT_HOP_SIGNING_CERT" "$signed_uki"
    validate_uki "$signed_uki" || {
        echo "signed BootHop image failed UKI validation" >&2
        exit 1
    }
    mv -f -- "$signed_uki" "$staged_uki"
    trap - EXIT
fi

# Both files share this directory, so mv uses a same-filesystem atomic rename. The stable file
# is untouched until every build, validation, and optional signing step has succeeded.
mv -f -- "$staged_uki" "$final_uki"
