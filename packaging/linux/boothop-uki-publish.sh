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

# These values are trusted only when supplied by a Phase 5 read-only verifier of the root-owned
# journal. Do not install or wire this hook until that verifier/update path exists; a state marker
# by itself never proves ownership.
journal_state=${BOOT_HOP_JOURNAL_STATE-}
case "$journal_state" in
    Provisioning)
        if [[ -e "$final_uki" || -L "$final_uki" ]]; then
            echo "initial provisioning requires an absent stable UKI path" >&2
            exit 1
        fi
        ;;
    Ready)
        expected_sha256=${BOOT_HOP_JOURNAL_UKI_SHA256-}
        expected_size=${BOOT_HOP_JOURNAL_UKI_SIZE-}
        if [[ ! "$expected_sha256" =~ ^[0-9a-f]{64}$ \
            || ! "$expected_size" =~ ^[1-9][0-9]*$ ]]; then
            echo "Ready journal ownership metadata is missing or malformed" >&2
            exit 1
        fi
        if [[ ! -f "$final_uki" || -L "$final_uki" ]]; then
            echo "Ready journal requires an existing regular stable UKI" >&2
            exit 1
        fi
        digest_line=$(sha256sum -- "$final_uki") || {
            echo "could not hash the existing stable UKI" >&2
            exit 1
        }
        actual_sha256=${digest_line%% *}
        actual_size=$(stat --format='%s' -- "$final_uki") || {
            echo "could not read the existing stable UKI size" >&2
            exit 1
        }
        if [[ "$actual_sha256" != "$expected_sha256" || "$actual_size" != "$expected_size" ]]; then
            echo "stable UKI does not match journaled ownership metadata" >&2
            exit 1
        fi
        ;;
    *)
        echo "a trusted Provisioning or Ready journal state is required" >&2
        exit 1
        ;;
esac

validate_uki() {
    local image=$1 format properties sections name
    format=$(objdump -f -- "$image") || return 1
    grep -Eq 'file format pei-[[:alnum:]_-]+' <<<"$format" || return 1

    properties=$(objdump -p -- "$image") || return 1
    grep -Eq '^Magic[[:space:]]+010b[[:space:]]+\(PE32\)$' <<<"$properties" \
        || grep -Eq '^Magic[[:space:]]+020b[[:space:]]+\(PE32\+\)$' <<<"$properties" \
        || return 1
    grep -Eq '^Subsystem[[:space:]]+0000000a[[:space:]]+\(EFI application\)$' <<<"$properties" \
        || return 1

    sections=$(objdump -h -- "$image") || return 1
    for name in .linux .initrd .cmdline; do
        awk -v expected="$name" \
            '$1 ~ /^[0-9]+$/ && $2 == expected {
                found = 1
                if ($3 !~ /^[[:xdigit:]]+$/ || $3 ~ /^0+$/) bad = 1
            }
            END { exit !(found && !bad) }' <<<"$sections" || return 1
    done
}

validate_uki "$staged_uki" || {
    echo "staged BootHop image is not a complete UKI" >&2
    exit 1
}

if [[ "$secure_boot_required" == 1 ]]; then
    : "${BOOT_HOP_SIGNING_KEY:?Secure Boot requires an already-configured signing key}"
    : "${BOOT_HOP_SIGNING_CERT:?Secure Boot requires an already-configured signing certificate}"
    signing_tmp_dir=$(mktemp -d -- "$directory/.boothop-uki.XXXXXX") || {
        echo "could not create private signer temporary directory" >&2
        exit 1
    }
    signed_uki="$signing_tmp_dir/arch.efi"
    trap 'rm -rf -- "$signing_tmp_dir"' EXIT
    sbsign --key "$BOOT_HOP_SIGNING_KEY" --cert "$BOOT_HOP_SIGNING_CERT" \
        --output "$signed_uki" "$staged_uki"
    sbverify --cert "$BOOT_HOP_SIGNING_CERT" "$signed_uki"
    validate_uki "$signed_uki" || {
        echo "signed BootHop image failed UKI validation" >&2
        exit 1
    }
    mv -f -- "$signed_uki" "$staged_uki"
fi

# Repeat the ownership check immediately before publication. The caller supplies these values
# only from the validated journal; a production adapter must make this decision under its update
# serialization boundary as well.
if [[ -e "$final_uki" || -L "$final_uki" ]]; then
    if [[ ! -f "$final_uki" || -L "$final_uki" ]]; then
        echo "existing stable UKI path is not a non-symlink regular file" >&2
        exit 1
    fi
    if [[ "$journal_state" != Ready ]]; then
        echo "initial provisioning cannot replace an existing stable UKI" >&2
        exit 1
    fi
    digest_line=$(sha256sum -- "$final_uki") || {
        echo "could not hash the existing stable UKI before publication" >&2
        exit 1
    }
    actual_sha256=${digest_line%% *}
    actual_size=$(stat --format='%s' -- "$final_uki") || {
        echo "could not read the stable UKI size before publication" >&2
        exit 1
    }
    if [[ "$actual_sha256" != "$expected_sha256" || "$actual_size" != "$expected_size" ]]; then
        echo "stable UKI ownership changed before publication" >&2
        exit 1
    fi
elif [[ "$journal_state" == Ready ]]; then
    echo "Ready journal stable UKI disappeared before publication" >&2
    exit 1
fi

# Both files share this directory, so mv uses a same-filesystem atomic rename. The stable file
# is untouched until every build, validation, and optional signing step has succeeded.
mv -f -- "$staged_uki" "$final_uki"
