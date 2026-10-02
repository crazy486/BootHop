//! Fail-closed evidence gate for the unpackaged M4 QEMU guest setup binary.
use std::{fs, path::Path};

pub const FW_CFG_MARKER_PATH: &str =
    "/sys/firmware/qemu_fw_cfg/by_name/opt/org.boothop/m4-guest/raw";
pub const FW_CFG_MARKER: &[u8] = b"BOOTHOP-M4-GUEST-SETUP-v1\n";

const DMI_SYS_VENDOR_PATH: &str = "/sys/class/dmi/id/sys_vendor";
const EFI_PLATFORM_SIZE_PATH: &str = "/sys/firmware/efi/fw_platform_size";
const EFI_VARS_PATH: &str = "/sys/firmware/efi/efivars";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestEvidence<'a> {
    pub fw_cfg_marker: Option<&'a [u8]>,
    pub dmi_sys_vendor: Option<&'a str>,
    pub efi_platform_size: Option<&'a str>,
    pub efivars_present: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestGuardError {
    FwCfgMarkerMissing,
    FwCfgMarkerWrong,
    VmEvidenceMissing,
    HostLikeEvidence,
    UefiEvidenceMissing,
}

/// Validate caller-supplied evidence so the guard can be tested without reading or
/// changing the machine running the tests.
pub fn validate_guest_evidence(evidence: GuestEvidence<'_>) -> Result<(), GuestGuardError> {
    match evidence.fw_cfg_marker {
        None => return Err(GuestGuardError::FwCfgMarkerMissing),
        Some(marker) if marker != FW_CFG_MARKER => {
            return Err(GuestGuardError::FwCfgMarkerWrong);
        }
        Some(_) => {}
    }

    match evidence.dmi_sys_vendor.map(str::trim) {
        None => return Err(GuestGuardError::VmEvidenceMissing),
        Some("QEMU") => {}
        Some(_) => return Err(GuestGuardError::HostLikeEvidence),
    }

    let has_uefi = evidence
        .efi_platform_size
        .map(str::trim)
        .is_some_and(|size| size == "32" || size == "64");
    if !has_uefi || !evidence.efivars_present {
        return Err(GuestGuardError::UefiEvidenceMissing);
    }

    Ok(())
}

/// Read the fixed QEMU fw_cfg, DMI, and UEFI evidence paths and reject any incomplete or
/// conflicting observation. No caller-controlled path participates in this decision.
pub fn require_current_qemu_uefi_guest() -> Result<(), GuestGuardError> {
    let marker = fs::read(FW_CFG_MARKER_PATH).ok();
    let vendor = fs::read_to_string(DMI_SYS_VENDOR_PATH).ok();
    let platform_size = fs::read_to_string(EFI_PLATFORM_SIZE_PATH).ok();
    let evidence = GuestEvidence {
        fw_cfg_marker: marker.as_deref(),
        dmi_sys_vendor: vendor.as_deref(),
        efi_platform_size: platform_size.as_deref(),
        efivars_present: Path::new(EFI_VARS_PATH).is_dir(),
    };
    validate_guest_evidence(evidence)
}
