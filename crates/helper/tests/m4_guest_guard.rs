#![cfg(all(target_os = "linux", feature = "m4-guest-setup"))]

use boothop_helper::m4_guest_guard::{
    FW_CFG_MARKER, GuestEvidence, GuestGuardError, validate_guest_evidence,
};

fn qemu_uefi_evidence<'a>(marker: Option<&'a [u8]>) -> GuestEvidence<'a> {
    GuestEvidence {
        fw_cfg_marker: marker,
        dmi_sys_vendor: Some("QEMU\n"),
        efi_platform_size: Some("64\n"),
        efivars_present: true,
    }
}

#[test]
fn accepts_the_fixed_marker_with_qemu_and_uefi_evidence() {
    assert_eq!(
        validate_guest_evidence(qemu_uefi_evidence(Some(FW_CFG_MARKER))),
        Ok(())
    );
}

#[test]
fn rejects_an_absent_or_wrong_fw_cfg_marker() {
    assert_eq!(
        validate_guest_evidence(qemu_uefi_evidence(None)),
        Err(GuestGuardError::FwCfgMarkerMissing)
    );
    assert_eq!(
        validate_guest_evidence(qemu_uefi_evidence(Some(b"wrong marker\n"))),
        Err(GuestGuardError::FwCfgMarkerWrong)
    );
}

#[test]
fn rejects_missing_or_host_like_vm_evidence() {
    let mut evidence = qemu_uefi_evidence(Some(FW_CFG_MARKER));
    evidence.dmi_sys_vendor = None;
    assert_eq!(
        validate_guest_evidence(evidence),
        Err(GuestGuardError::VmEvidenceMissing)
    );

    let mut evidence = qemu_uefi_evidence(Some(FW_CFG_MARKER));
    evidence.dmi_sys_vendor = Some("Example Host Vendor\n");
    assert_eq!(
        validate_guest_evidence(evidence),
        Err(GuestGuardError::HostLikeEvidence)
    );
}

#[test]
fn rejects_missing_or_invalid_uefi_evidence() {
    let mut evidence = qemu_uefi_evidence(Some(FW_CFG_MARKER));
    evidence.efi_platform_size = None;
    assert_eq!(
        validate_guest_evidence(evidence),
        Err(GuestGuardError::UefiEvidenceMissing)
    );

    let mut evidence = qemu_uefi_evidence(Some(FW_CFG_MARKER));
    evidence.efi_platform_size = Some("unknown\n");
    assert_eq!(
        validate_guest_evidence(evidence),
        Err(GuestGuardError::UefiEvidenceMissing)
    );

    let mut evidence = qemu_uefi_evidence(Some(FW_CFG_MARKER));
    evidence.efivars_present = false;
    assert_eq!(
        validate_guest_evidence(evidence),
        Err(GuestGuardError::UefiEvidenceMissing)
    );
}
