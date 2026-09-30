#![cfg(target_os = "linux")]

use boothop_platform::linux::uki::{
    UkiBuildBackend, UkiBuildError, UkiBuildPlan, UkiConfigSnapshot, UkiPolicy, plan_uki_snapshot,
    prepare_uki_artifact,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn plan() -> UkiBuildPlan {
    let files = BTreeMap::from([
        ("/etc/mkinitcpio.d/linux.preset".to_string(), "ALL_kver='/boot/vmlinuz-linux'\nALL_config='/etc/mkinitcpio.conf'\nALL_image='/boot/initramfs-linux.img'\nALL_uki='/boot/EFI/BootHop/arch.efi.staging'\nALL_cmdline='/etc/boothop/cmdline'\n".to_string()),
        ("/etc/boothop/cmdline".to_string(), "root=UUID=abc rw".to_string()),
        ("/etc/mkinitcpio.conf".to_string(), "HOOKS=(base udev autodetect microcode modconf block filesystems)\n".to_string()),
    ]);
    let mut regular_files: BTreeSet<String> = files.keys().cloned().collect();
    regular_files.insert("/boot/vmlinuz-linux".into());
    regular_files.insert("/boot/initramfs-linux.img".into());
    plan_uki_snapshot(
        &UkiConfigSnapshot {
            mounted_esp: Some("/boot".into()),
            esp_efi_directory: true,
            esp_boothop_directory: true,
            regular_files,
            text_files: files,
            directory_entries: BTreeMap::new(),
        },
        &UkiPolicy {
            selected_flavor: Some("linux".into()),
            esp_mount: "/boot".into(),
            secure_boot_required: false,
            signer_configured: false,
        },
    )
    .unwrap()
}

struct FakeBuilder {
    bytes: Vec<u8>,
    sign_suffix: Vec<u8>,
    fail_on: Option<BuilderFailure>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum BuilderFailure {
    Build,
    Validate,
    Sign,
}
impl UkiBuildBackend for FakeBuilder {
    fn build(&mut self, _: &UkiBuildPlan) -> Result<Vec<u8>, UkiBuildError> {
        if self.fail_on == Some(BuilderFailure::Build) {
            Err(UkiBuildError::Build("fake build failure".into()))
        } else {
            Ok(self.bytes.clone())
        }
    }
    fn validate(&mut self, _: &[u8], _: &UkiBuildPlan) -> Result<(), UkiBuildError> {
        if self.fail_on == Some(BuilderFailure::Validate) {
            Err(UkiBuildError::Validation("fake validation failure".into()))
        } else {
            Ok(())
        }
    }
    fn sign_if_required(
        &mut self,
        bytes: &mut Vec<u8>,
        _: &UkiBuildPlan,
    ) -> Result<(), UkiBuildError> {
        if self.fail_on == Some(BuilderFailure::Sign) {
            return Err(UkiBuildError::Signing("fake signing failure".into()));
        }
        bytes.extend_from_slice(&self.sign_suffix);
        Ok(())
    }
}

#[test]
fn prepared_uki_artifact_contains_the_exact_bounded_signed_bytes_metadata() {
    let mut plan = plan();
    plan.secure_boot.signing_required = true;
    plan.secure_boot.signer_already_configured = true;
    plan.validation.verify_after_signing = true;
    let mut builder = FakeBuilder {
        bytes: b"validated UKI".to_vec(),
        sign_suffix: b" signed".to_vec(),
        fail_on: None,
    };
    let prepared = prepare_uki_artifact(&plan, &mut builder).unwrap();
    let expected = b"validated UKI signed";
    assert_eq!(prepared.bytes(), expected);
    let expected_sha256: [u8; 32] = Sha256::digest(expected).into();
    assert_eq!(prepared.metadata().sha256, expected_sha256);
    assert_eq!(prepared.metadata().size, expected.len() as u64);
}

#[test]
fn build_failure_produces_no_prepared_artifact() {
    let mut builder = FakeBuilder {
        bytes: Vec::new(),
        sign_suffix: Vec::new(),
        fail_on: Some(BuilderFailure::Build),
    };
    assert!(prepare_uki_artifact(&plan(), &mut builder).is_err());
}

#[test]
fn oversized_uki_is_rejected_before_it_can_be_prepared() {
    let mut builder = FakeBuilder {
        bytes: vec![0x5a; 64 * 1024 * 1024 + 1],
        sign_suffix: Vec::new(),
        fail_on: None,
    };
    assert!(prepare_uki_artifact(&plan(), &mut builder).is_err());
}

#[test]
fn unsupported_publication_path_is_rejected_during_preparation() {
    let mut plan = plan();
    plan.final_uki_path = "EFI/BootHop/other.efi".into();
    let mut builder = FakeBuilder {
        bytes: b"uki".to_vec(),
        sign_suffix: Vec::new(),
        fail_on: None,
    };
    assert!(prepare_uki_artifact(&plan, &mut builder).is_err());
}

#[test]
fn validation_and_signing_failures_produce_no_prepared_artifact() {
    for fail_on in [BuilderFailure::Validate, BuilderFailure::Sign] {
        let mut builder = FakeBuilder {
            bytes: b"unsigned UKI".to_vec(),
            sign_suffix: Vec::new(),
            fail_on: Some(fail_on),
        };
        let mut plan = plan();
        plan.secure_boot.signing_required = true;
        plan.secure_boot.signer_already_configured = true;
        plan.validation.verify_after_signing = true;
        assert!(prepare_uki_artifact(&plan, &mut builder).is_err());
    }
}
