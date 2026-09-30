#![cfg(target_os = "linux")]

use boothop_platform::linux::uki::{
    ArchConfigFs, CmdlineSource, UkiInput, UkiPolicy, discover_uki_plan,
};
use std::collections::BTreeMap;

#[derive(Default)]
struct FixtureFs {
    files: BTreeMap<String, String>,
    directories: Vec<String>,
}

impl FixtureFs {
    fn arch() -> Self {
        let mut fs = Self::default();
        fs.directories.extend([
            "/boot".into(),
            "/boot/EFI".into(),
            "/boot/EFI/BootHop".into(),
            "/etc/boothop/cmdline.d".into(),
        ]);
        fs.files.insert(
            "/etc/mkinitcpio.d/linux.preset".into(),
            "ALL_kver='/boot/vmlinuz-linux'\nALL_config='/etc/mkinitcpio.conf'\nPRESETS=('default')\ndefault_image='/boot/initramfs-linux.img'\ndefault_uki='/boot/EFI/BootHop/arch.efi.staging'\ndefault_cmdline='/etc/boothop/cmdline'\n".into(),
        );
        fs.files
            .insert("/etc/boothop/cmdline".into(), "root=UUID=abc rw".into());
        fs.files.insert(
            "/etc/mkinitcpio.conf".into(),
            "HOOKS=(base udev autodetect microcode modconf block filesystems)\n".into(),
        );
        fs.files
            .insert("/boot/vmlinuz-linux".into(), "kernel".into());
        fs.files
            .insert("/boot/initramfs-linux.img".into(), "initramfs".into());
        fs
    }

    fn insert(&mut self, path: &str, value: &str) {
        self.files.insert(path.into(), value.into());
    }

    fn remove(&mut self, path: &str) {
        self.files.remove(path);
    }

    fn use_default_mkinitcpio_config(&mut self) {
        if let Some(preset) = self.files.get_mut("/etc/mkinitcpio.d/linux.preset") {
            *preset = preset.replace("ALL_config='/etc/mkinitcpio.conf'\n", "");
        }
    }
}

impl ArchConfigFs for FixtureFs {
    fn read_text(&self, path: &str) -> Result<Option<String>, String> {
        Ok(self.files.get(path).cloned())
    }

    fn is_file(&self, path: &str) -> bool {
        self.files.contains_key(path)
    }

    fn is_directory(&self, path: &str) -> bool {
        self.directories.iter().any(|dir| dir == path)
    }

    fn is_mounted_esp(&self, mount_path: &str) -> bool {
        mount_path == "/boot"
    }

    fn files_in_directory(&self, path: &str) -> Result<Vec<String>, String> {
        let prefix = format!("{}/", path.trim_end_matches('/'));
        Ok(self
            .files
            .keys()
            .filter(|file| file.starts_with(&prefix) && !file[prefix.len()..].contains('/'))
            .cloned()
            .collect())
    }
}

fn policy() -> UkiPolicy {
    UkiPolicy {
        selected_flavor: Some("linux".into()),
        esp_mount: "/boot".into(),
        secure_boot_required: false,
        signer_configured: false,
    }
}

#[test]
fn discovers_active_preset_and_complete_fixed_path_plan() {
    let fs = FixtureFs::arch();

    let plan = discover_uki_plan(&fs, &policy()).unwrap();

    assert_eq!(plan.kernel_flavor, "linux");
    assert_eq!(plan.kernel_image, "/boot/vmlinuz-linux");
    assert_eq!(plan.preset_path, "/etc/mkinitcpio.d/linux.preset");
    assert_eq!(plan.config_path, "/etc/mkinitcpio.conf");
    assert_eq!(plan.final_uki_path, "EFI/BootHop/arch.efi");
    assert_eq!(plan.staged_uki_path, "EFI/BootHop/arch.efi.staging");
    assert_eq!(plan.command_line, "root=UUID=abc rw");
    assert_eq!(plan.command_line_source, CmdlineSource::Preset);
    assert!(plan.includes_microcode);
    assert!(plan.validation.require_efi_application);
    assert!(!plan.secure_boot.signing_required);
    assert!(
        plan.inputs
            .contains(&UkiInput::Kernel("/boot/vmlinuz-linux".into()))
    );
    assert!(
        plan.inputs
            .contains(&UkiInput::Initramfs("/boot/initramfs-linux.img".into()))
    );
    assert!(plan.inputs.contains(&UkiInput::EarlyMicrocodeFromInitramfs(
        "/boot/initramfs-linux.img".into()
    )));
    assert!(
        plan.inputs
            .contains(&UkiInput::ConfirmedCommandLine("root=UUID=abc rw".into()))
    );
}

#[test]
fn preset_specific_kernel_and_config_override_all_values() {
    let mut fs = FixtureFs::arch();
    fs.insert("/boot/vmlinuz-linux-default", "selected kernel");
    fs.insert("/boot/initramfs-linux-default.img", "selected initramfs");
    fs.insert(
        "/etc/mkinitcpio-default.conf",
        "HOOKS=(base udev block filesystems)\n",
    );
    fs.insert(
        "/etc/mkinitcpio.d/linux.preset",
        "ALL_kver='/boot/vmlinuz-linux'\nALL_config='/etc/mkinitcpio.conf'\nPRESETS=('default')\ndefault_kver='/boot/vmlinuz-linux-default'\ndefault_config='/etc/mkinitcpio-default.conf'\ndefault_image='/boot/initramfs-linux-default.img'\ndefault_uki='/boot/EFI/BootHop/arch.efi.staging'\ndefault_cmdline='/etc/boothop/cmdline'\n",
    );
    fs.insert(
        "/etc/mkinitcpio.conf.d/20-conflicting-default.conf",
        "HOOKS=(base udev microcode block filesystems)\n",
    );

    let plan = discover_uki_plan(&fs, &policy()).unwrap();

    assert_eq!(plan.kernel_image, "/boot/vmlinuz-linux-default");
    assert_eq!(plan.config_path, "/etc/mkinitcpio-default.conf");
    assert_eq!(plan.initramfs_image, "/boot/initramfs-linux-default.img");
    assert!(!plan.includes_microcode);
}

#[test]
fn static_dropins_add_or_remove_microcode_in_sorted_override_order() {
    let mut added = FixtureFs::arch();
    added.use_default_mkinitcpio_config();
    added.insert(
        "/etc/mkinitcpio.conf",
        "HOOKS=(base udev block filesystems)\n",
    );
    added.insert(
        "/etc/mkinitcpio.conf.d/20-boothop.conf",
        "HOOKS=(base udev microcode block filesystems)\n",
    );
    assert!(
        discover_uki_plan(&added, &policy())
            .unwrap()
            .includes_microcode
    );

    let mut removed = FixtureFs::arch();
    removed.use_default_mkinitcpio_config();
    removed.insert(
        "/etc/mkinitcpio.conf.d/10-no-microcode.conf",
        "HOOKS=(base udev block filesystems)\n",
    );
    removed.insert(
        "/etc/mkinitcpio.conf.d/20-microcode.conf",
        "HOOKS=(base udev microcode block filesystems)\n",
    );
    removed.insert(
        "/etc/mkinitcpio.conf.d/30-final.conf",
        "HOOKS=(base udev block filesystems)\n",
    );
    assert!(
        !discover_uki_plan(&removed, &policy())
            .unwrap()
            .includes_microcode
    );
}

#[test]
fn unsupported_or_dynamic_mkinitcpio_dropin_fails_closed() {
    let mut fs = FixtureFs::arch();
    fs.use_default_mkinitcpio_config();
    fs.insert(
        "/etc/mkinitcpio.conf.d/20-dynamic.conf",
        "HOOKS+=(microcode)\n",
    );

    let error = discover_uki_plan(&fs, &policy()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported mkinitcpio config/drop-in syntax")
    );
}

#[test]
fn rejects_ambiguous_installed_kernel_flavors_without_policy_selection() {
    let mut fs = FixtureFs::arch();
    fs.insert(
        "/etc/mkinitcpio.d/linux-zen.preset",
        "ALL_kver='/boot/vmlinuz-linux-zen'\nALL_config='/etc/mkinitcpio.conf'\nPRESETS=('default')\ndefault_image='/boot/initramfs-linux-zen.img'\ndefault_cmdline='root=UUID=abc rw'\n",
    );
    fs.insert("/boot/vmlinuz-linux-zen", "kernel");
    fs.insert("/boot/initramfs-linux-zen.img", "initramfs");

    let mut choice = policy();
    choice.selected_flavor = None;
    let error = discover_uki_plan(&fs, &choice).unwrap_err();

    assert!(error.to_string().contains("select"));
    assert!(error.to_string().contains("linux-zen"));
}

#[test]
fn rejects_unsupported_preset_layout_and_unmounted_or_unsafe_esp_paths() {
    let mut fs = FixtureFs::arch();
    fs.insert(
        "/etc/mkinitcpio.d/linux.preset",
        "default_image='/boot/initramfs-linux.img'\ndefault_cmdline='root=UUID=abc rw'\n",
    );
    assert!(discover_uki_plan(&fs, &policy()).is_err());

    let fs = FixtureFs::arch();
    let mut direct_to_stable = FixtureFs::arch();
    direct_to_stable.insert(
        "/etc/mkinitcpio.d/linux.preset",
        "ALL_kver='/boot/vmlinuz-linux'\nALL_config='/etc/mkinitcpio.conf'\nPRESETS=('default')\ndefault_image='/boot/initramfs-linux.img'\ndefault_uki='/boot/EFI/BootHop/arch.efi'\ndefault_cmdline='/etc/boothop/cmdline'\n",
    );
    let error = discover_uki_plan(&direct_to_stable, &policy()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("stable path is never a build target")
    );

    let mut unmounted = policy();
    unmounted.esp_mount = "/efi".into();
    assert!(discover_uki_plan(&fs, &unmounted).is_err());

    let mut unsafe_path = policy();
    unsafe_path.esp_mount = "/boot/../etc".into();
    assert!(discover_uki_plan(&fs, &unsafe_path).is_err());
}

#[test]
fn preset_cmdline_precedes_static_file_and_proc_only_fallback_is_rejected() {
    let mut fs = FixtureFs::arch();
    fs.insert("/etc/kernel/cmdline", "root=UUID=deadbeef quiet");
    fs.insert("/proc/cmdline", "root=UUID=proc");
    assert_eq!(
        discover_uki_plan(&fs, &policy()).unwrap().command_line,
        "root=UUID=abc rw"
    );

    let mut no_preset_cmdline = FixtureFs::arch();
    no_preset_cmdline.insert(
        "/etc/mkinitcpio.d/linux.preset",
        "ALL_kver='/boot/vmlinuz-linux'\nALL_config='/etc/mkinitcpio.conf'\nPRESETS=('default')\ndefault_image='/boot/initramfs-linux.img'\ndefault_uki='/boot/EFI/BootHop/arch.efi.staging'\n",
    );
    no_preset_cmdline.insert("/etc/kernel/cmdline", "root=UUID=deadbeef quiet");
    assert_eq!(
        discover_uki_plan(&no_preset_cmdline, &policy())
            .unwrap()
            .command_line,
        "root=UUID=deadbeef quiet"
    );

    no_preset_cmdline.remove("/etc/kernel/cmdline");
    no_preset_cmdline.insert("/etc/cmdline.d/boothop.conf", "root=PARTUUID=def rw");
    assert_eq!(
        discover_uki_plan(&no_preset_cmdline, &policy())
            .unwrap()
            .command_line,
        "root=PARTUUID=def rw"
    );
    no_preset_cmdline.remove("/etc/cmdline.d/boothop.conf");
    no_preset_cmdline.insert("/proc/cmdline", "root=UUID=proc");
    let error = discover_uki_plan(&no_preset_cmdline, &policy()).unwrap_err();
    assert!(error.to_string().contains("persistent"));
}

#[test]
fn preset_cmdline_must_be_an_absolute_regular_file_path() {
    for cmdline_value in ["root=UUID=inline rw", "cmdline", "/etc/boothop/cmdline.d"] {
        let mut fs = FixtureFs::arch();
        if cmdline_value == "cmdline" {
            fs.insert("cmdline", "root=UUID=relative rw");
        }
        fs.insert(
            "/etc/mkinitcpio.d/linux.preset",
            &format!("ALL_kver='/boot/vmlinuz-linux'\nALL_config='/etc/mkinitcpio.conf'\nPRESETS=('default')\ndefault_image='/boot/initramfs-linux.img'\ndefault_uki='/boot/EFI/BootHop/arch.efi.staging'\ndefault_cmdline='{cmdline_value}'\n"),
        );

        assert!(
            discover_uki_plan(&fs, &policy()).is_err(),
            "preset cmdline value {cmdline_value:?} must be rejected"
        );
    }
}

#[test]
fn secure_boot_requires_an_existing_signer_and_records_verification_expectations() {
    let fs = FixtureFs::arch();
    let mut secure = policy();
    secure.secure_boot_required = true;
    assert!(
        discover_uki_plan(&fs, &secure)
            .unwrap_err()
            .to_string()
            .contains("already-configured")
    );

    secure.signer_configured = true;
    let plan = discover_uki_plan(&fs, &secure).unwrap();
    assert!(plan.secure_boot.signing_required);
    assert!(plan.secure_boot.signer_already_configured);
    assert!(plan.validation.verify_after_signing);
}

#[test]
fn rejects_dynamic_cmdline_and_missing_kernel_or_initramfs() {
    let mut dynamic = FixtureFs::arch();
    dynamic.insert(
        "/etc/mkinitcpio.d/linux.preset",
        "ALL_kver='/boot/vmlinuz-linux'\nALL_config='/etc/mkinitcpio.conf'\nPRESETS=('default')\ndefault_image='/boot/initramfs-linux.img'\ndefault_uki='/boot/EFI/BootHop/arch.efi.staging'\ndefault_cmdline=\"$(cat /proc/cmdline)\"\n",
    );
    assert!(discover_uki_plan(&dynamic, &policy()).is_err());

    let mut missing_kernel = FixtureFs::arch();
    missing_kernel.remove("/boot/vmlinuz-linux");
    assert!(discover_uki_plan(&missing_kernel, &policy()).is_err());

    let mut missing_initramfs = FixtureFs::arch();
    missing_initramfs.remove("/boot/initramfs-linux.img");
    assert!(discover_uki_plan(&missing_initramfs, &policy()).is_err());
}

#[test]
fn rejects_unsupported_root_and_crypt_configuration() {
    for cmdline in [
        "root=/dev/nfs ip=dhcp",
        "cryptdevice=UUID=abc:cryptroot root=/dev/mapper/cryptroot",
    ] {
        let mut fs = FixtureFs::arch();
        fs.insert(
            "/etc/mkinitcpio.d/linux.preset",
            "ALL_kver='/boot/vmlinuz-linux'\nALL_config='/etc/mkinitcpio.conf'\nPRESETS=('default')\ndefault_image='/boot/initramfs-linux.img'\ndefault_uki='/boot/EFI/BootHop/arch.efi.staging'\ndefault_cmdline='/etc/boothop/cmdline'\n",
        );
        fs.insert("/etc/boothop/cmdline", cmdline);
        assert!(discover_uki_plan(&fs, &policy()).is_err(), "{cmdline}");
    }
}

#[test]
fn root_identifier_must_be_unique_nonempty_and_conservatively_valid() {
    for cmdline in [
        "root=UUID= rw",
        "root=PARTUUID= rw",
        "root=UUID=abc root=UUID=def rw",
        "root=UUID=abc root=PARTUUID=def rw",
        "root=UUID=abc/def rw",
        "root=PARTUUID=abc:def rw",
        "root=UUID=not-a-uuid rw",
        "root=UUID=--- rw",
        "root=UUID=-abc rw",
        "root=UUID=abc- rw",
        "root=UUID=ab--cd rw",
    ] {
        let mut fs = FixtureFs::arch();
        fs.insert(
            "/etc/mkinitcpio.d/linux.preset",
            "ALL_kver='/boot/vmlinuz-linux'\nALL_config='/etc/mkinitcpio.conf'\nPRESETS=('default')\ndefault_image='/boot/initramfs-linux.img'\ndefault_uki='/boot/EFI/BootHop/arch.efi.staging'\ndefault_cmdline='/etc/boothop/cmdline'\n",
        );
        fs.insert("/etc/boothop/cmdline", cmdline);
        assert!(discover_uki_plan(&fs, &policy()).is_err(), "{cmdline}");
    }

    for cmdline in [
        "root=UUID=123e4567-e89b-12d3-a456-426614174000 rw",
        "root=UUID=ABCDEF12-3456-7890-ABCD-EF1234567890 rw",
        "root=PARTUUID=123e4567-e89b-12d3-a456-426614174000 rw",
        "root=PARTUUID=12345678-01 rw",
    ] {
        let mut fs = FixtureFs::arch();
        fs.insert(
            "/etc/mkinitcpio.d/linux.preset",
            "ALL_kver='/boot/vmlinuz-linux'\nALL_config='/etc/mkinitcpio.conf'\nPRESETS=('default')\ndefault_image='/boot/initramfs-linux.img'\ndefault_uki='/boot/EFI/BootHop/arch.efi.staging'\ndefault_cmdline='/etc/boothop/cmdline'\n",
        );
        fs.insert("/etc/boothop/cmdline", cmdline);
        assert!(discover_uki_plan(&fs, &policy()).is_ok(), "{cmdline}");
    }
}
