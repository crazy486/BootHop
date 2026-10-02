#![cfg(target_os = "linux")]

use boothop_core::GptEspIdentity;
use boothop_platform::linux::arch_uki::{
    ArchSetupSource, CmdlineSource, EspInfo, PackageHookRoute, SecureBootState, SetupError,
    plan_arch_uki, render_boothop_preset,
};

const ESP_IDENTITY: GptEspIdentity = GptEspIdentity {
    partition_number: 1,
    start_lba: 2048,
    size_lba: 1_048_576,
    guid_uefi_bytes: [0x11; 16],
};

struct Fixture {
    flavors: Vec<String>,
    cmdline: CmdlineSource,
    esp: EspInfo,
    secure_boot: SecureBootState,
    route: Option<PackageHookRoute>,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            flavors: vec!["linux".into(), "linux-lts".into()],
            cmdline: CmdlineSource::Persistent("/etc/kernel/cmdline".into()),
            esp: EspInfo {
                mount_point: "/boot".into(),
                filesystem: "vfat".into(),
                is_mounted: true,
                is_efi_system_partition: true,
                gpt_identity: Some(ESP_IDENTITY),
            },
            secure_boot: SecureBootState::Disabled,
            route: Some(PackageHookRoute {
                preset: "linux-lts".into(),
                post_hooks_enabled: true,
            }),
        }
    }
}

impl ArchSetupSource for Fixture {
    fn installed_flavors(&self) -> Result<Vec<String>, SetupError> {
        Ok(self.flavors.clone())
    }

    fn cmdline_source(&self) -> Result<CmdlineSource, SetupError> {
        Ok(self.cmdline.clone())
    }

    fn esp_info(&self) -> Result<EspInfo, SetupError> {
        Ok(self.esp.clone())
    }

    fn secure_boot_state(&self) -> Result<SecureBootState, SetupError> {
        Ok(self.secure_boot)
    }

    fn package_hook_route(&self) -> Result<Option<PackageHookRoute>, SetupError> {
        Ok(self.route.clone())
    }
}

#[test]
fn two_installed_flavors_require_explicit_flavor_selection() {
    let source = Fixture::default();

    assert_eq!(
        plan_arch_uki("", &source),
        Err(SetupError::FlavorSelectionRequired)
    );

    let plan = plan_arch_uki("linux-lts", &source).unwrap();
    assert_eq!(plan.flavor(), "linux-lts");
    assert_eq!(
        plan.preset_path().to_str(),
        Some("/etc/mkinitcpio.d/linux-lts.preset")
    );
    assert_eq!(plan.cmdline_path().to_str(), Some("/etc/kernel/cmdline"));
    assert_eq!(
        plan.staged_uki_path().to_str(),
        Some("/boot/EFI/BootHop/arch.efi.tmp")
    );
    assert_eq!(
        plan.final_uki_path().to_str(),
        Some("/boot/EFI/BootHop/arch.efi")
    );
    assert_eq!(plan.esp_identity(), ESP_IDENTITY);
}

#[test]
fn rejects_uninstalled_or_path_like_flavor_names() {
    let source = Fixture::default();

    assert_eq!(
        plan_arch_uki("linux-old", &source),
        Err(SetupError::FlavorNotInstalled)
    );
    assert_eq!(
        plan_arch_uki("../linux", &source),
        Err(SetupError::InvalidFlavor)
    );
    assert_eq!(
        plan_arch_uki("-linux", &source),
        Err(SetupError::InvalidFlavor)
    );
}

#[test]
fn rejects_missing_and_dynamic_kernel_command_lines() {
    for cmdline in [CmdlineSource::Missing, CmdlineSource::Dynamic] {
        let source = Fixture {
            cmdline,
            ..Fixture::default()
        };

        assert!(matches!(
            plan_arch_uki("linux-lts", &source),
            Err(SetupError::UnsupportedCmdline)
        ));
    }
}

#[test]
fn rejects_a_persistent_command_line_from_another_path() {
    let source = Fixture {
        cmdline: CmdlineSource::Persistent("/proc/cmdline".into()),
        ..Fixture::default()
    };

    assert_eq!(
        plan_arch_uki("linux-lts", &source),
        Err(SetupError::UnsupportedCmdline)
    );
}

#[test]
fn rejects_non_vfat_non_esp_or_non_gpt_filesystems() {
    let unsupported = [
        EspInfo {
            filesystem: "ext4".into(),
            ..Fixture::default().esp
        },
        EspInfo {
            is_mounted: false,
            ..Fixture::default().esp
        },
        EspInfo {
            is_efi_system_partition: false,
            ..Fixture::default().esp
        },
        EspInfo {
            gpt_identity: None,
            ..Fixture::default().esp
        },
    ];

    for esp in unsupported {
        let source = Fixture {
            esp,
            ..Fixture::default()
        };
        assert_eq!(
            plan_arch_uki("linux-lts", &source),
            Err(SetupError::UnsupportedEsp)
        );
    }
}

#[test]
fn rejects_secure_boot_enabled_or_unknown() {
    for secure_boot in [SecureBootState::Enabled, SecureBootState::Unknown] {
        let source = Fixture {
            secure_boot,
            ..Fixture::default()
        };
        assert_eq!(
            plan_arch_uki("linux-lts", &source),
            Err(SetupError::UnsupportedSecureBoot)
        );
    }
}

#[test]
fn rejects_unknown_or_mismatched_package_hook_routing() {
    for route in [
        None,
        Some(PackageHookRoute {
            preset: "linux".into(),
            post_hooks_enabled: true,
        }),
        Some(PackageHookRoute {
            preset: "linux-lts".into(),
            post_hooks_enabled: false,
        }),
    ] {
        let source = Fixture {
            route,
            ..Fixture::default()
        };
        assert_eq!(
            plan_arch_uki("linux-lts", &source),
            Err(SetupError::UnknownPackageHookRoute)
        );
    }
}

#[test]
fn preset_renderer_appends_only_boot_hop_and_preserves_existing_outputs() {
    let plan = plan_arch_uki("linux-lts", &Fixture::default()).unwrap();
    let existing = "ALL_kver='/boot/vmlinuz-linux-lts'\nPRESETS=('default' 'fallback')\ndefault_image='/boot/initramfs-linux-lts.img'\nfallback_image='/boot/initramfs-linux-lts-fallback.img'\nfallback_options='-S autodetect'\n";

    let rendered = render_boothop_preset(existing, &plan).unwrap();

    assert!(rendered.contains("PRESETS=('default' 'fallback' 'boothop')\n"));
    assert!(rendered.contains("default_image='/boot/initramfs-linux-lts.img'\n"));
    assert!(rendered.contains("fallback_image='/boot/initramfs-linux-lts-fallback.img'\n"));
    assert!(rendered.contains("fallback_options='-S autodetect'\n"));
    assert!(rendered.contains("boothop_uki='/boot/EFI/BootHop/arch.efi.tmp'\n"));
    assert!(rendered.contains("boothop_cmdline='/etc/kernel/cmdline'\n"));
    assert_eq!(rendered.matches("boothop_uki=").count(), 1);
}

#[test]
fn preset_renderer_refuses_existing_boot_hop_preset_or_assignments() {
    let plan = plan_arch_uki("linux-lts", &Fixture::default()).unwrap();
    for existing in [
        "PRESETS=('default' 'fallback' 'boothop')\n",
        "PRESETS=('default' 'fallback')\nboothop_uki='/old/path'\n",
        "PRESETS=('default' 'fallback')\nboothop_cmdline='/old/cmdline'\n",
        "PRESETS=('default' 'fallback')\nreadonly boothop_uki='/old/path'\n",
        "PRESETS=('default' 'fallback')\nreadonly -r boothop_cmdline='/old/cmdline'\n",
        "PRESETS=('default' 'fallback')\ndeclare -r boothop_uki='/old/path'\n",
        "PRESETS=('default' 'fallback')\ndeclare -xr boothop_cmdline='/old/cmdline'\n",
        "PRESETS=('default' 'fallback')\ndeclare -r unrelated='kept' boothop_uki='/old/path'\n",
    ] {
        assert!(matches!(
            render_boothop_preset(existing, &plan),
            Err(SetupError::ConflictingPreset)
        ));
    }
}

#[test]
fn preset_renderer_allows_readonly_declarations_of_unrelated_variables() {
    let plan = plan_arch_uki("linux-lts", &Fixture::default()).unwrap();
    for declaration in [
        "readonly unrelated='/kept/path'",
        "declare -r unrelated='/kept/path'",
        "declare -r unrelated='/kept/path' another='value'",
    ] {
        let existing = format!("PRESETS=('default' 'fallback')\n{declaration}\n");
        assert!(render_boothop_preset(&existing, &plan).is_ok());
    }
}

#[test]
fn preset_renderer_refuses_dynamic_or_duplicate_presets() {
    let plan = plan_arch_uki("linux-lts", &Fixture::default()).unwrap();
    for existing in [
        "PRESETS=($(discover-presets))\n",
        "PRESETS=('default' 'default')\n",
        "PRESETS=('default' 'fallback')\nPRESETS=('default')\n",
    ] {
        assert!(matches!(
            render_boothop_preset(existing, &plan),
            Err(SetupError::UnsupportedPreset)
        ));
    }
}
