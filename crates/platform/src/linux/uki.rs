use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use boothop_core::{ArchProvisionState, PublishMetadata};
use sha2::{Digest, Sha256};

pub const FINAL_UKI_PATH: &str = "EFI/BootHop/arch.efi";
pub const STAGED_UKI_PATH: &str = "EFI/BootHop/arch.efi.staging";

/// Read-only view used to discover an Arch/mkinitcpio configuration. Implementations must not
/// repair mounts, execute commands, or write files; production callers should provide a bounded
/// view of explicitly selected configuration inputs.
pub trait ArchConfigFs {
    fn read_text(&self, path: &str) -> Result<Option<String>, String>;
    fn is_file(&self, path: &str) -> bool;
    fn is_directory(&self, path: &str) -> bool;
    fn is_mounted_esp(&self, mount_path: &str) -> bool;
    fn files_in_directory(&self, path: &str) -> Result<Vec<String>, String>;
}

/// Immutable read-only inputs for the pure UKI planner. The production entry point builds this
/// snapshot from the standard Arch paths; tests can exercise all selection and validation logic
/// without calling a filesystem-boundary function.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UkiConfigSnapshot {
    pub mounted_esp: Option<String>,
    pub esp_efi_directory: bool,
    pub esp_boothop_directory: bool,
    pub regular_files: BTreeSet<String>,
    pub text_files: BTreeMap<String, String>,
    pub directory_entries: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UkiPolicy {
    /// Must be explicitly selected when more than one supported preset is installed.
    pub selected_flavor: Option<String>,
    pub esp_mount: String,
    pub secure_boot_required: bool,
    /// Discovery only records whether a signer is already configured. It never provisions one.
    pub signer_configured: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CmdlineSource {
    Preset,
    KernelCmdlineFile,
    BootHopCmdlineFile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UkiInput {
    Kernel(String),
    Initramfs(String),
    EarlyMicrocodeFromInitramfs(String),
    ConfirmedCommandLine(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UkiValidation {
    pub require_efi_application: bool,
    pub require_kernel_section: bool,
    pub require_initrd_section: bool,
    pub require_cmdline_section: bool,
    pub verify_after_signing: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureBootPlan {
    pub signing_required: bool,
    pub signer_already_configured: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UkiBuildPlan {
    pub kernel_flavor: String,
    pub kernel_image: String,
    pub initramfs_image: String,
    pub config_path: String,
    pub preset_path: String,
    pub final_uki_path: String,
    pub staged_uki_path: String,
    pub command_line_source: CmdlineSource,
    pub command_line: String,
    pub includes_microcode: bool,
    pub secure_boot: SecureBootPlan,
    pub validation: UkiValidation,
    pub inputs: Vec<UkiInput>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UkiDiscoveryError {
    Io(String),
    UnsupportedLayout(String),
    InvalidEsp(String),
    FlavorSelectionRequired(Vec<String>),
    InvalidCommandLine(String),
    UnsupportedRoot(String),
    SigningNotConfigured,
}

impl fmt::Display for UkiDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message)
            | Self::UnsupportedLayout(message)
            | Self::InvalidEsp(message)
            | Self::InvalidCommandLine(message)
            | Self::UnsupportedRoot(message) => f.write_str(message),
            Self::FlavorSelectionRequired(flavors) => write!(
                f,
                "multiple Arch kernel presets are installed ({}); explicitly select the BootHop kernel flavor",
                flavors.join(", ")
            ),
            Self::SigningNotConfigured => f.write_str(
                "Secure Boot requires signing, but no already-configured UKI signer is available",
            ),
        }
    }
}

impl std::error::Error for UkiDiscoveryError {}

/// Discovers a stable UKI plan from synthetic or trusted read-only inputs. It never invokes
/// mkinitcpio and never writes to the ESP.
pub fn discover_uki_plan(
    fs: &impl ArchConfigFs,
    policy: &UkiPolicy,
) -> Result<UkiBuildPlan, UkiDiscoveryError> {
    let snapshot = capture_arch_config(fs, policy)?;
    plan_uki_snapshot(&snapshot, policy)
}

/// Purely computes the fixed-path UKI plan from an immutable view of already-read Arch inputs.
/// It does not access a filesystem, execute commands, invoke mkinitcpio, or write the ESP.
pub fn plan_uki_snapshot(
    snapshot: &UkiConfigSnapshot,
    policy: &UkiPolicy,
) -> Result<UkiBuildPlan, UkiDiscoveryError> {
    validate_esp_snapshot(snapshot, &policy.esp_mount)?;
    if policy.secure_boot_required && !policy.signer_configured {
        return Err(UkiDiscoveryError::SigningNotConfigured);
    }

    let flavors = ["linux", "linux-zen"]
        .into_iter()
        .filter(|flavor| {
            snapshot
                .regular_files
                .contains(&format!("/etc/mkinitcpio.d/{flavor}.preset"))
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if flavors.is_empty() {
        return Err(UkiDiscoveryError::UnsupportedLayout(
            "no supported /etc/mkinitcpio.d/linux*.preset was found".into(),
        ));
    }

    let flavor = match policy.selected_flavor.as_deref() {
        Some(selected) if flavors.iter().any(|flavor| flavor == selected) => selected,
        Some(selected) => {
            return Err(UkiDiscoveryError::UnsupportedLayout(format!(
                "selected kernel flavor {selected:?} has no supported mkinitcpio preset"
            )));
        }
        None if flavors.len() == 1 => flavors[0].as_str(),
        None => return Err(UkiDiscoveryError::FlavorSelectionRequired(flavors)),
    };

    let preset_path = format!("/etc/mkinitcpio.d/{flavor}.preset");
    let preset = read_required_snapshot(snapshot, &preset_path)?;
    let values = parse_assignments(&preset);
    let kernel_image = value(&values, "default_kver")
        .or_else(|| value(&values, "ALL_kver"))
        .ok_or_else(|| unsupported("preset must define ALL_kver or default_kver"))?;
    let explicit_config_path =
        value(&values, "default_config").or_else(|| value(&values, "ALL_config"));
    let config_is_explicit = explicit_config_path.is_some();
    let config_path = explicit_config_path.unwrap_or_else(|| "/etc/mkinitcpio.conf".into());
    let initramfs_image = value(&values, "default_image")
        .or_else(|| value(&values, "ALL_image"))
        .ok_or_else(|| {
            unsupported("preset must define default_image or ALL_image for UKI input")
        })?;
    let staged_output = value(&values, "default_uki").or_else(|| value(&values, "ALL_uki"));
    let expected_staged_output = format!(
        "{}/{}",
        policy.esp_mount.trim_end_matches('/'),
        STAGED_UKI_PATH
    );
    if staged_output.as_deref() != Some(expected_staged_output.as_str()) {
        return Err(unsupported(format!(
            "selected preset must write its UKI to the staging path {expected_staged_output}; the stable path is never a build target"
        )));
    }
    if !snapshot.regular_files.contains(&kernel_image) {
        return Err(unsupported(format!(
            "selected kernel image is missing: {kernel_image}"
        )));
    }
    if !snapshot.regular_files.contains(&initramfs_image) {
        return Err(unsupported(format!(
            "selected initramfs image is missing: {initramfs_image}"
        )));
    }
    let config = read_required_snapshot(snapshot, &config_path)?;
    let includes_microcode =
        discover_microcode_hook(snapshot, &config_path, &config, !config_is_explicit)?;

    let (command_line_source, command_line) = discover_cmdline(snapshot, &values)?;
    validate_cmdline(&command_line)?;

    let signing_required = policy.secure_boot_required;
    let inputs = if includes_microcode {
        vec![
            UkiInput::Kernel(kernel_image.clone()),
            UkiInput::Initramfs(initramfs_image.clone()),
            UkiInput::EarlyMicrocodeFromInitramfs(initramfs_image.clone()),
            UkiInput::ConfirmedCommandLine(command_line.clone()),
        ]
    } else {
        vec![
            UkiInput::Kernel(kernel_image.clone()),
            UkiInput::Initramfs(initramfs_image.clone()),
            UkiInput::ConfirmedCommandLine(command_line.clone()),
        ]
    };

    Ok(UkiBuildPlan {
        kernel_flavor: flavor.to_owned(),
        kernel_image,
        initramfs_image,
        config_path,
        preset_path,
        final_uki_path: FINAL_UKI_PATH.into(),
        staged_uki_path: STAGED_UKI_PATH.into(),
        command_line_source,
        command_line,
        includes_microcode,
        secure_boot: SecureBootPlan {
            signing_required,
            signer_already_configured: policy.signer_configured,
        },
        validation: UkiValidation {
            require_efi_application: true,
            require_kernel_section: true,
            require_initrd_section: true,
            require_cmdline_section: true,
            verify_after_signing: signing_required,
        },
        inputs,
    })
}

fn capture_arch_config(
    fs: &impl ArchConfigFs,
    policy: &UkiPolicy,
) -> Result<UkiConfigSnapshot, UkiDiscoveryError> {
    validate_esp_fs(fs, &policy.esp_mount)?;
    if policy.secure_boot_required && !policy.signer_configured {
        return Err(UkiDiscoveryError::SigningNotConfigured);
    }

    let mut snapshot = UkiConfigSnapshot {
        mounted_esp: Some(policy.esp_mount.clone()),
        esp_efi_directory: true,
        esp_boothop_directory: true,
        ..UkiConfigSnapshot::default()
    };
    let mut flavors = Vec::new();
    for flavor in ["linux", "linux-zen"] {
        let path = format!("/etc/mkinitcpio.d/{flavor}.preset");
        if fs.is_file(&path) {
            snapshot.regular_files.insert(path);
            flavors.push(flavor);
        }
    }
    let selected = match policy.selected_flavor.as_deref() {
        Some(selected) if flavors.contains(&selected) => selected,
        Some(selected) => {
            return Err(UkiDiscoveryError::UnsupportedLayout(format!(
                "selected kernel flavor {selected:?} has no supported mkinitcpio preset"
            )));
        }
        None if flavors.len() == 1 => flavors[0],
        None if flavors.is_empty() => return Ok(snapshot),
        None => {
            return Err(UkiDiscoveryError::FlavorSelectionRequired(
                flavors.into_iter().map(str::to_owned).collect(),
            ));
        }
    };
    let preset_path = format!("/etc/mkinitcpio.d/{selected}.preset");
    let preset = read_required(fs, &preset_path)?;
    snapshot
        .text_files
        .insert(preset_path.clone(), preset.clone());
    let values = parse_assignments(&preset);
    let kernel_image = value(&values, "default_kver")
        .or_else(|| value(&values, "ALL_kver"))
        .ok_or_else(|| unsupported("preset must define ALL_kver or default_kver"))?;
    let initramfs_image = value(&values, "default_image")
        .or_else(|| value(&values, "ALL_image"))
        .ok_or_else(|| {
            unsupported("preset must define default_image or ALL_image for UKI input")
        })?;
    let staged_output = value(&values, "default_uki").or_else(|| value(&values, "ALL_uki"));
    let expected_staged_output = format!(
        "{}/{}",
        policy.esp_mount.trim_end_matches('/'),
        STAGED_UKI_PATH
    );
    if staged_output.as_deref() != Some(expected_staged_output.as_str()) {
        return Err(unsupported(format!(
            "selected preset must write its UKI to the staging path {expected_staged_output}; the stable path is never a build target"
        )));
    }
    for (path, label) in [(&kernel_image, "kernel"), (&initramfs_image, "initramfs")] {
        if !fs.is_file(path) {
            return Err(unsupported(format!(
                "selected {label} image is missing: {path}"
            )));
        }
        snapshot.regular_files.insert(path.clone());
    }

    let explicit_config = value(&values, "default_config").or_else(|| value(&values, "ALL_config"));
    let include_dropins = explicit_config.is_none();
    let config_path = explicit_config.unwrap_or_else(|| "/etc/mkinitcpio.conf".into());
    capture_text_file(fs, &mut snapshot, &config_path)?;

    if include_dropins {
        let dir = "/etc/mkinitcpio.conf.d";
        let paths = validated_dropin_paths(
            fs.files_in_directory(dir).map_err(UkiDiscoveryError::Io)?,
            dir,
        )?;
        snapshot.directory_entries.insert(dir.into(), paths.clone());
        for path in paths {
            capture_text_file(fs, &mut snapshot, &path)?;
        }
    }

    if let Some(path) = value(&values, "default_cmdline").or_else(|| value(&values, "ALL_cmdline"))
    {
        // Dynamic and non-absolute values are rejected by the pure planner before file lookup.
        if path.starts_with('/') && !is_dynamic(&path) && fs.is_file(&path) {
            snapshot.regular_files.insert(path.clone());
            if let Some(text) = fs.read_text(&path).map_err(UkiDiscoveryError::Io)? {
                snapshot.text_files.insert(path, text);
            }
        }
    } else {
        for path in ["/etc/kernel/cmdline", "/etc/cmdline.d/boothop.conf"] {
            if let Some(text) = fs.read_text(path).map_err(UkiDiscoveryError::Io)? {
                snapshot.regular_files.insert(path.into());
                snapshot.text_files.insert(path.into(), text);
                break;
            }
        }
    }

    Ok(snapshot)
}

fn capture_text_file(
    fs: &impl ArchConfigFs,
    snapshot: &mut UkiConfigSnapshot,
    path: &str,
) -> Result<(), UkiDiscoveryError> {
    let text = read_required(fs, path)?;
    snapshot.regular_files.insert(path.into());
    snapshot.text_files.insert(path.into(), text);
    Ok(())
}

fn validate_esp_snapshot(
    snapshot: &UkiConfigSnapshot,
    mount: &str,
) -> Result<(), UkiDiscoveryError> {
    validate_esp_path(mount)?;
    if snapshot.mounted_esp.as_deref() != Some(mount) {
        return Err(UkiDiscoveryError::InvalidEsp(format!(
            "configured ESP path {mount} is not a mounted ESP"
        )));
    }
    if !snapshot.esp_efi_directory || !snapshot.esp_boothop_directory {
        return Err(UkiDiscoveryError::InvalidEsp(
            "mounted ESP must already contain EFI/BootHop; discovery does not create it".into(),
        ));
    }
    Ok(())
}

fn validate_esp_fs(fs: &impl ArchConfigFs, mount: &str) -> Result<(), UkiDiscoveryError> {
    validate_esp_path(mount)?;
    if !fs.is_mounted_esp(mount) {
        return Err(UkiDiscoveryError::InvalidEsp(format!(
            "configured ESP path {mount} is not a mounted ESP"
        )));
    }
    let directory = |relative: &str| format!("{}/{}", mount.trim_end_matches('/'), relative);
    if !fs.is_directory(&directory("EFI")) || !fs.is_directory(&directory("EFI/BootHop")) {
        return Err(UkiDiscoveryError::InvalidEsp(
            "mounted ESP must already contain EFI/BootHop; discovery does not create it".into(),
        ));
    }
    Ok(())
}

fn validate_esp_path(mount: &str) -> Result<(), UkiDiscoveryError> {
    if !mount.starts_with('/')
        || mount
            .split('/')
            .any(|component| component == ".." || component == ".")
    {
        return Err(UkiDiscoveryError::InvalidEsp(
            "ESP mount path must be an absolute normalized path".into(),
        ));
    }
    Ok(())
}

fn read_required(fs: &impl ArchConfigFs, path: &str) -> Result<String, UkiDiscoveryError> {
    fs.read_text(path)
        .map_err(UkiDiscoveryError::Io)?
        .ok_or_else(|| unsupported(format!("required Arch input is missing: {path}")))
}

fn read_required_snapshot(
    snapshot: &UkiConfigSnapshot,
    path: &str,
) -> Result<String, UkiDiscoveryError> {
    snapshot
        .text_files
        .get(path)
        .cloned()
        .ok_or_else(|| unsupported(format!("required Arch input is missing: {path}")))
}

fn discover_microcode_hook(
    snapshot: &UkiConfigSnapshot,
    config_path: &str,
    main_config: &str,
    include_default_dropins: bool,
) -> Result<bool, UkiDiscoveryError> {
    let mut hooks = parse_static_config_hooks(main_config, config_path)?
        .ok_or_else(|| unsupported(format!("{config_path} does not define static HOOKS")))?;
    if !include_default_dropins {
        return Ok(hooks.iter().any(|hook| hook == "microcode"));
    }
    let dropin_dir = "/etc/mkinitcpio.conf.d";
    let mut dropins = validated_dropin_paths(
        snapshot
            .directory_entries
            .get(dropin_dir)
            .cloned()
            .unwrap_or_default(),
        dropin_dir,
    )?;
    dropins.sort();
    for path in dropins {
        let text = read_required_snapshot(snapshot, &path)?;
        if let Some(override_hooks) = parse_static_config_hooks(&text, &path)? {
            hooks = override_hooks;
        }
    }
    Ok(hooks.iter().any(|hook| hook == "microcode"))
}

fn validated_dropin_paths(
    paths: Vec<String>,
    dropin_dir: &str,
) -> Result<Vec<String>, UkiDiscoveryError> {
    let mut dropins = paths
        .into_iter()
        .filter(|path| path.ends_with(".conf"))
        .collect::<Vec<_>>();
    if dropins.len() > 64 {
        return Err(unsupported("too many mkinitcpio config drop-ins"));
    }
    let prefix = format!("{dropin_dir}/");
    for path in &dropins {
        if !path.starts_with(&prefix)
            || path[prefix.len()..].is_empty()
            || path[prefix.len()..].contains('/')
        {
            return Err(unsupported(format!(
                "unsupported mkinitcpio drop-in path: {path}"
            )));
        }
    }
    dropins.sort();
    Ok(dropins)
}

/// Parse only bounded static assignments. This intentionally does not interpret shell syntax,
/// source files, expand variables, or execute commands. Later static HOOKS assignments replace
/// earlier ones, matching the mkinitcpio config/drop-in precedence used for this setting.
fn parse_static_config_hooks(
    text: &str,
    source: &str,
) -> Result<Option<Vec<String>>, UkiDiscoveryError> {
    let mut hooks = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            return Err(unsupported(format!(
                "unsupported mkinitcpio config/drop-in syntax in {source}"
            )));
        };
        if !valid_shell_name(key) || raw_value.contains(['$', '`', ';', '&', '|', '<', '>']) {
            return Err(unsupported(format!(
                "unsupported mkinitcpio config/drop-in syntax in {source}"
            )));
        }
        if key == "HOOKS" {
            let value = raw_value.trim();
            if !value.starts_with('(') || !value.ends_with(')') {
                return Err(unsupported(format!(
                    "unsupported static HOOKS assignment in {source}"
                )));
            }
            let body = &value[1..value.len() - 1];
            let mut parsed = Vec::new();
            for token in body.split_whitespace() {
                let token = token.trim_matches(['\'', '"']);
                if token.is_empty()
                    || !token
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
                {
                    return Err(unsupported(format!(
                        "unsupported static HOOKS assignment in {source}"
                    )));
                }
                parsed.push(token.to_owned());
            }
            hooks = Some(parsed);
        }
    }
    Ok(hooks)
}

fn valid_shell_name(value: &str) -> bool {
    let mut chars = value.bytes();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && chars.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn parse_assignments(text: &str) -> std::collections::BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, raw) = line.split_once('=')?;
            let value = raw.trim();
            let value = if value.len() >= 2
                && ((value.starts_with('\'') && value.ends_with('\''))
                    || (value.starts_with('"') && value.ends_with('"')))
            {
                value[1..value.len() - 1].to_owned()
            } else {
                value.to_owned()
            };
            Some((key.trim().to_owned(), value))
        })
        .collect()
}

fn value(values: &std::collections::BTreeMap<String, String>, key: &str) -> Option<String> {
    values.get(key).cloned()
}

fn discover_cmdline(
    snapshot: &UkiConfigSnapshot,
    preset: &std::collections::BTreeMap<String, String>,
) -> Result<(CmdlineSource, String), UkiDiscoveryError> {
    if let Some(value) = value(preset, "default_cmdline").or_else(|| value(preset, "ALL_cmdline")) {
        if is_dynamic(&value) {
            return Err(UkiDiscoveryError::InvalidCommandLine(
                "preset command line is dynamic; configure a static persistent command line".into(),
            ));
        }
        if !value.starts_with('/') {
            return Err(UkiDiscoveryError::InvalidCommandLine(
                "preset cmdline must name an absolute regular file path".into(),
            ));
        }
        if !snapshot.regular_files.contains(&value) {
            return Err(UkiDiscoveryError::InvalidCommandLine(format!(
                "preset cmdline is not an existing regular file: {value}"
            )));
        }
        let resolved = snapshot.text_files.get(&value).cloned().ok_or_else(|| {
            UkiDiscoveryError::InvalidCommandLine(format!(
                "preset command-line file is missing: {value}"
            ))
        })?;
        if is_dynamic(&resolved) {
            return Err(UkiDiscoveryError::InvalidCommandLine(
                "preset command line is dynamic; configure a static persistent command line".into(),
            ));
        }
        return Ok((CmdlineSource::Preset, resolved.trim().to_owned()));
    }
    for (path, source) in [
        ("/etc/kernel/cmdline", CmdlineSource::KernelCmdlineFile),
        (
            "/etc/cmdline.d/boothop.conf",
            CmdlineSource::BootHopCmdlineFile,
        ),
    ] {
        if let Some(value) = snapshot.text_files.get(path) {
            if is_dynamic(value) {
                return Err(UkiDiscoveryError::InvalidCommandLine(format!(
                    "{path} contains dynamic command-line content; use a static persistent source"
                )));
            }
            return Ok((source, value.trim().to_owned()));
        }
    }
    Err(UkiDiscoveryError::InvalidCommandLine(
        "no persistent command line is configured; /proc/cmdline fallback is not accepted".into(),
    ))
}

fn is_dynamic(value: &str) -> bool {
    value.contains('$')
        || value.contains('`')
        || value.contains("/proc/cmdline")
        || value.contains('%')
}

fn validate_cmdline(command_line: &str) -> Result<(), UkiDiscoveryError> {
    if command_line.trim().is_empty() || command_line.contains(['\n', '\r', '\0']) {
        return Err(UkiDiscoveryError::InvalidCommandLine(
            "persistent command line must be non-empty and contain one line".into(),
        ));
    }
    let tokens = command_line.split_whitespace().collect::<Vec<_>>();
    if tokens
        .iter()
        .any(|token| token.starts_with("cryptdevice=") || token.starts_with("rd.luks."))
    {
        return Err(UkiDiscoveryError::UnsupportedRoot(
            "crypt/LUKS root configuration is unsupported by this UKI plan".into(),
        ));
    }
    let mut roots = tokens
        .iter()
        .filter_map(|token| token.strip_prefix("root="));
    let root = roots.next();
    if roots.next().is_some() {
        return Err(UkiDiscoveryError::UnsupportedRoot(
            "persistent command line must identify exactly one root= device".into(),
        ));
    }
    match root {
        Some(root) if root.starts_with("UUID=") || root.starts_with("PARTUUID=") => {
            let (_, identifier) = root.split_once('=').expect("prefix has equals");
            if identifier.is_empty()
                || !identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
                || !identifier.bytes().any(|byte| byte.is_ascii_hexdigit())
                || identifier.starts_with('-')
                || identifier.ends_with('-')
                || identifier.contains("--")
            {
                return Err(UkiDiscoveryError::UnsupportedRoot(
                    "root UUID= or PARTUUID= identifier is empty or malformed".into(),
                ));
            }
            Ok(())
        }
        Some(root) => Err(UkiDiscoveryError::UnsupportedRoot(format!(
            "root={root} is unsupported; use a persistent UUID= or PARTUUID= root"
        ))),
        None => Err(UkiDiscoveryError::UnsupportedRoot(
            "persistent command line must identify root=UUID= or root=PARTUUID=".into(),
        )),
    }
}

fn unsupported(message: impl Into<String>) -> UkiDiscoveryError {
    UkiDiscoveryError::UnsupportedLayout(message.into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UkiBuildError {
    Build(String),
    Validation(String),
    Signing(String),
    Publish(String),
    DiskFull,
}

impl fmt::Display for UkiBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(message)
            | Self::Validation(message)
            | Self::Signing(message)
            | Self::Publish(message) => f.write_str(message),
            Self::DiskFull => f.write_str("insufficient space to stage the UKI"),
        }
    }
}

impl std::error::Error for UkiBuildError {}

/// Injected builder boundary. A real implementation may call the configured mkinitcpio path;
/// discovery itself remains side-effect free. Signing must only use an existing signer.
pub trait UkiBuildBackend {
    fn build(&mut self, plan: &UkiBuildPlan) -> Result<Vec<u8>, UkiBuildError>;
    fn validate(&mut self, artifact: &[u8], plan: &UkiBuildPlan) -> Result<(), UkiBuildError>;
    fn sign_if_required(
        &mut self,
        artifact: &mut Vec<u8>,
        plan: &UkiBuildPlan,
    ) -> Result<(), UkiBuildError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UkiFinalPathState {
    Absent,
    /// Metadata for a non-symlink regular file, measured from its exact file contents.
    Regular(PublishMetadata),
    /// Directories, symlinks (including dangling symlinks), and other objects.
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UkiPublicationAuthority {
    /// A journaled initial attempt may publish only while the fixed path remains absent.
    ProvisioningAttempted(PublishMetadata),
    /// Updates are authorized only while the stable file still matches this journaled identity.
    Ready(PublishMetadata),
}

/// Injected publication boundary. `final_path_state` must not follow symlinks and must report a
/// regular file's exact SHA-256 and byte size. `write_stage` must target the plan's sibling
/// staging file. `rename_stage_over_final` must re-enforce the supplied authority at the
/// publication boundary, perform a same-filesystem atomic replace, and leave `final` untouched
/// on error. A production adapter must obtain the authority only from a successfully decoded,
/// root-owned provisioning journal; caller-provided paths or standalone ownership markers are
/// not sufficient.
pub trait UkiPublishFs {
    fn final_path_state(&mut self, path: &str) -> Result<UkiFinalPathState, UkiBuildError>;
    fn write_stage(&mut self, path: &str, contents: &[u8]) -> Result<(), UkiBuildError>;
    fn rename_stage_over_final(
        &mut self,
        stage_path: &str,
        final_path: &str,
        authority: &UkiPublicationAuthority,
    ) -> Result<(), UkiBuildError>;
}

/// Durable journal checkpoints coupled to UKI publication. Implementations must fsync each
/// transition before returning success. The caller must hold the same exclusive provisioning
/// journal lock from loading `journal_state` through this entire transaction, including atomic
/// rename, final-file readback, and the completion checkpoint.
pub trait UkiPublishJournal {
    /// Persist `Provisioning(UkiPublicationAttempted)` with the exact staged artifact metadata.
    fn persist_initial_publication_attempt(
        &mut self,
        metadata: &PublishMetadata,
    ) -> Result<(), UkiBuildError>;
    /// Advance to `Provisioning(UkiPublished)` only after exact final-file readback.
    fn mark_initial_uki_published(
        &mut self,
        metadata: &PublishMetadata,
    ) -> Result<(), UkiBuildError>;
    /// Update `Ready` metadata after exact final-file readback. Success means durable save.
    fn persist_ready_uki_update(&mut self, metadata: &PublishMetadata)
    -> Result<(), UkiBuildError>;
}

pub fn build_and_publish_uki(
    plan: &UkiBuildPlan,
    journal_state: &ArchProvisionState,
    journal: &mut impl UkiPublishJournal,
    builder: &mut impl UkiBuildBackend,
    publisher: &mut impl UkiPublishFs,
) -> Result<PublishMetadata, UkiBuildError> {
    if plan.final_uki_path != FINAL_UKI_PATH || plan.staged_uki_path != STAGED_UKI_PATH {
        return Err(UkiBuildError::Publish(
            "UKI publication paths must match the fixed BootHop paths".into(),
        ));
    }
    match journal_state {
        ArchProvisionState::Provisioning(record)
            if record.owned_entry.uki_path == FINAL_UKI_PATH
                && record.owned_entry.publish.is_none()
                && record.step == boothop_core::ProvisioningStep::UkiPublicationPending
                && record.residual.is_empty() =>
        {
            publish_initial_uki(plan, journal, builder, publisher)
        }
        ArchProvisionState::Provisioning(record)
            if record.step == boothop_core::ProvisioningStep::UkiPublicationAttempted =>
        {
            let _ = verify_interrupted_initial_publication(journal_state, publisher)?;
            Err(UkiBuildError::Publish(
                "interrupted initial UKI publication requires explicit recovery; it will not be retried".into(),
            ))
        }
        ArchProvisionState::Ready(entry) if entry.uki_path == FINAL_UKI_PATH => {
            let old_metadata = entry.publish.as_ref().ok_or_else(|| {
                UkiBuildError::Publish("journaled UKI ownership metadata is missing".into())
            })?;
            publish_ready_update(plan, old_metadata, journal, builder, publisher)
        }
        ArchProvisionState::Provisioning(_) => Err(UkiBuildError::Publish(
            "only the exact UkiPublicationPending checkpoint may start initial UKI publication"
                .into(),
        )),
        ArchProvisionState::Ready(_) => Err(UkiBuildError::Publish(
            "journaled UKI path does not match the fixed BootHop path".into(),
        )),
        ArchProvisionState::Unprovisioned
        | ArchProvisionState::Uninstalling(_)
        | ArchProvisionState::Uninstalled(_) => Err(UkiBuildError::Publish(
            "a valid Provisioning or Ready ownership journal is required".into(),
        )),
    }
}

fn publish_initial_uki(
    plan: &UkiBuildPlan,
    journal: &mut impl UkiPublishJournal,
    builder: &mut impl UkiBuildBackend,
    publisher: &mut impl UkiPublishFs,
) -> Result<PublishMetadata, UkiBuildError> {
    require_absent_final(publisher, &plan.final_uki_path)?;
    let artifact = build_validated_artifact(plan, builder)?;
    let metadata = metadata_for(&artifact);

    // Persist intent before any ESP write. If the process stops during staging or after rename,
    // the Attempted state is reconciliation-only and cannot authorize a rebuild.
    journal.persist_initial_publication_attempt(&metadata)?;
    publisher.write_stage(&plan.staged_uki_path, &artifact)?;
    require_absent_final(publisher, &plan.final_uki_path)?;
    let attempted_authority = UkiPublicationAuthority::ProvisioningAttempted(metadata.clone());
    publisher.rename_stage_over_final(
        &plan.staged_uki_path,
        &plan.final_uki_path,
        &attempted_authority,
    )?;
    require_exact_final(publisher, &plan.final_uki_path, &metadata)?;
    journal.mark_initial_uki_published(&metadata)?;
    Ok(metadata)
}

fn publish_ready_update(
    plan: &UkiBuildPlan,
    old_metadata: &PublishMetadata,
    journal: &mut impl UkiPublishJournal,
    builder: &mut impl UkiBuildBackend,
    publisher: &mut impl UkiPublishFs,
) -> Result<PublishMetadata, UkiBuildError> {
    if old_metadata.size == 0 {
        return Err(UkiBuildError::Publish(
            "journaled UKI ownership metadata is incomplete".into(),
        ));
    }
    require_exact_final(publisher, &plan.final_uki_path, old_metadata)?;
    let artifact = build_validated_artifact(plan, builder)?;
    let new_metadata = metadata_for(&artifact);
    verify_publication_authority(
        publisher,
        &plan.final_uki_path,
        &UkiPublicationAuthority::Ready(old_metadata.clone()),
    )?;
    publisher.write_stage(&plan.staged_uki_path, &artifact)?;
    verify_publication_authority(
        publisher,
        &plan.final_uki_path,
        &UkiPublicationAuthority::Ready(old_metadata.clone()),
    )?;
    publisher.rename_stage_over_final(
        &plan.staged_uki_path,
        &plan.final_uki_path,
        &UkiPublicationAuthority::Ready(old_metadata.clone()),
    )?;
    require_exact_final(publisher, &plan.final_uki_path, &new_metadata)?;
    // If this durable write fails after rename, the journal still describes the old file. The
    // next update consequently fails its old digest/size gate and cannot overwrite blindly.
    journal.persist_ready_uki_update(&new_metadata)?;
    Ok(new_metadata)
}

fn build_validated_artifact(
    plan: &UkiBuildPlan,
    builder: &mut impl UkiBuildBackend,
) -> Result<Vec<u8>, UkiBuildError> {
    let mut artifact = builder.build(plan)?;
    builder.validate(&artifact, plan)?;
    builder.sign_if_required(&mut artifact, plan)?;
    builder.validate(&artifact, plan)?;
    Ok(artifact)
}

fn metadata_for(artifact: &[u8]) -> PublishMetadata {
    PublishMetadata {
        sha256: Sha256::digest(artifact).into(),
        size: artifact.len() as u64,
    }
}

fn require_absent_final(
    publisher: &mut impl UkiPublishFs,
    final_path: &str,
) -> Result<(), UkiBuildError> {
    match publisher.final_path_state(final_path)? {
        UkiFinalPathState::Absent => Ok(()),
        _ => Err(UkiBuildError::Publish(
            "initial provisioning requires an absent stable UKI path".into(),
        )),
    }
}

fn require_exact_final(
    publisher: &mut impl UkiPublishFs,
    final_path: &str,
    expected: &PublishMetadata,
) -> Result<(), UkiBuildError> {
    verify_publication_authority(
        publisher,
        final_path,
        &UkiPublicationAuthority::Ready(expected.clone()),
    )
}

fn verify_publication_authority(
    publisher: &mut impl UkiPublishFs,
    final_path: &str,
    authority: &UkiPublicationAuthority,
) -> Result<(), UkiBuildError> {
    let state = publisher.final_path_state(final_path)?;
    match (authority, state) {
        (UkiPublicationAuthority::ProvisioningAttempted(_), UkiFinalPathState::Absent) => Ok(()),
        (UkiPublicationAuthority::Ready(expected), UkiFinalPathState::Regular(actual))
            if expected == &actual =>
        {
            Ok(())
        }
        (UkiPublicationAuthority::ProvisioningAttempted(_), _) => Err(UkiBuildError::Publish(
            "initial publication requires the stable UKI path to remain absent".into(),
        )),
        (UkiPublicationAuthority::Ready(_), _) => Err(UkiBuildError::Publish(
            "stable UKI does not match journaled ownership metadata".into(),
        )),
    }
}

/// Readback-only reconciliation helper for `Provisioning(UkiPublicationAttempted)`. It never
/// builds, renames, deletes, or advances the journal. A caller may explicitly persist
/// `UkiPublished` only when this returns the exact recorded attempt metadata.
pub fn verify_interrupted_initial_publication(
    journal_state: &ArchProvisionState,
    publisher: &mut impl UkiPublishFs,
) -> Result<PublishMetadata, UkiBuildError> {
    let ArchProvisionState::Provisioning(record) = journal_state else {
        return Err(UkiBuildError::Publish(
            "interrupted initial publication requires a Provisioning journal".into(),
        ));
    };
    let Some(expected) = record.owned_entry.publish.as_ref() else {
        return Err(UkiBuildError::Publish(
            "journal is not at a complete UkiPublicationAttempted checkpoint".into(),
        ));
    };
    if record.step != boothop_core::ProvisioningStep::UkiPublicationAttempted
        || record.owned_entry.uki_path != FINAL_UKI_PATH
        || expected.size == 0
    {
        return Err(UkiBuildError::Publish(
            "journal is not at a complete UkiPublicationAttempted checkpoint".into(),
        ));
    }
    require_exact_final(publisher, FINAL_UKI_PATH, expected)?;
    Ok(expected.clone())
}
