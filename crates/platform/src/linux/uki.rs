use std::fmt;

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
    validate_esp(fs, &policy.esp_mount)?;
    if policy.secure_boot_required && !policy.signer_configured {
        return Err(UkiDiscoveryError::SigningNotConfigured);
    }

    let flavors = ["linux", "linux-zen"]
        .into_iter()
        .filter(|flavor| fs.is_file(&format!("/etc/mkinitcpio.d/{flavor}.preset")))
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
    let preset = read_required(fs, &preset_path)?;
    let values = parse_assignments(&preset);
    let kernel_image = value(&values, "default_kver")
        .or_else(|| value(&values, "ALL_kver"))
        .ok_or_else(|| unsupported("preset must define ALL_kver or default_kver"))?;
    let config_path = value(&values, "default_config")
        .or_else(|| value(&values, "ALL_config"))
        .unwrap_or_else(|| "/etc/mkinitcpio.conf".into());
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
    if !fs.is_file(&kernel_image) {
        return Err(unsupported(format!(
            "selected kernel image is missing: {kernel_image}"
        )));
    }
    if !fs.is_file(&initramfs_image) {
        return Err(unsupported(format!(
            "selected initramfs image is missing: {initramfs_image}"
        )));
    }
    let config = read_required(fs, &config_path)?;
    let includes_microcode = discover_microcode_hook(fs, &config_path, &config)?;

    let (command_line_source, command_line) = discover_cmdline(fs, &values)?;
    validate_cmdline(&command_line)?;

    let signing_required = policy.secure_boot_required;
    let mut inputs = vec![
        UkiInput::Kernel(kernel_image.clone()),
        UkiInput::Initramfs(initramfs_image.clone()),
    ];
    if includes_microcode {
        inputs.push(UkiInput::EarlyMicrocodeFromInitramfs(
            initramfs_image.clone(),
        ));
    }
    inputs.push(UkiInput::ConfirmedCommandLine(command_line.clone()));

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

fn validate_esp(fs: &impl ArchConfigFs, mount: &str) -> Result<(), UkiDiscoveryError> {
    if !mount.starts_with('/')
        || mount
            .split('/')
            .any(|component| component == ".." || component == ".")
    {
        return Err(UkiDiscoveryError::InvalidEsp(
            "ESP mount path must be an absolute normalized path".into(),
        ));
    }
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

fn read_required(fs: &impl ArchConfigFs, path: &str) -> Result<String, UkiDiscoveryError> {
    fs.read_text(path)
        .map_err(UkiDiscoveryError::Io)?
        .ok_or_else(|| unsupported(format!("required Arch input is missing: {path}")))
}

fn discover_microcode_hook(
    fs: &impl ArchConfigFs,
    config_path: &str,
    main_config: &str,
) -> Result<bool, UkiDiscoveryError> {
    let mut hooks = parse_static_config_hooks(main_config, config_path)?
        .ok_or_else(|| unsupported(format!("{config_path} does not define static HOOKS")))?;
    let dropin_dir = "/etc/mkinitcpio.conf.d";
    let mut dropins = fs
        .files_in_directory(dropin_dir)
        .map_err(UkiDiscoveryError::Io)?
        .into_iter()
        .filter(|path| path.ends_with(".conf"))
        .collect::<Vec<_>>();
    if dropins.len() > 64 {
        return Err(unsupported("too many mkinitcpio config drop-ins"));
    }
    for path in &dropins {
        let prefix = format!("{dropin_dir}/");
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
    for path in dropins {
        let text = read_required(fs, &path)?;
        if let Some(override_hooks) = parse_static_config_hooks(&text, &path)? {
            hooks = override_hooks;
        }
    }
    Ok(hooks.iter().any(|hook| hook == "microcode"))
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
    fs: &impl ArchConfigFs,
    preset: &std::collections::BTreeMap<String, String>,
) -> Result<(CmdlineSource, String), UkiDiscoveryError> {
    if let Some(value) = value(preset, "default_cmdline").or_else(|| value(preset, "ALL_cmdline")) {
        if is_dynamic(&value) {
            return Err(UkiDiscoveryError::InvalidCommandLine(
                "preset command line is dynamic; configure a static persistent command line".into(),
            ));
        }
        let resolved = if value.starts_with('/') {
            fs.read_text(&value)
                .map_err(UkiDiscoveryError::Io)?
                .ok_or_else(|| {
                    UkiDiscoveryError::InvalidCommandLine(format!(
                        "preset command-line file is missing: {value}"
                    ))
                })?
        } else {
            value
        };
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
        if let Some(value) = fs.read_text(path).map_err(UkiDiscoveryError::Io)? {
            if is_dynamic(&value) {
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
    let root = tokens.iter().find_map(|token| token.strip_prefix("root="));
    match root {
        Some(root) if root.starts_with("UUID=") || root.starts_with("PARTUUID=") => Ok(()),
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

/// Injected publication boundary. `write_stage` must target the plan's sibling staging file;
/// `rename_stage_over_final` must perform a same-filesystem atomic replace and leave `final`
/// untouched on error.
pub trait UkiPublishFs {
    fn write_stage(&mut self, path: &str, contents: &[u8]) -> Result<(), UkiBuildError>;
    fn rename_stage_over_final(
        &mut self,
        stage_path: &str,
        final_path: &str,
    ) -> Result<(), UkiBuildError>;
}

pub fn build_and_publish_uki(
    plan: &UkiBuildPlan,
    builder: &mut impl UkiBuildBackend,
    publisher: &mut impl UkiPublishFs,
) -> Result<(), UkiBuildError> {
    if plan.final_uki_path != FINAL_UKI_PATH || plan.staged_uki_path != STAGED_UKI_PATH {
        return Err(UkiBuildError::Publish(
            "UKI publication paths must match the fixed BootHop paths".into(),
        ));
    }
    let mut artifact = builder.build(plan)?;
    builder.validate(&artifact, plan)?;
    builder.sign_if_required(&mut artifact, plan)?;
    builder.validate(&artifact, plan)?;
    publisher.write_stage(&plan.staged_uki_path, &artifact)?;
    publisher.rename_stage_over_final(&plan.staged_uki_path, &plan.final_uki_path)
}
