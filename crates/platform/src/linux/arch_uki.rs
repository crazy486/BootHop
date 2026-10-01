use std::path::{Component, Path, PathBuf};

use boothop_core::GptEspIdentity;

const CMDLINE_PATH: &str = "/etc/kernel/cmdline";
const PRESET_DIRECTORY: &str = "/etc/mkinitcpio.d";
const UKI_RELATIVE_DIRECTORY: &str = "EFI/BootHop";
const UKI_FILE: &str = "arch.efi";
const UKI_STAGE_FILE: &str = "arch.efi.tmp";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetupError {
    SourceUnavailable,
    FlavorSelectionRequired,
    InvalidFlavor,
    FlavorNotInstalled,
    UnsupportedCmdline,
    UnsupportedEsp,
    UnsupportedSecureBoot,
    UnknownPackageHookRoute,
    ConflictingPreset,
    UnsupportedPreset,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CmdlineSource {
    Missing,
    Dynamic,
    Persistent(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EspInfo {
    pub mount_point: PathBuf,
    pub filesystem: String,
    pub is_mounted: bool,
    pub is_efi_system_partition: bool,
    pub gpt_identity: Option<GptEspIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureBootState {
    Disabled,
    Enabled,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageHookRoute {
    pub preset: String,
    pub post_hooks_enabled: bool,
}

/// Read-only observations needed to choose and validate the one supported Arch UKI route.
pub trait ArchSetupSource {
    fn installed_flavors(&self) -> Result<Vec<String>, SetupError>;
    fn cmdline_source(&self) -> Result<CmdlineSource, SetupError>;
    fn esp_info(&self) -> Result<EspInfo, SetupError>;
    fn secure_boot_state(&self) -> Result<SecureBootState, SetupError>;
    fn package_hook_route(&self) -> Result<Option<PackageHookRoute>, SetupError>;
}

/// A validated read-only plan consumed by the later explicit setup runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UkiPlan {
    flavor: String,
    preset_path: PathBuf,
    cmdline_path: PathBuf,
    esp_mount_point: PathBuf,
    esp_identity: GptEspIdentity,
    staged_uki_path: PathBuf,
    final_uki_path: PathBuf,
}

impl UkiPlan {
    pub fn flavor(&self) -> &str {
        &self.flavor
    }

    pub fn preset_path(&self) -> &Path {
        &self.preset_path
    }

    pub fn cmdline_path(&self) -> &Path {
        &self.cmdline_path
    }

    pub fn esp_mount_point(&self) -> &Path {
        &self.esp_mount_point
    }

    pub fn esp_identity(&self) -> GptEspIdentity {
        self.esp_identity
    }

    pub fn staged_uki_path(&self) -> &Path {
        &self.staged_uki_path
    }

    pub fn final_uki_path(&self) -> &Path {
        &self.final_uki_path
    }
}

pub fn plan_arch_uki(flavor: &str, source: &impl ArchSetupSource) -> Result<UkiPlan, SetupError> {
    if flavor.is_empty() {
        return Err(SetupError::FlavorSelectionRequired);
    }
    if !is_safe_flavor(flavor) {
        return Err(SetupError::InvalidFlavor);
    }

    let mut installed = source.installed_flavors()?;
    installed.sort();
    if installed.windows(2).any(|pair| pair[0] == pair[1])
        || installed.iter().any(|value| !is_safe_flavor(value))
    {
        return Err(SetupError::UnsupportedPreset);
    }
    if !installed
        .iter()
        .any(|installed_flavor| installed_flavor == flavor)
    {
        return Err(SetupError::FlavorNotInstalled);
    }

    match source.cmdline_source()? {
        CmdlineSource::Persistent(path) if path == Path::new(CMDLINE_PATH) => {}
        CmdlineSource::Missing | CmdlineSource::Dynamic | CmdlineSource::Persistent(_) => {
            return Err(SetupError::UnsupportedCmdline);
        }
    }

    let esp = source.esp_info()?;
    let Some(esp_identity) = esp.gpt_identity else {
        return Err(SetupError::UnsupportedEsp);
    };
    if !esp.is_mounted
        || !esp.is_efi_system_partition
        || esp.filesystem != "vfat"
        || !esp.mount_point.is_absolute()
        || esp.mount_point.to_str().is_none()
        || esp.mount_point.to_string_lossy().contains('\0')
        || esp
            .mount_point
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || esp_identity.partition_number == 0
        || esp_identity.size_lba == 0
        || esp_identity.guid_uefi_bytes.iter().all(|byte| *byte == 0)
    {
        return Err(SetupError::UnsupportedEsp);
    }

    if source.secure_boot_state()? != SecureBootState::Disabled {
        return Err(SetupError::UnsupportedSecureBoot);
    }

    let route = source
        .package_hook_route()?
        .ok_or(SetupError::UnknownPackageHookRoute)?;
    if route.preset != flavor || !route.post_hooks_enabled {
        return Err(SetupError::UnknownPackageHookRoute);
    }

    let preset_path = Path::new(PRESET_DIRECTORY).join(format!("{flavor}.preset"));
    let uki_directory = esp.mount_point.join(UKI_RELATIVE_DIRECTORY);
    Ok(UkiPlan {
        flavor: flavor.to_owned(),
        preset_path,
        cmdline_path: PathBuf::from(CMDLINE_PATH),
        esp_mount_point: esp.mount_point,
        esp_identity,
        staged_uki_path: uki_directory.join(UKI_STAGE_FILE),
        final_uki_path: uki_directory.join(UKI_FILE),
    })
}

/// Add exactly one `boothop` preset while preserving all unrelated preset lines verbatim.
pub fn render_boothop_preset(existing: &str, plan: &UkiPlan) -> Result<String, SetupError> {
    if existing.contains('\0') || !is_safe_flavor(&plan.flavor) {
        return Err(SetupError::UnsupportedPreset);
    }
    let expected_preset = Path::new(PRESET_DIRECTORY).join(format!("{}.preset", plan.flavor));
    let expected_directory = plan.esp_mount_point.join(UKI_RELATIVE_DIRECTORY);
    if plan.preset_path != expected_preset
        || plan.cmdline_path != Path::new(CMDLINE_PATH)
        || plan.staged_uki_path != expected_directory.join(UKI_STAGE_FILE)
        || plan.final_uki_path != expected_directory.join(UKI_FILE)
    {
        return Err(SetupError::UnsupportedPreset);
    }

    let mut preset_line = None;
    let mut offset = 0_usize;
    for line in existing.split_inclusive('\n') {
        let text = line.strip_suffix('\n').unwrap_or(line);
        let trimmed = text.trim_start();
        if trimmed.starts_with("PRESETS") {
            if preset_line.is_some() {
                return Err(SetupError::UnsupportedPreset);
            }
            let (open, close, names) = parse_presets_line(text)?;
            if names.contains(&"boothop".to_owned()) {
                return Err(SetupError::ConflictingPreset);
            }
            preset_line = Some((offset + close, names));
            let _ = open;
        }
        let statement = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        if statement.starts_with("boothop_")
            || statement.starts_with("boothop=")
            || statement.starts_with("declare boothop_")
        {
            return Err(SetupError::ConflictingPreset);
        }
        offset += line.len();
    }
    let Some((insert_at, _names)) = preset_line else {
        return Err(SetupError::UnsupportedPreset);
    };

    let mut rendered = String::with_capacity(existing.len() + 100);
    rendered.push_str(&existing[..insert_at]);
    rendered.push_str(" 'boothop'");
    rendered.push_str(&existing[insert_at..]);
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    rendered.push_str("boothop_uki=");
    rendered.push_str(&shell_quote(&plan.staged_uki_path.to_string_lossy()));
    rendered.push('\n');
    rendered.push_str("boothop_cmdline=");
    rendered.push_str(&shell_quote(&plan.cmdline_path.to_string_lossy()));
    rendered.push('\n');
    Ok(rendered)
}

fn parse_presets_line(line: &str) -> Result<(usize, usize, Vec<String>), SetupError> {
    let left_trim = line.len() - line.trim_start().len();
    let line = &line[left_trim..];
    let Some(equal) = line.find('=') else {
        return Err(SetupError::UnsupportedPreset);
    };
    if line[..equal].trim() != "PRESETS" {
        return Err(SetupError::UnsupportedPreset);
    }
    let rhs = &line[equal + 1..];
    let rhs_leading = rhs.len() - rhs.trim_start().len();
    let open = equal + 1 + rhs_leading;
    if line.as_bytes().get(open) != Some(&b'(') {
        return Err(SetupError::UnsupportedPreset);
    }
    let Some(close_rel) = line[open + 1..].find(')') else {
        return Err(SetupError::UnsupportedPreset);
    };
    let close = open + 1 + close_rel;
    let suffix = line[close + 1..].trim();
    if !suffix.is_empty() && !suffix.starts_with('#') {
        return Err(SetupError::UnsupportedPreset);
    }

    let values = &line[open + 1..close];
    let names = parse_static_array(values)?;
    if names.is_empty() {
        return Err(SetupError::UnsupportedPreset);
    }
    let mut sorted = names.clone();
    sorted.sort();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SetupError::UnsupportedPreset);
    }
    Ok((left_trim + open, left_trim + close, names))
}

fn parse_static_array(value: &str) -> Result<Vec<String>, SetupError> {
    let bytes = value.as_bytes();
    let mut index = 0_usize;
    let mut names = Vec::new();
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        let quote = match bytes[index] {
            b'\'' | b'"' => {
                let quote = bytes[index];
                index += 1;
                Some(quote)
            }
            _ => None,
        };
        let start = index;
        while index < bytes.len() {
            if let Some(quote) = quote {
                if bytes[index] == quote {
                    break;
                }
            } else if bytes[index].is_ascii_whitespace() {
                break;
            }
            if !is_preset_name_byte(bytes[index]) {
                return Err(SetupError::UnsupportedPreset);
            }
            index += 1;
        }
        if start == index {
            return Err(SetupError::UnsupportedPreset);
        }
        let name = std::str::from_utf8(&bytes[start..index])
            .map_err(|_| SetupError::UnsupportedPreset)?
            .to_owned();
        if let Some(quote) = quote {
            if bytes.get(index) != Some(&quote) {
                return Err(SetupError::UnsupportedPreset);
            }
            index += 1;
            if index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                return Err(SetupError::UnsupportedPreset);
            }
        }
        names.push(name);
    }
    Ok(names)
}

pub fn is_safe_flavor(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'.'))
        && value != "."
        && value != ".."
}

fn is_preset_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'.')
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
