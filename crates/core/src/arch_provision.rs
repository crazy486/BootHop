use serde::{Deserialize, Serialize};

use crate::{
    BootId, CanonicalDevicePathNode, CanonicalIdentity, Error, Os, TargetRecord, decode_record,
    encode_record,
};

const RECORD_VERSION: u64 = 2;
const IDENTITY_VERSION: u64 = 1;
const MAX_RECORD_BYTES: usize = 1_048_576;
const FIXED_IDENTITY_PATH: &str = "\\EFI\\BootHop\\arch.efi";
const FIXED_UKI_PATH: &str = "EFI/BootHop/arch.efi";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchProvisionState {
    Unprovisioned,
    Provisioning(ProvisioningRecord),
    Ready(OwnedArchEntry),
    Uninstalling(UninstallingRecord),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedArchEntry {
    pub boot_id: BootId,
    pub identity: CanonicalIdentity,
    pub identity_version: u64,
    pub uki_path: String,
    pub build: BuildMetadata,
    pub publish: PublishMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildMetadata {
    pub kernel: String,
    pub kernel_release: String,
    pub initramfs_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishMetadata {
    pub sha256: [u8; 32],
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningRecord {
    pub operation_id: String,
    pub operation_version: u64,
    /// Complete reserved ownership metadata persisted before any EFI variable write.
    pub owned_entry: OwnedArchEntry,
    pub step: ProvisioningStep,
    pub residual: Vec<Residual>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UninstallingRecord {
    pub operation_id: String,
    pub operation_version: u64,
    /// Retained until BootOrder, Boot####, and UKI cleanup have been verified complete.
    pub owned_entry: OwnedArchEntry,
    pub step: UninstallingStep,
    pub residual: Vec<Residual>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Journal checkpoints only; a step never authorizes repeating an EFI mutation.
pub enum ProvisioningStep {
    UkiPublished,
    BootEntryCreateAttempted,
    BootEntryCreated,
    BootEntryReadBackVerified,
    BootOrderAppendAttempted,
    BootOrderAppended,
    BootOrderReadBackVerified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Journal checkpoints only; a step never authorizes repeating cleanup.
pub enum UninstallingStep {
    Started,
    BootOrderRemovalAttempted,
    BootOrderRemoved,
    BootOrderRemovalReadBackVerified,
    BootEntryRemovalAttempted,
    BootEntryRemoved,
    BootEntryRemovalReadBackVerified,
    UkiRemovalAttempted,
    UkiRemoved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Uncertainty evidence only; these values never authorize retries or cleanup.
pub enum Residual {
    BootEntryMayExist,
    BootOrderMayContainEntry,
    UkiMayRemain,
    ConfigurationMayRemain,
}

#[derive(Deserialize)]
struct VersionEnvelope {
    version: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    version: u64,
    state: WireState,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum WireState {
    Provisioning {
        operation_id: String,
        operation_version: u64,
        owned_entry: WireOwnedArchEntry,
        step: ProvisioningStep,
        residual: Vec<Residual>,
    },
    Ready {
        entry: WireOwnedArchEntry,
    },
    Uninstalling {
        operation_id: String,
        operation_version: u64,
        owned_entry: WireOwnedArchEntry,
        step: UninstallingStep,
        residual: Vec<Residual>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOwnedArchEntry {
    boot_id: u16,
    identity_record: String,
    identity_version: u64,
    uki_path: String,
    build: WireBuildMetadata,
    publish: WirePublishMetadata,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBuildMetadata {
    kernel: String,
    kernel_release: String,
    initramfs_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePublishMetadata {
    sha256: String,
    size: u64,
}

/// Missing journal bytes alone mean Unprovisioned. Present bytes must decode completely.
pub fn decode_arch_provision_state(bytes: Option<&[u8]>) -> Result<ArchProvisionState, Error> {
    let Some(bytes) = bytes else {
        return Ok(ArchProvisionState::Unprovisioned);
    };
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::ResourceLimit);
    }
    let envelope: VersionEnvelope =
        serde_json::from_slice(bytes).map_err(|_| Error::CorruptRecord)?;
    if envelope.version != RECORD_VERSION {
        return Err(Error::UnsupportedRecordVersion {
            found: envelope.version,
        });
    }
    let wire: WireRecord = serde_json::from_slice(bytes).map_err(|_| Error::CorruptRecord)?;
    match wire.state {
        WireState::Provisioning {
            operation_id,
            operation_version,
            owned_entry,
            step,
            residual,
        } => {
            validate_operation(&operation_id, operation_version)?;
            Ok(ArchProvisionState::Provisioning(ProvisioningRecord {
                operation_id,
                operation_version,
                owned_entry: decode_owned_entry(owned_entry)?,
                step,
                residual,
            }))
        }
        WireState::Ready { entry } => Ok(ArchProvisionState::Ready(decode_owned_entry(entry)?)),
        WireState::Uninstalling {
            operation_id,
            operation_version,
            owned_entry,
            step,
            residual,
        } => {
            validate_operation(&operation_id, operation_version)?;
            Ok(ArchProvisionState::Uninstalling(UninstallingRecord {
                operation_id,
                operation_version,
                owned_entry: decode_owned_entry(owned_entry)?,
                step,
                residual,
            }))
        }
    }
}

pub fn encode_arch_provision_state(state: &ArchProvisionState) -> Result<Vec<u8>, Error> {
    let state = match state {
        ArchProvisionState::Unprovisioned => return Err(Error::CorruptRecord),
        ArchProvisionState::Provisioning(record) => {
            validate_operation(&record.operation_id, record.operation_version)?;
            WireState::Provisioning {
                operation_id: record.operation_id.clone(),
                operation_version: record.operation_version,
                owned_entry: encode_owned_entry(&record.owned_entry)?,
                step: record.step,
                residual: record.residual.clone(),
            }
        }
        ArchProvisionState::Ready(entry) => WireState::Ready {
            entry: encode_owned_entry(entry)?,
        },
        ArchProvisionState::Uninstalling(record) => {
            validate_operation(&record.operation_id, record.operation_version)?;
            WireState::Uninstalling {
                operation_id: record.operation_id.clone(),
                operation_version: record.operation_version,
                owned_entry: encode_owned_entry(&record.owned_entry)?,
                step: record.step,
                residual: record.residual.clone(),
            }
        }
    };
    let bytes = serde_json::to_vec(&WireRecord {
        version: RECORD_VERSION,
        state,
    })
    .map_err(|_| Error::CorruptRecord)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(bytes)
}

fn validate_operation(id: &str, version: u64) -> Result<(), Error> {
    if version != 1 {
        return Err(Error::UnsupportedRecordVersion { found: version });
    }
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(Error::CorruptRecord);
    }
    Ok(())
}

fn validate_owned_entry(entry: &OwnedArchEntry) -> Result<(), Error> {
    if entry.identity_version != IDENTITY_VERSION {
        return Err(Error::UnsupportedIdentityComponent);
    }
    if entry.uki_path != FIXED_UKI_PATH
        || entry.build.kernel.is_empty()
        || entry.build.kernel_release.is_empty()
        || entry.publish.size == 0
    {
        return Err(Error::CorruptRecord);
    }
    validate_fixed_identity(&entry.identity)
}

fn validate_fixed_identity(identity: &CanonicalIdentity) -> Result<(), Error> {
    crate::identity::validate_canonical_identity(identity).map_err(|_| Error::CorruptRecord)?;
    let CanonicalDevicePathNode::FilePath(path) = &identity.nodes[1] else {
        return Err(Error::CorruptRecord);
    };
    if String::from_utf16(&path.path_utf16).ok().as_deref() != Some(FIXED_IDENTITY_PATH) {
        return Err(Error::CorruptRecord);
    }
    Ok(())
}

fn encode_identity(identity: &CanonicalIdentity) -> Result<String, Error> {
    let record = TargetRecord {
        os: Os::Linux,
        boot_id: BootId(0),
        identity: identity.clone(),
    };
    let bytes = encode_record(&record)?;
    Ok(encode_hex_vec(&bytes))
}

fn encode_owned_entry(entry: &OwnedArchEntry) -> Result<WireOwnedArchEntry, Error> {
    validate_owned_entry(entry)?;
    Ok(WireOwnedArchEntry {
        boot_id: entry.boot_id.0,
        identity_record: encode_identity(&entry.identity)?,
        identity_version: entry.identity_version,
        uki_path: entry.uki_path.clone(),
        build: WireBuildMetadata {
            kernel: entry.build.kernel.clone(),
            kernel_release: entry.build.kernel_release.clone(),
            initramfs_sha256: encode_hex(entry.build.initramfs_sha256),
        },
        publish: WirePublishMetadata {
            sha256: encode_hex(entry.publish.sha256),
            size: entry.publish.size,
        },
    })
}

fn decode_owned_entry(wire: WireOwnedArchEntry) -> Result<OwnedArchEntry, Error> {
    let entry = OwnedArchEntry {
        boot_id: BootId(wire.boot_id),
        identity: decode_identity(&wire.identity_record)?,
        identity_version: wire.identity_version,
        uki_path: wire.uki_path,
        build: BuildMetadata {
            kernel: wire.build.kernel,
            kernel_release: wire.build.kernel_release,
            initramfs_sha256: decode_hex::<32>(&wire.build.initramfs_sha256)?,
        },
        publish: PublishMetadata {
            sha256: decode_hex::<32>(&wire.publish.sha256)?,
            size: wire.publish.size,
        },
    };
    validate_owned_entry(&entry)?;
    Ok(entry)
}

fn decode_identity(encoded: &str) -> Result<CanonicalIdentity, Error> {
    let bytes = decode_hex_vec(encoded)?;
    let record = decode_record(&bytes)?;
    validate_fixed_identity(&record.identity)?;
    Ok(record.identity)
}

fn encode_hex<const N: usize>(bytes: [u8; N]) -> String {
    encode_hex_vec(&bytes)
}
fn encode_hex_vec(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
    out
}
fn decode_hex<const N: usize>(encoded: &str) -> Result<[u8; N], Error> {
    if encoded.len() != N * 2 {
        return Err(Error::CorruptRecord);
    }
    let bytes = decode_hex_vec(encoded)?;
    bytes.try_into().map_err(|_| Error::CorruptRecord)
}
fn decode_hex_vec(encoded: &str) -> Result<Vec<u8>, Error> {
    if encoded.len() % 2 != 0 {
        return Err(Error::CorruptRecord);
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().chunks_exact(2) {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        bytes.push(high * 16 + low);
    }
    Ok(bytes)
}
fn decode_nibble(value: u8) -> Result<u8, Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(Error::CorruptRecord),
    }
}
