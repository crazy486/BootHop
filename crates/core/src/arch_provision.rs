use serde::{Deserialize, Serialize};

use crate::{
    BootId, CanonicalDevicePathNode, CanonicalIdentity, Error, Os, TargetRecord, decode_record,
    encode_record,
};

const RECORD_VERSION: u64 = 5;
const IDENTITY_VERSION: u64 = 1;
const MAX_RECORD_BYTES: usize = 1_048_576;
const FIXED_IDENTITY_PATH: &str = "\\EFI\\BootHop\\arch.efi";
const FIXED_UKI_PATH: &str = "EFI/BootHop/arch.efi";
const BOOT_ORDER_ATTRIBUTES: u32 = 7;
const MAX_BOOT_ORDER_ITEMS: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchProvisionState {
    Unprovisioned,
    Provisioning(ProvisioningRecord),
    Ready(OwnedArchEntry),
    Uninstalling(UninstallingRecord),
    /// Terminal ownership tombstone. The owned metadata remains until a later explicit
    /// provisioning operation replaces this record.
    Uninstalled(UninstalledRecord),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedArchEntry {
    pub boot_id: BootId,
    pub identity: CanonicalIdentity,
    pub identity_version: u64,
    pub uki_path: String,
    pub build: BuildMetadata,
    /// Absent only while the journal is at `UkiPublicationPending` and no output exists yet.
    pub publish: Option<PublishMetadata>,
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
    /// Durable full-order evidence for the owned BootOrder removal. This is absent only before
    /// the removal attempt is proof-bound; once present it is retained through all later steps.
    pub boot_order_proof: Option<BootOrderRemovalProof>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootOrderSnapshot {
    pub attributes: u32,
    pub ids: Vec<BootId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootOrderRemovalProof {
    pub operation_id: String,
    pub operation_version: u64,
    pub boot_id: BootId,
    pub before: BootOrderSnapshot,
    pub expected_after: BootOrderSnapshot,
    /// Set only after an exact post-mutation readback. Recovery may advance a checkpoint only
    /// when this exact expected snapshot is observed again.
    pub observed_after: Option<BootOrderSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UninstalledRecord {
    pub operation_id: String,
    pub operation_version: u64,
    pub owned_entry: OwnedArchEntry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Journal checkpoints only; a step never authorizes repeating an EFI mutation.
pub enum ProvisioningStep {
    UkiPublicationPending,
    UkiPublicationAttempted,
    UkiPublished,
    BootEntryCreateAttempted,
    BootEntryCreated,
    BootEntryReadBackVerified,
    BootOrderAppendAttempted,
    BootOrderAppendWriteCompleted,
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
    BootEntryDeleteCompleted,
    BootEntryRemoved,
    BootEntryRemovalReadBackVerified,
    UkiRemovalAttempted,
    UkiDeleteCompleted,
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
        boot_order_proof: Option<WireBootOrderRemovalProof>,
    },
    Uninstalled {
        operation_id: String,
        operation_version: u64,
        owned_entry: WireOwnedArchEntry,
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
    publish: Option<WirePublishMetadata>,
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBootOrderRemovalProof {
    operation_id: String,
    operation_version: u64,
    boot_id: u16,
    before: WireBootOrderSnapshot,
    expected_after: WireBootOrderSnapshot,
    observed_after: Option<WireBootOrderSnapshot>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBootOrderSnapshot {
    attributes: u32,
    ids: Vec<u16>,
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
            let owned_entry = decode_owned_entry(owned_entry)?;
            validate_provisioning_publish_checkpoint(&owned_entry, step)?;
            Ok(ArchProvisionState::Provisioning(ProvisioningRecord {
                operation_id,
                operation_version,
                owned_entry,
                step,
                residual,
            }))
        }
        WireState::Ready { entry } => {
            let entry = decode_owned_entry(entry)?;
            require_publish_metadata(&entry)?;
            Ok(ArchProvisionState::Ready(entry))
        }
        WireState::Uninstalling {
            operation_id,
            operation_version,
            owned_entry,
            step,
            residual,
            boot_order_proof,
        } => {
            validate_operation(&operation_id, operation_version)?;
            let owned_entry = decode_owned_entry(owned_entry)?;
            require_publish_metadata(&owned_entry)?;
            let boot_order_proof = decode_boot_order_proof(boot_order_proof)?;
            validate_uninstall_boot_order_proof(
                &operation_id,
                operation_version,
                &owned_entry,
                step,
                boot_order_proof.as_ref(),
            )?;
            Ok(ArchProvisionState::Uninstalling(UninstallingRecord {
                operation_id,
                operation_version,
                owned_entry,
                step,
                residual,
                boot_order_proof,
            }))
        }
        WireState::Uninstalled {
            operation_id,
            operation_version,
            owned_entry,
        } => {
            validate_operation(&operation_id, operation_version)?;
            let owned_entry = decode_owned_entry(owned_entry)?;
            require_publish_metadata(&owned_entry)?;
            Ok(ArchProvisionState::Uninstalled(UninstalledRecord {
                operation_id,
                operation_version,
                owned_entry,
            }))
        }
    }
}

pub fn encode_arch_provision_state(state: &ArchProvisionState) -> Result<Vec<u8>, Error> {
    let state = match state {
        ArchProvisionState::Unprovisioned => return Err(Error::CorruptRecord),
        ArchProvisionState::Provisioning(record) => {
            validate_operation(&record.operation_id, record.operation_version)?;
            validate_provisioning_publish_checkpoint(&record.owned_entry, record.step)?;
            WireState::Provisioning {
                operation_id: record.operation_id.clone(),
                operation_version: record.operation_version,
                owned_entry: encode_owned_entry(&record.owned_entry)?,
                step: record.step,
                residual: record.residual.clone(),
            }
        }
        ArchProvisionState::Ready(entry) => {
            require_publish_metadata(entry)?;
            WireState::Ready {
                entry: encode_owned_entry(entry)?,
            }
        }
        ArchProvisionState::Uninstalling(record) => {
            validate_operation(&record.operation_id, record.operation_version)?;
            require_publish_metadata(&record.owned_entry)?;
            validate_uninstall_boot_order_proof(
                &record.operation_id,
                record.operation_version,
                &record.owned_entry,
                record.step,
                record.boot_order_proof.as_ref(),
            )?;
            WireState::Uninstalling {
                operation_id: record.operation_id.clone(),
                operation_version: record.operation_version,
                owned_entry: encode_owned_entry(&record.owned_entry)?,
                step: record.step,
                residual: record.residual.clone(),
                boot_order_proof: record
                    .boot_order_proof
                    .as_ref()
                    .map(encode_boot_order_proof)
                    .transpose()?,
            }
        }
        ArchProvisionState::Uninstalled(record) => {
            validate_operation(&record.operation_id, record.operation_version)?;
            require_publish_metadata(&record.owned_entry)?;
            WireState::Uninstalled {
                operation_id: record.operation_id.clone(),
                operation_version: record.operation_version,
                owned_entry: encode_owned_entry(&record.owned_entry)?,
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

fn decode_boot_order_proof(
    wire: Option<WireBootOrderRemovalProof>,
) -> Result<Option<BootOrderRemovalProof>, Error> {
    wire.map(|proof| {
        let proof = BootOrderRemovalProof {
            operation_id: proof.operation_id,
            operation_version: proof.operation_version,
            boot_id: BootId(proof.boot_id),
            before: decode_boot_order_snapshot(proof.before)?,
            expected_after: decode_boot_order_snapshot(proof.expected_after)?,
            observed_after: proof
                .observed_after
                .map(decode_boot_order_snapshot)
                .transpose()?,
        };
        proof.validate().map(|()| proof)
    })
    .transpose()
}

fn decode_boot_order_snapshot(wire: WireBootOrderSnapshot) -> Result<BootOrderSnapshot, Error> {
    let snapshot = BootOrderSnapshot {
        attributes: wire.attributes,
        ids: wire.ids.into_iter().map(BootId).collect(),
    };
    snapshot.validate()?;
    Ok(snapshot)
}

fn encode_boot_order_proof(
    proof: &BootOrderRemovalProof,
) -> Result<WireBootOrderRemovalProof, Error> {
    proof.validate()?;
    Ok(WireBootOrderRemovalProof {
        operation_id: proof.operation_id.clone(),
        operation_version: proof.operation_version,
        boot_id: proof.boot_id.0,
        before: encode_boot_order_snapshot(&proof.before),
        expected_after: encode_boot_order_snapshot(&proof.expected_after),
        observed_after: proof
            .observed_after
            .as_ref()
            .map(encode_boot_order_snapshot),
    })
}

fn encode_boot_order_snapshot(snapshot: &BootOrderSnapshot) -> WireBootOrderSnapshot {
    WireBootOrderSnapshot {
        attributes: snapshot.attributes,
        ids: snapshot.ids.iter().map(|id| id.0).collect(),
    }
}

fn validate_uninstall_boot_order_proof(
    operation_id: &str,
    operation_version: u64,
    entry: &OwnedArchEntry,
    step: UninstallingStep,
    proof: Option<&BootOrderRemovalProof>,
) -> Result<(), Error> {
    match step {
        UninstallingStep::Started => {
            if proof.is_some() {
                return Err(Error::CorruptRecord);
            }
        }
        UninstallingStep::BootOrderRemovalAttempted => {
            let Some(proof) = proof else {
                return Err(Error::CorruptRecord);
            };
            proof.validate_binding(operation_id, operation_version, entry)?;
            if proof.observed_after.is_some() {
                return Err(Error::CorruptRecord);
            }
        }
        _ => {
            let Some(proof) = proof else {
                return Err(Error::CorruptRecord);
            };
            proof.validate_binding(operation_id, operation_version, entry)?;
            if proof.observed_after.as_ref() != Some(&proof.expected_after) {
                return Err(Error::CorruptRecord);
            }
        }
    }
    Ok(())
}

impl BootOrderSnapshot {
    pub fn validate(&self) -> Result<(), Error> {
        if self.attributes != BOOT_ORDER_ATTRIBUTES || self.ids.len() > MAX_BOOT_ORDER_ITEMS {
            return Err(Error::UnsupportedFormat);
        }
        let mut seen = vec![false; 65_536];
        for id in &self.ids {
            let slot = &mut seen[id.0 as usize];
            if *slot {
                return Err(Error::UnsupportedFormat);
            }
            *slot = true;
        }
        Ok(())
    }
}

impl BootOrderRemovalProof {
    pub fn validate(&self) -> Result<(), Error> {
        validate_operation(&self.operation_id, self.operation_version)?;
        self.before.validate()?;
        self.expected_after.validate()?;
        if self.before.attributes != self.expected_after.attributes
            || !self.before.ids.contains(&self.boot_id)
            || self.expected_after.ids.contains(&self.boot_id)
        {
            return Err(Error::CorruptRecord);
        }
        let expected = BootOrderSnapshot {
            attributes: self.before.attributes,
            ids: self
                .before
                .ids
                .iter()
                .copied()
                .filter(|id| *id != self.boot_id)
                .collect(),
        };
        if self.expected_after != expected {
            return Err(Error::CorruptRecord);
        }
        if let Some(observed_after) = &self.observed_after
            && observed_after != &self.expected_after
        {
            return Err(Error::CorruptRecord);
        }
        Ok(())
    }

    fn validate_binding(
        &self,
        operation_id: &str,
        operation_version: u64,
        entry: &OwnedArchEntry,
    ) -> Result<(), Error> {
        self.validate()?;
        if self.operation_id != operation_id
            || self.operation_version != operation_version
            || self.boot_id != entry.boot_id
        {
            return Err(Error::IdentityMismatch);
        }
        Ok(())
    }
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
        || entry
            .publish
            .as_ref()
            .is_some_and(|metadata| metadata.size == 0)
    {
        return Err(Error::CorruptRecord);
    }
    validate_fixed_identity(&entry.identity)
}

fn require_publish_metadata(entry: &OwnedArchEntry) -> Result<(), Error> {
    if entry.publish.is_none() {
        return Err(Error::CorruptRecord);
    }
    validate_owned_entry(entry)
}

fn validate_provisioning_publish_checkpoint(
    entry: &OwnedArchEntry,
    step: ProvisioningStep,
) -> Result<(), Error> {
    validate_owned_entry(entry)?;
    match (step, entry.publish.as_ref()) {
        (ProvisioningStep::UkiPublicationPending, None) => Ok(()),
        (ProvisioningStep::UkiPublicationPending, Some(_)) => Err(Error::CorruptRecord),
        (_, Some(metadata)) if metadata.size > 0 => Ok(()),
        _ => Err(Error::CorruptRecord),
    }
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
        publish: entry.publish.as_ref().map(|metadata| WirePublishMetadata {
            sha256: encode_hex(metadata.sha256),
            size: metadata.size,
        }),
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
        publish: wire
            .publish
            .map(|metadata| {
                Ok(PublishMetadata {
                    sha256: decode_hex::<32>(&metadata.sha256)?,
                    size: metadata.size,
                })
            })
            .transpose()?,
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
    if !encoded.len().is_multiple_of(2) {
        return Err(Error::CorruptRecord);
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().as_chunks::<2>().0 {
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
