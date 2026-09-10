use serde::{Deserialize, Serialize};

use crate::{
    BootId, CanonicalDevicePathNode, CanonicalEndEntireNode, CanonicalFilePathNode,
    CanonicalHardDriveNode, CanonicalIdentity, Error, OpaqueAlgorithm, OpaqueExactV1, Os,
    TargetRecord,
};

const RECORD_VERSION: u64 = 1;
const IDENTITY_VERSION: u64 = 1;
const OPAQUE_VERSION: u64 = 1;
const MAX_RECORD_BYTES: usize = 1_048_576;

#[derive(Deserialize)]
struct VersionEnvelope {
    version: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    version: u64,
    target: WireTarget,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireTarget {
    os: WireOs,
    boot_id: u16,
    identity: WireIdentity,
}

#[derive(Deserialize, Serialize)]
enum WireOs {
    Windows,
    Linux,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireIdentity {
    kind: String,
    version: u64,
    file_path_list_length: u16,
    nodes: Vec<WireNode>,
    optional_data: WireOpaque,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum WireNode {
    HardDrive {
        #[serde(rename = "type")]
        node_type: u8,
        subtype: u8,
        length: u16,
        partition_number: u32,
        partition_start_lba: u64,
        partition_size_lba: u64,
        partition_signature_uefi_bytes: [u8; 16],
        mbr_type: u8,
        signature_type: u8,
    },
    FilePath {
        #[serde(rename = "type")]
        node_type: u8,
        subtype: u8,
        length: u16,
        path_utf16: Vec<u16>,
        terminator: u16,
    },
    EndEntire {
        #[serde(rename = "type")]
        node_type: u8,
        subtype: u8,
        length: u16,
    },
    #[serde(other)]
    Unsupported,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireOpaque {
    kind: String,
    version: u64,
    algorithm: String,
    byte_length: u64,
    digest: String,
}

pub fn decode_record(bytes: &[u8]) -> Result<TargetRecord, Error> {
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
    wire.try_into()
}

pub fn encode_record(record: &TargetRecord) -> Result<Vec<u8>, Error> {
    crate::identity::validate_canonical_identity(&record.identity)
        .map_err(|_| Error::CorruptRecord)?;
    let encoded =
        serde_json::to_vec(&WireRecord::from(record)).map_err(|_| Error::CorruptRecord)?;
    if encoded.len() > MAX_RECORD_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(encoded)
}

pub fn expected_target(host: Os) -> Os {
    match host {
        Os::Windows => Os::Linux,
        Os::Linux => Os::Windows,
    }
}

impl TryFrom<WireRecord> for TargetRecord {
    type Error = Error;

    fn try_from(wire: WireRecord) -> Result<Self, Self::Error> {
        if wire.version != RECORD_VERSION {
            return Err(Error::UnsupportedRecordVersion {
                found: wire.version,
            });
        }
        if wire.target.identity.kind != "CanonicalIdentity"
            || wire.target.identity.version != IDENTITY_VERSION
            || wire.target.identity.optional_data.kind != "OpaqueExact"
            || wire.target.identity.optional_data.version != OPAQUE_VERSION
            || wire.target.identity.optional_data.algorithm != "Sha256"
            || wire
                .target
                .identity
                .nodes
                .iter()
                .any(|node| matches!(node, WireNode::Unsupported))
        {
            return Err(Error::UnsupportedIdentityComponent);
        }

        let [hard_drive, file_path, end_entire]: [WireNode; 3] = wire
            .target
            .identity
            .nodes
            .try_into()
            .map_err(|_| Error::CorruptRecord)?;
        let WireNode::HardDrive {
            node_type: hard_drive_type,
            subtype: hard_drive_subtype,
            length: hard_drive_length,
            partition_number,
            partition_start_lba,
            partition_size_lba,
            partition_signature_uefi_bytes,
            mbr_type,
            signature_type,
        } = hard_drive
        else {
            return Err(Error::CorruptRecord);
        };
        let WireNode::FilePath {
            node_type: file_path_type,
            subtype: file_path_subtype,
            length: file_path_length,
            path_utf16,
            terminator,
        } = file_path
        else {
            return Err(Error::CorruptRecord);
        };
        let WireNode::EndEntire {
            node_type: end_type,
            subtype: end_subtype,
            length: end_length,
        } = end_entire
        else {
            return Err(Error::CorruptRecord);
        };

        let identity = CanonicalIdentity {
            file_path_list_length: wire.target.identity.file_path_list_length,
            nodes: [
                CanonicalDevicePathNode::HardDrive(CanonicalHardDriveNode {
                    node_type: hard_drive_type,
                    subtype: hard_drive_subtype,
                    length: hard_drive_length,
                    partition_number,
                    partition_start_lba,
                    partition_size_lba,
                    partition_signature_uefi_bytes,
                    mbr_type,
                    signature_type,
                }),
                CanonicalDevicePathNode::FilePath(CanonicalFilePathNode {
                    node_type: file_path_type,
                    subtype: file_path_subtype,
                    length: file_path_length,
                    path_utf16,
                    terminator,
                }),
                CanonicalDevicePathNode::EndEntire(CanonicalEndEntireNode {
                    node_type: end_type,
                    subtype: end_subtype,
                    length: end_length,
                }),
            ],
            optional_data: OpaqueExactV1 {
                algorithm: OpaqueAlgorithm::Sha256,
                byte_length: wire.target.identity.optional_data.byte_length,
                digest: decode_digest(&wire.target.identity.optional_data.digest)?,
            },
        };
        crate::identity::validate_canonical_identity(&identity)
            .map_err(|_| Error::CorruptRecord)?;

        Ok(TargetRecord {
            os: wire.target.os.into(),
            boot_id: BootId(wire.target.boot_id),
            identity,
        })
    }
}

impl From<&TargetRecord> for WireRecord {
    fn from(record: &TargetRecord) -> Self {
        let [hard_drive, file_path, end_entire] = &record.identity.nodes;
        let CanonicalDevicePathNode::HardDrive(hard_drive) = hard_drive else {
            unreachable!("identity was validated before serialization")
        };
        let CanonicalDevicePathNode::FilePath(file_path) = file_path else {
            unreachable!("identity was validated before serialization")
        };
        let CanonicalDevicePathNode::EndEntire(end_entire) = end_entire else {
            unreachable!("identity was validated before serialization")
        };

        Self {
            version: RECORD_VERSION,
            target: WireTarget {
                os: record.os.into(),
                boot_id: record.boot_id.0,
                identity: WireIdentity {
                    kind: "CanonicalIdentity".to_owned(),
                    version: IDENTITY_VERSION,
                    file_path_list_length: record.identity.file_path_list_length,
                    nodes: vec![
                        WireNode::HardDrive {
                            node_type: hard_drive.node_type,
                            subtype: hard_drive.subtype,
                            length: hard_drive.length,
                            partition_number: hard_drive.partition_number,
                            partition_start_lba: hard_drive.partition_start_lba,
                            partition_size_lba: hard_drive.partition_size_lba,
                            partition_signature_uefi_bytes: hard_drive
                                .partition_signature_uefi_bytes,
                            mbr_type: hard_drive.mbr_type,
                            signature_type: hard_drive.signature_type,
                        },
                        WireNode::FilePath {
                            node_type: file_path.node_type,
                            subtype: file_path.subtype,
                            length: file_path.length,
                            path_utf16: file_path.path_utf16.clone(),
                            terminator: file_path.terminator,
                        },
                        WireNode::EndEntire {
                            node_type: end_entire.node_type,
                            subtype: end_entire.subtype,
                            length: end_entire.length,
                        },
                    ],
                    optional_data: WireOpaque {
                        kind: "OpaqueExact".to_owned(),
                        version: OPAQUE_VERSION,
                        algorithm: "Sha256".to_owned(),
                        byte_length: record.identity.optional_data.byte_length,
                        digest: encode_digest(record.identity.optional_data.digest),
                    },
                },
            },
        }
    }
}

impl From<Os> for WireOs {
    fn from(os: Os) -> Self {
        match os {
            Os::Windows => Self::Windows,
            Os::Linux => Self::Linux,
        }
    }
}

impl From<WireOs> for Os {
    fn from(os: WireOs) -> Self {
        match os {
            WireOs::Windows => Self::Windows,
            WireOs::Linux => Self::Linux,
        }
    }
}

fn encode_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_digest(encoded: &str) -> Result<[u8; 32], Error> {
    if encoded.len() != 64 {
        return Err(Error::CorruptRecord);
    }

    let mut digest = [0_u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        let high = decode_nibble(encoded.as_bytes()[index * 2])?;
        let low = decode_nibble(encoded.as_bytes()[index * 2 + 1])?;
        *output = high * 16 + low;
    }
    Ok(digest)
}

fn decode_nibble(value: u8) -> Result<u8, Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(Error::CorruptRecord),
    }
}
