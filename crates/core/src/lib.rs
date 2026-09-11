mod device_path;
mod error;
mod flow;
mod identity;
mod load_option;
mod model;
mod record;

pub use device_path::parse_device_path;
pub use error::{Error, ResidualAssessment};
pub use flow::{Platform, execute};
pub use identity::{canonicalize, classify, validate_target};
pub use load_option::parse_load_option;
pub use model::{
    BootId, Candidate, CanonicalDevicePathNode, CanonicalEndEntireNode, CanonicalFilePathNode,
    CanonicalHardDriveNode, CanonicalIdentity, Classification, DevicePath, DevicePathInstance,
    DevicePathNode, DevicePathNodeKind, EnumerationDiagnostic, FilePathNode, HardDriveNode,
    LoadOption, OpaqueAlgorithm, OpaqueExactV1, OptionInventory, Os, RebootOutcome,
    RecordDiagnostic, RecordState, Report, Request, Stage, TargetRecord,
};
pub use record::{decode_record, encode_record, expected_target};
