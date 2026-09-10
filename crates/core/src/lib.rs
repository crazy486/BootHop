mod device_path;
mod error;
mod identity;
mod load_option;
mod model;

pub use device_path::parse_device_path;
pub use error::Error;
pub use identity::{canonicalize, classify, validate_target};
pub use load_option::parse_load_option;
pub use model::{
    BootId, CanonicalDevicePathNode, CanonicalEndEntireNode, CanonicalFilePathNode,
    CanonicalHardDriveNode, CanonicalIdentity, Classification, DevicePath, DevicePathInstance,
    DevicePathNode, DevicePathNodeKind, FilePathNode, HardDriveNode, LoadOption, OpaqueAlgorithm,
    OpaqueExactV1, Os, TargetRecord,
};
