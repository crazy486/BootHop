#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    MalformedLoadOption,
    MalformedDevicePath,
    ResourceLimit,
    UnsupportedFormat,
    UnsupportedRecordVersion { found: u64 },
    UnsupportedIdentityComponent,
    CorruptRecord,
    IdentityMismatch,
}
