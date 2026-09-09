#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    MalformedLoadOption,
    MalformedDevicePath,
    ResourceLimit,
}
