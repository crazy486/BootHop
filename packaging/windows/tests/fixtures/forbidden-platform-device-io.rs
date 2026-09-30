use windows::Win32::System::IO::DeviceIoControl;

pub fn issue_device_io_control() {
    let _ = DeviceIoControl;
}
