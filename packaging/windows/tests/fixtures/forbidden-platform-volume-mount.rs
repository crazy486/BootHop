use windows::Win32::Storage::FileSystem::SetVolumeMountPointW;

pub fn unsafe_mount() {
    let _ = SetVolumeMountPointW;
}
