use windows::Win32::Storage::FileSystem::FindFirstVolumeW;

pub fn enumerate_read_only() {
    let _ = FindFirstVolumeW;
}
