use windows::Win32::Storage::FileSystem::FindFirstVolumeW;

pub fn enumerate_outside_boundary() {
    let _ = FindFirstVolumeW;
}
