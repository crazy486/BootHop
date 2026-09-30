use windows::Win32::Storage::FileSystem::{
    FindFirstVolumeMountPointW, FindFirstVolumeW, FindNextVolumeMountPointW,
    GetVolumeInformationByHandleW,
};

pub fn enumerate_read_only() {
    let _ = FindFirstVolumeW;
    let _ = FindFirstVolumeMountPointW;
    let _ = FindNextVolumeMountPointW;
    let _ = GetVolumeInformationByHandleW;
}
