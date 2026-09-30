use windows::Win32::Storage::FileSystem::DeleteFileW;

pub fn unsafe_delete() {
    let _ = DeleteFileW;
}
