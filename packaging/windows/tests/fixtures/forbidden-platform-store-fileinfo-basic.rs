use windows::Win32::Storage::FileSystem::GetFileInformationByHandle;

pub fn unallowlisted_basic_metadata_query() {
    let _ = GetFileInformationByHandle;
}
