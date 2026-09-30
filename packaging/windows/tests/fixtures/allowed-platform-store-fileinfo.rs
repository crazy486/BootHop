use windows::Win32::Storage::FileSystem::GetFileInformationByHandleEx;

pub fn existing_store_metadata_query() {
    let _ = GetFileInformationByHandleEx;
}
