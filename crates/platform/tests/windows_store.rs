use boothop_core::{RecordState, TargetRecord, canonicalize, encode_record, parse_load_option};
use boothop_platform::ProtectedStore;
use boothop_platform::windows::store::{
    Dacl, ObjectKind, ObjectMetadata, OperationCapability, Owner, SecurityDescriptor,
    WindowsProtectedStore, WindowsStoreCalls,
};

#[derive(Clone, Debug)]
struct Fake {
    events: Vec<&'static str>,
    root: ObjectMetadata,
    dir: ObjectMetadata,
}

#[derive(Clone)]
struct SaveHandle {
    name: String,
    meta: ObjectMetadata,
    bytes: Vec<u8>,
    cursor: usize,
}

struct SaveFake {
    events: Vec<String>,
    root: SaveHandle,
    directory: SaveHandle,
    record: Option<Vec<u8>>,
    record_size_override: Option<u64>,
    durability_error: Option<i32>,
}

impl SaveFake {
    fn installed(record: Option<Vec<u8>>) -> Self {
        Self {
            events: Vec::new(),
            root: SaveHandle {
                name: "ProgramData".into(),
                meta: ObjectMetadata::program_data(1),
                bytes: Vec::new(),
                cursor: 0,
            },
            directory: SaveHandle {
                name: "BootHop".into(),
                meta: ObjectMetadata::protected_directory(2, 1),
                bytes: Vec::new(),
                cursor: 0,
            },
            record,
            record_size_override: None,
            durability_error: None,
        }
    }
}

impl WindowsStoreCalls for SaveFake {
    type Handle = SaveHandle;

    fn known_folder_program_data(&mut self) -> Result<Self::Handle, i32> {
        Ok(self.root.clone())
    }
    fn open_directory(&mut self, _: &Self::Handle, name: &str) -> Result<Self::Handle, i32> {
        assert_eq!(name, "BootHop");
        Ok(self.directory.clone())
    }
    fn open_file(&mut self, _: &Self::Handle, name: &str) -> Result<Self::Handle, i32> {
        if name != "targets.json" {
            return Err(2);
        }
        self.record.clone().map_or(Err(2), |bytes| {
            Ok(SaveHandle {
                name: name.into(),
                meta: ObjectMetadata {
                    kind: ObjectKind::File,
                    reparse_point: false,
                    trusted_known_folder: false,
                    file_id: 3,
                    parent_id: Some(2),
                    size: self.record_size_override.unwrap_or(bytes.len() as u64),
                    security: SecurityDescriptor::PROTECTED,
                },
                bytes,
                cursor: 0,
            })
        })
    }
    fn metadata(&mut self, handle: &Self::Handle) -> Result<ObjectMetadata, i32> {
        Ok(handle.meta.clone())
    }
    fn security(&mut self, handle: &Self::Handle) -> Result<SecurityDescriptor, i32> {
        Ok(handle.meta.security)
    }
    fn read(&mut self, handle: &mut Self::Handle, bytes: &mut [u8]) -> Result<usize, i32> {
        let count = bytes
            .len()
            .min(handle.bytes.len().saturating_sub(handle.cursor));
        bytes[..count].copy_from_slice(&handle.bytes[handle.cursor..handle.cursor + count]);
        handle.cursor += count;
        Ok(count)
    }
    fn create_exclusive_file(
        &mut self,
        _: &Self::Handle,
        name: &str,
        security: &SecurityDescriptor,
    ) -> Result<Self::Handle, i32> {
        self.events.push(format!("create:{name}"));
        Ok(SaveHandle {
            name: name.into(),
            meta: ObjectMetadata {
                kind: ObjectKind::File,
                reparse_point: false,
                trusted_known_folder: false,
                file_id: if name == "targets.json" { 3 } else { 4 },
                parent_id: Some(2),
                size: 0,
                security: *security,
            },
            bytes: Vec::new(),
            cursor: 0,
        })
    }
    fn write(&mut self, handle: &mut Self::Handle, bytes: &[u8]) -> Result<usize, i32> {
        self.events.push("write".into());
        handle.bytes.extend_from_slice(bytes);
        handle.meta.size = handle.bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self, handle: &Self::Handle) -> Result<(), i32> {
        self.events.push(format!("flush:{}", handle.name));
        if handle.name == "BootHop" {
            self.durability_error.map_or(Ok(()), Err)
        } else {
            Ok(())
        }
    }
    fn close(&mut self, handle: Self::Handle) -> Result<(), i32> {
        self.events.push(format!("close:{}", handle.name));
        if handle.name == "targets.json" && self.record.is_none() {
            self.record = Some(handle.bytes);
        }
        Ok(())
    }
    fn replace_file(
        &mut self,
        _: &Self::Handle,
        temporary_name: &str,
        record_name: &str,
        flags: u32,
    ) -> Result<(), i32> {
        self.events
            .push(format!("replace:{temporary_name}:{record_name}:{flags}"));
        Ok(())
    }
    fn remove_file(&mut self, _: &Self::Handle, name: &str) -> Result<(), i32> {
        self.events.push(format!("remove:{name}"));
        Ok(())
    }
}

fn target() -> TargetRecord {
    let hex = include_str!("../../../fixtures/uefi/synthetic/task1-shape.hex").trim();
    let bytes: Vec<_> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    TargetRecord {
        boot_id: boothop_core::BootId(7),
        os: boothop_core::Os::Windows,
        identity: canonicalize(&parse_load_option(&bytes).unwrap()).unwrap(),
    }
}

impl Fake {
    fn trusted() -> Self {
        Self {
            events: Vec::new(),
            root: ObjectMetadata::program_data(1),
            dir: ObjectMetadata::protected_directory(2, 1),
        }
    }
}

impl WindowsStoreCalls for Fake {
    type Handle = ObjectMetadata;

    fn known_folder_program_data(&mut self) -> Result<Self::Handle, i32> {
        self.events.push("known_folder");
        Ok(self.root.clone())
    }
    fn open_directory(&mut self, parent: &Self::Handle, name: &str) -> Result<Self::Handle, i32> {
        self.events.push("open_directory");
        assert_eq!(name, "BootHop");
        assert_eq!(parent.file_id, 1);
        Ok(self.dir.clone())
    }
    fn open_file(&mut self, _: &Self::Handle, _: &str) -> Result<Self::Handle, i32> {
        Err(2)
    }
    fn metadata(&mut self, handle: &Self::Handle) -> Result<ObjectMetadata, i32> {
        Ok(handle.clone())
    }
    fn security(&mut self, handle: &Self::Handle) -> Result<SecurityDescriptor, i32> {
        Ok(handle.security)
    }
    fn read(&mut self, _: &mut Self::Handle, _: &mut [u8]) -> Result<usize, i32> {
        Err(5)
    }
    fn create_exclusive_file(
        &mut self,
        _: &Self::Handle,
        _: &str,
        _: &SecurityDescriptor,
    ) -> Result<Self::Handle, i32> {
        Err(5)
    }
    fn write(&mut self, _: &mut Self::Handle, _: &[u8]) -> Result<usize, i32> {
        Err(5)
    }
    fn flush(&mut self, _: &Self::Handle) -> Result<(), i32> {
        Ok(())
    }
    fn close(&mut self, _: Self::Handle) -> Result<(), i32> {
        Ok(())
    }
    fn replace_file(&mut self, _: &Self::Handle, _: &str, _: &str, _: u32) -> Result<(), i32> {
        Err(5)
    }
    fn remove_file(&mut self, _: &Self::Handle, _: &str) -> Result<(), i32> {
        Ok(())
    }
}

#[test]
fn trusted_parent_and_directory_make_absent_record_a_valid_missing_state() {
    let fake = Fake::trusted();
    let mut store = WindowsProtectedStore::open(fake, OperationCapability::for_testing()).unwrap();
    assert_eq!(store.load(), Ok(RecordState::Missing));
}

#[test]
fn unsafe_known_folder_and_components_are_rejected_before_record_access() {
    let mut cases = Vec::new();
    let mut root = ObjectMetadata::program_data(1);
    root.trusted_known_folder = false;
    cases.push((root, ObjectMetadata::protected_directory(2, 1)));
    let mut root = ObjectMetadata::program_data(1);
    root.reparse_point = true;
    cases.push((root, ObjectMetadata::protected_directory(2, 1)));
    let mut directory = ObjectMetadata::protected_directory(2, 1);
    directory.kind = ObjectKind::File;
    cases.push((ObjectMetadata::program_data(1), directory));
    let mut directory = ObjectMetadata::protected_directory(2, 1);
    directory.reparse_point = true;
    cases.push((ObjectMetadata::program_data(1), directory));
    let mut directory = ObjectMetadata::protected_directory(2, 1);
    directory.security.owner = Owner::Other;
    cases.push((ObjectMetadata::program_data(1), directory));
    let mut directory = ObjectMetadata::protected_directory(2, 1);
    directory.security.dacl = Dacl {
        ordinary_user_mutation: true,
        ..Dacl::PROTECTED
    };
    cases.push((ObjectMetadata::program_data(1), directory));
    for (root, dir) in cases {
        let fake = Fake {
            events: Vec::new(),
            root,
            dir,
        };
        assert!(WindowsProtectedStore::open(fake, OperationCapability::for_testing()).is_err());
    }
}

#[test]
fn inherited_mutation_capability_is_rejected_even_with_expected_owner() {
    let mut directory = ObjectMetadata::protected_directory(2, 1);
    directory.security.dacl.inherited_ordinary_user_mutation = true;
    let fake = Fake {
        events: Vec::new(),
        root: ObjectMetadata::program_data(1),
        dir: directory,
    };
    assert!(WindowsProtectedStore::open(fake, OperationCapability::for_testing()).is_err());
}

#[test]
fn replacement_flushes_and_closes_temp_then_uses_zero_flags_without_retry() {
    let bytes = encode_record(&target()).unwrap();
    let mut fake = SaveFake::installed(Some(bytes));
    let mut store = WindowsProtectedStore::open(fake, OperationCapability::for_testing()).unwrap();
    store.save(&target()).unwrap();
    fake = store.into_calls();
    let replace = fake
        .events
        .iter()
        .position(|event| event.starts_with("replace:"))
        .unwrap();
    let close = fake
        .events
        .iter()
        .position(|event| event == "close:.targets-1-0.tmp" || event.starts_with("close:.targets-"))
        .unwrap();
    assert!(close < replace);
    assert!(fake.events[replace].ends_with(":0"));
    assert_eq!(
        fake.events
            .iter()
            .filter(|event| event.starts_with("replace:"))
            .count(),
        1
    );
}

#[test]
fn directory_flush_failure_reports_durability_unknown_after_logical_success() {
    let bytes = encode_record(&target()).unwrap();
    let mut fake = SaveFake::installed(Some(bytes));
    fake.durability_error = Some(5);
    let mut store = WindowsProtectedStore::open(fake, OperationCapability::for_testing()).unwrap();
    assert_eq!(
        store.save(&target()),
        Err(boothop_core::Error::StoreDurabilityUnknown { raw_code: 5 })
    );
}

#[test]
fn corrupt_and_unsupported_records_are_not_treated_as_missing() {
    for (bytes, expected) in [
        (b"not-json".to_vec(), boothop_core::Error::CorruptRecord),
        (
            br#"{"version":999}"#.to_vec(),
            boothop_core::Error::UnsupportedRecordVersion { found: 999 },
        ),
    ] {
        let mut store = WindowsProtectedStore::open(
            SaveFake::installed(Some(bytes)),
            OperationCapability::for_testing(),
        )
        .unwrap();
        assert_eq!(store.load(), Err(expected));
    }
}

#[test]
fn oversized_metadata_is_rejected_before_unbounded_read() {
    let mut fake = SaveFake::installed(Some(Vec::new()));
    fake.record_size_override = Some(1_048_577);
    let mut store = WindowsProtectedStore::open(fake, OperationCapability::for_testing()).unwrap();
    assert_eq!(store.load(), Err(boothop_core::Error::ResourceLimit));
}

#[test]
fn first_creation_is_exclusive_and_revalidated_without_replace() {
    let mut store = WindowsProtectedStore::open(
        SaveFake::installed(None),
        OperationCapability::for_testing(),
    )
    .unwrap();
    store.save(&target()).unwrap();
    let fake = store.into_calls();
    assert!(
        fake.events
            .iter()
            .any(|event| event == "create:targets.json")
    );
    assert!(
        !fake
            .events
            .iter()
            .any(|event| event.starts_with("replace:"))
    );
}
