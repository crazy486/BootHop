use boothop_core::{
    ArchProvisionState, BootId, BuildMetadata, OwnedArchEntry, ProvisioningRecord,
    ProvisioningStep, PublishMetadata, Residual, arch_uki_load_option, canonicalize,
};
use boothop_platform::linux::{
    LinuxCalls,
    boot_entry::{
        BootEntrySpec, CreateMutationState, allocate_boot_id, create_and_verify_entry,
        inspect_boot_namespace,
    },
    esp_identity::EspPartitionIdentity,
    firmware::{Metadata, OpenKind},
    reboot::{Probe, Reply},
};
use std::{cell::RefCell, collections::BTreeMap};

const EFIVARFS: u64 = 0xde5e81e4;
const GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

#[derive(Clone)]
struct Handle {
    path: String,
    offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Inject {
    None,
    CreateAfterMutationError,
    CreateCollision,
    WriteErrorAfterMutation,
    ShortWrite,
    CorruptReadback,
    DifferentReadback,
    AbsentReadback,
    WrongType,
    WrongFs,
    ReadOnly,
}

struct FakeCalls {
    vars: RefCell<BTreeMap<String, Vec<u8>>>,
    extra_names: Vec<Vec<u8>>,
    names_error: bool,
    names_calls: usize,
    set_next_on_names: Option<usize>,
    injection: Inject,
    events: RefCell<Vec<String>>,
}

impl FakeCalls {
    fn new() -> Self {
        let mut vars = BTreeMap::new();
        vars.insert(
            format!("BootOrder-{GUID}"),
            [7, 0, 0, 0, 1, 0, 2, 0].to_vec(),
        );
        vars.insert(format!("BootCurrent-{GUID}"), [6, 0, 0, 0, 3, 0].to_vec());
        vars.insert(format!("Boot0000-{GUID}"), [7, 0, 0, 0, 9].to_vec());
        vars.insert(format!("Boot0005-{GUID}"), [7, 0, 0, 0, 9].to_vec());
        Self {
            vars: RefCell::new(vars),
            extra_names: Vec::new(),
            names_error: false,
            names_calls: 0,
            set_next_on_names: None,
            injection: Inject::None,
            events: RefCell::new(Vec::new()),
        }
    }
    fn put(&self, name: &str, bytes: Vec<u8>) {
        self.vars
            .borrow_mut()
            .insert(format!("{name}-{GUID}"), bytes);
    }
    fn contains(&self, id: u16) -> bool {
        self.vars
            .borrow()
            .contains_key(&format!("Boot{id:04X}-{GUID}"))
    }
    fn raw(&self, id: u16) -> Option<Vec<u8>> {
        self.vars
            .borrow()
            .get(&format!("Boot{id:04X}-{GUID}"))
            .cloned()
    }
    fn meta(path: &str, size: u64) -> Metadata {
        Metadata {
            mode: if path == "/"
                || path.ends_with("/sys")
                || path.ends_with("/firmware")
                || path.ends_with("/efi")
                || path.ends_with("/efivars")
            {
                0o40755
            } else {
                0o100600
            },
            filesystem: if path.ends_with("/efivars") || path.contains(GUID) {
                EFIVARFS
            } else {
                0x1234
            },
            readonly: false,
            size,
            device: 1,
            inode: 10 + size,
            mtime: (1, 1),
            ctime: (2, 2),
        }
    }
}

impl LinuxCalls for FakeCalls {
    type Handle = Handle;
    fn root(&mut self) -> Result<Self::Handle, i32> {
        Ok(Handle {
            path: "/".into(),
            offset: 0,
        })
    }
    fn open(
        &mut self,
        dir: &Self::Handle,
        name: &str,
        kind: OpenKind,
    ) -> Result<Self::Handle, i32> {
        self.events
            .borrow_mut()
            .push(format!("open:{name}:{kind:?}"));
        let path = if dir.path == "/" {
            format!("/{name}")
        } else {
            format!("{}/{name}", dir.path.trim_end_matches('/'))
        };
        if kind == OpenKind::Directory {
            return Ok(Handle { path, offset: 0 });
        }
        let mut vars = self.vars.borrow_mut();
        match kind {
            OpenKind::ReadVariable => vars
                .contains_key(name)
                .then_some(Handle {
                    path: name.into(),
                    offset: 0,
                })
                .ok_or(2),
            OpenKind::CreateEntry => {
                if self.injection == Inject::CreateCollision {
                    vars.insert(name.into(), b"other-owner-existing-entry".to_vec());
                    return Err(17);
                }
                if vars.contains_key(name) {
                    return Err(17);
                }
                vars.insert(name.into(), Vec::new());
                if self.injection == Inject::CreateAfterMutationError {
                    return Err(5);
                }
                Ok(Handle {
                    path: name.into(),
                    offset: 0,
                })
            }
            _ => Err(13),
        }
    }
    fn metadata(&mut self, fd: &Self::Handle) -> Result<Metadata, i32> {
        let size = self
            .vars
            .borrow()
            .get(&fd.path)
            .map_or(0, |bytes| bytes.len() as u64);
        let mut meta = Self::meta(&fd.path, size);
        match self.injection {
            Inject::WrongType if fd.path.starts_with("Boot0004-") => meta.mode = 0o040755,
            Inject::WrongFs if fd.path.starts_with("Boot0004-") => meta.filesystem = 0x1234,
            Inject::ReadOnly if fd.path.starts_with("Boot0004-") => meta.readonly = true,
            _ => {}
        }
        Ok(meta)
    }
    fn names(&mut self, _dir: &Self::Handle) -> Result<Vec<Vec<u8>>, boothop_core::Error> {
        self.names_calls += 1;
        if self.set_next_on_names == Some(self.names_calls) {
            self.put("BootNext", [7, 0, 0, 0, 4, 0].to_vec());
        }
        if self.names_error {
            return Err(boothop_core::Error::PlatformIo {
                operation: boothop_core::PlatformOperation::Read,
                raw_code: 5,
            });
        }
        let mut names = self
            .vars
            .borrow()
            .keys()
            .map(|name| name.as_bytes().to_vec())
            .collect::<Vec<_>>();
        names.extend(self.extra_names.clone());
        Ok(names)
    }
    fn read(&mut self, fd: &mut Self::Handle, buffer: &mut [u8]) -> Result<usize, i32> {
        let vars = self.vars.borrow();
        let bytes = vars.get(&fd.path).ok_or(2)?;
        let count = (bytes.len() - fd.offset).min(buffer.len());
        buffer[..count].copy_from_slice(&bytes[fd.offset..fd.offset + count]);
        fd.offset += count;
        Ok(count)
    }
    fn write(&mut self, fd: &mut Self::Handle, bytes: &[u8]) -> Result<usize, i32> {
        let mut vars = self.vars.borrow_mut();
        let target = vars.get_mut(&fd.path).ok_or(2)?;
        if self.injection == Inject::AbsentReadback {
            target.extend_from_slice(bytes);
            drop(vars);
            self.vars.borrow_mut().remove(&fd.path);
            return Ok(bytes.len());
        }
        match self.injection {
            Inject::WriteErrorAfterMutation => {
                target.extend_from_slice(&bytes[..bytes.len().min(7)]);
                Err(5)
            }
            Inject::ShortWrite => {
                target.extend_from_slice(&bytes[..bytes.len().min(3)]);
                Ok(bytes.len().min(3))
            }
            Inject::CorruptReadback => {
                target.extend_from_slice(bytes);
                if let Some(last) = target.last_mut() {
                    *last ^= 1;
                }
                Ok(bytes.len())
            }
            Inject::DifferentReadback => {
                target.extend_from_slice(bytes);
                if let Some(first_description_byte) = target.get_mut(6) {
                    *first_description_byte ^= 2;
                }
                Ok(bytes.len())
            }
            _ => {
                target.extend_from_slice(bytes);
                Ok(bytes.len())
            }
        }
    }
    fn probe(&mut self) -> Result<Probe, boothop_core::Error> {
        Ok(Probe {
            systemd_version: "255".into(),
            polkit_version: "124".into(),
            effective_uid: 0,
            introspection: String::new(),
        })
    }
    fn reboot_with_flags(&mut self, _flags: u64) -> Reply {
        Reply::NotSent
    }
}

#[test]
fn allocator_skips_referenced_and_orphan_entries() {
    let mut calls = FakeCalls::new();
    assert_eq!(allocate_boot_id(&mut calls).unwrap(), BootId(4));
    let namespace = inspect_boot_namespace(&mut calls).unwrap();
    assert!(namespace.occupied[0]);
    assert!(namespace.occupied[5]);
    assert!(namespace.referenced[1]);
    assert!(namespace.referenced[3]);
}

#[test]
fn malformed_boot_like_names_and_incomplete_enumeration_fail_closed() {
    let mut calls = FakeCalls::new();
    calls
        .extra_names
        .push(format!("boot0008-{GUID}").into_bytes());
    assert_eq!(
        allocate_boot_id(&mut calls),
        Err(boothop_core::Error::UnsupportedFormat)
    );
    for malformed in [
        format!("Boot00G8-{GUID}"),
        "Boot0008-8BE4DF61-93CA-11D2-AA0D-00E098032B8C".into(),
    ] {
        let mut calls = FakeCalls::new();
        calls.extra_names.push(malformed.into_bytes());
        assert_eq!(
            allocate_boot_id(&mut calls),
            Err(boothop_core::Error::UnsupportedFormat)
        );
    }
    let mut calls = FakeCalls::new();
    calls
        .vars
        .borrow_mut()
        .remove(&format!("BootCurrent-{GUID}"));
    assert!(matches!(
        allocate_boot_id(&mut calls),
        Err(boothop_core::Error::PlatformIo { .. })
    ));
    let mut calls = FakeCalls::new();
    calls.names_error = true;
    assert!(matches!(
        allocate_boot_id(&mut calls),
        Err(boothop_core::Error::PlatformIo { .. })
    ));
}

#[test]
fn namespace_candidate_reports_exhaustion() {
    let namespace = boothop_platform::linux::boot_entry::BootNamespace {
        occupied: [true; 65536],
        referenced: [false; 65536],
        boot_next_set: false,
    };
    assert_eq!(
        namespace.candidate(),
        Err(boothop_core::Error::ResourceLimit)
    );
}

#[test]
fn provisioning_blocks_when_bootnext_is_already_set_or_appears_during_recheck() {
    let (esp, state, spec) = crate_test_state();
    for target in [spec.boot_id.0, 0xbeef] {
        let mut calls = FakeCalls::new();
        calls.put(
            "BootNext",
            [7, 0, 0, 0, target as u8, (target >> 8) as u8].to_vec(),
        );
        assert_eq!(allocate_boot_id(&mut calls), Err(boothop_core::Error::Busy));
        let result = create_and_verify_entry(&mut calls, &esp, &spec, &state).unwrap_err();
        assert_eq!(result.error, boothop_core::Error::Busy);
        assert_eq!(result.mutation, CreateMutationState::NoEntryCreated);
        assert!(!calls.contains(spec.boot_id.0));
    }

    let mut raced = FakeCalls::new();
    raced.set_next_on_names = Some(2);
    let result = create_and_verify_entry(&mut raced, &esp, &spec, &state).unwrap_err();
    assert_eq!(result.error, boothop_core::Error::Busy);
    assert_eq!(result.mutation, CreateMutationState::NoEntryCreated);
    assert!(!raced.contains(spec.boot_id.0));

    let (esp, mut uncertain, spec) = crate_test_state();
    if let ArchProvisionState::Provisioning(record) = &mut uncertain {
        record.residual.push(Residual::BootEntryMayExist);
    }
    let mut calls = FakeCalls::new();
    let result = create_and_verify_entry(&mut calls, &esp, &spec, &uncertain).unwrap_err();
    assert_eq!(result.error, boothop_core::Error::NotConfigured);
    assert_eq!(result.mutation, CreateMutationState::NoEntryCreated);
    assert!(!calls.contains(spec.boot_id.0));
}

#[test]
fn firmware_exclusive_create_readback_and_failure_boundaries() {
    // State assembly below uses the synthetic identity fixture, not the installed firmware.
    let mut calls = FakeCalls::new();
    let (esp, state, spec) = crate_test_state();
    assert_eq!(
        create_and_verify_entry(&mut calls, &esp, &spec, &state),
        Ok(())
    );
    assert!(calls.contains(spec.boot_id.0));
    assert_eq!(
        calls
            .events
            .borrow()
            .iter()
            .filter(|event| event.starts_with("open:Boot0004-") && event.ends_with("CreateEntry"))
            .count(),
        1
    );

    let mut collision = FakeCalls::new();
    collision.put("Boot0004", vec![7, 0, 0, 0, 0xaa]);
    let before = collision.raw(4);
    let result = create_and_verify_entry(&mut collision, &esp, &spec, &state).unwrap_err();
    assert_eq!(result.mutation, CreateMutationState::NoEntryCreated);
    assert_eq!(collision.raw(4), before);

    let mut raced = FakeCalls::new();
    raced.injection = Inject::CreateCollision;
    let result = create_and_verify_entry(&mut raced, &esp, &spec, &state).unwrap_err();
    assert_eq!(result.mutation, CreateMutationState::NoEntryCreated);
    assert_eq!(raced.raw(4), Some(b"other-owner-existing-entry".to_vec()));

    for injection in [
        Inject::CreateAfterMutationError,
        Inject::WriteErrorAfterMutation,
        Inject::ShortWrite,
        Inject::CorruptReadback,
        Inject::DifferentReadback,
        Inject::AbsentReadback,
    ] {
        let mut calls = FakeCalls::new();
        calls.injection = injection;
        let result = create_and_verify_entry(&mut calls, &esp, &spec, &state).unwrap_err();
        assert_eq!(
            result.mutation,
            CreateMutationState::MayExist,
            "injection {injection:?}: {result:?}"
        );
        if injection != Inject::AbsentReadback {
            assert!(
                calls.contains(4),
                "entry must be retained for {injection:?}"
            );
        }
    }
    for injection in [Inject::WrongType, Inject::WrongFs, Inject::ReadOnly] {
        let mut calls = FakeCalls::new();
        calls.injection = injection;
        let result = create_and_verify_entry(&mut calls, &esp, &spec, &state).unwrap_err();
        assert_eq!(
            result.mutation,
            CreateMutationState::MayExist,
            "injection {injection:?}: {result:?}"
        );
        assert_eq!(calls.raw(4), Some(Vec::new()));
    }
}

fn crate_test_state() -> (EspPartitionIdentity, ArchProvisionState, BootEntrySpec) {
    let esp = EspPartitionIdentity {
        partition_number: 9,
        start_lba: 0x0102_0304_0506_0708,
        size_lba: 0x1112_1314_1516_1718,
        partition_guid_uefi_bytes: [0x5a; 16],
    };
    let identity = canonicalize(
        &arch_uki_load_option(
            esp.partition_number,
            esp.start_lba,
            esp.size_lba,
            esp.partition_guid_uefi_bytes,
        )
        .unwrap(),
    )
    .unwrap();
    let entry = OwnedArchEntry {
        boot_id: BootId(4),
        identity: identity.clone(),
        identity_version: 1,
        uki_path: "EFI/BootHop/arch.efi".into(),
        build: BuildMetadata {
            kernel: "linux".into(),
            kernel_release: "6.12.1".into(),
            initramfs_sha256: [0x11; 32],
        },
        publish: Some(PublishMetadata {
            sha256: [0x22; 32],
            size: 100,
        }),
    };
    let spec = BootEntrySpec {
        boot_id: BootId(4),
        identity,
    };
    let state = ArchProvisionState::Provisioning(ProvisioningRecord {
        operation_id: "test-op".into(),
        operation_version: 1,
        owned_entry: entry,
        step: ProvisioningStep::BootEntryCreateAttempted,
        residual: Vec::new(),
    });
    (esp, state, spec)
}
