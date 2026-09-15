#![cfg(target_os = "linux")]
mod support;
use boothop_core::{Error, PlatformOperation, RecordState};
use boothop_platform::{ProtectedStore, linux::store::LockedStore};
use support::*;

// Catches a save that skips reloading the on-disk version and destroys newer records.
#[test]
fn unknown_record_not_overwritten() {
    let fs = FakeFs::installed();
    fs.set_record(br#"{"version":999,"target":{}}"#.to_vec());
    let old = fs.record();
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(
        store.save(&target()),
        Err(Error::UnsupportedRecordVersion { found: 999 })
    );
    assert_eq!(fs.record(), old);
}

#[test]
fn installer_precreates_layout_first_inspect_reports_missing_record() {
    let fs = FakeFs::installed();
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(store.load(), Ok(RecordState::Missing));
    assert!(fs.held());
    drop(store);
    assert!(!fs.held());
}

// Catches missing path validation, insecure metadata acceptance, and repair on configure.
#[test]
fn writable_parent_symlink_hardlink_rejected() {
    for (path, field, value) in [
        ("/", "mode", 0o40777),
        ("/var", "mode", 0o40775),
        ("/var/lib", "uid", 1000),
        ("/var/lib/boothop", "mode", 0o40750),
        ("/var/lib/boothop", "gid", 1000),
        ("/var/lib/boothop", "mode", 0o120700),
        ("/var/lib/boothop/operation.lock", "links", 2),
        ("/var/lib/boothop/operation.lock", "mode", 0o100640),
        ("/var/lib/boothop/operation.lock", "uid", 1000),
        ("/var/lib/boothop/operation.lock", "mode", 0o010600),
        ("/var/lib/boothop/targets.json", "gid", 1000),
        ("/var/lib/boothop/targets.json", "links", 2),
        ("/var/lib/boothop/targets.json", "mode", 0o120600),
        ("/var/lib/boothop/targets.json", "mode", 0o100660),
        ("/var/lib/boothop/targets.json", "mode", 0o040600),
    ] {
        let fs = FakeFs::installed();
        fs.set_record(boothop_core::encode_record(&target()).unwrap());
        let before = fs.record();
        {
            let s = fs.0.borrow();
            let mut node = s.nodes[path].borrow_mut();
            match field {
                "uid" => node.meta.uid = value,
                "gid" => node.meta.gid = value,
                "mode" => node.meta.mode = value,
                _ => node.meta.links = value.into(),
            }
        }
        let result = LockedStore::acquire(fs.clone()).and_then(|mut s| s.save(&target()));
        assert!(result.is_err(), "{path} {field} {value}");
        assert_eq!(fs.record(), before);
        assert!(!fs.held());
        assert!(!fs.0.borrow().events.iter().any(|e| e == "create"));
    }
}

#[test]
fn configure_does_not_repair_install_layout() {
    for path in ["/var/lib/boothop", "/var/lib/boothop/operation.lock"] {
        let fs = FakeFs::installed();
        fs.0.borrow_mut().nodes.remove(path);
        let result = LockedStore::acquire(fs.clone()).and_then(|mut s| s.save(&target()));
        assert!(
            matches!(result,Err(Error::PlatformIo{operation,raw_code:2}) if operation == PlatformOperation::Open)
        );
        assert!(!fs.0.borrow().nodes.contains_key(path));
        assert_eq!(fs.record(), None);
    }
}

#[test]
fn permission_error_not_missing() {
    let fs = FakeFs::installed();
    fs.0.borrow_mut().fail = Some(("open_record", 13));
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(
        store.load(),
        Err(Error::PlatformIo {
            operation: PlatformOperation::Open,
            raw_code: 13
        })
    );
    assert_eq!(
        store.save(&target()),
        Err(Error::PlatformIo {
            operation: PlatformOperation::Open,
            raw_code: 13
        })
    );
    assert_eq!(fs.record(), None);
}

#[test]
fn corrupt_and_oversize_records_are_not_overwritten() {
    for (bytes, error) in [
        (b"broken".to_vec(), Error::CorruptRecord),
        (vec![b' '; 1_048_577], Error::ResourceLimit),
    ] {
        let fs = FakeFs::installed();
        fs.set_record(bytes);
        let old = fs.record();
        let mut store = LockedStore::acquire(fs.clone()).unwrap();
        assert_eq!(store.save(&target()), Err(error));
        assert_eq!(fs.record(), old);
    }
}

// Catches replacement before all bytes and temp fsync succeed, and generic errno loss.
#[test]
fn pre_rename_failures_preserve_old_record() {
    for (stage, operation, code) in [
        ("create", PlatformOperation::Open, 28),
        ("read", PlatformOperation::Read, 5),
        ("write", PlatformOperation::Write, 28),
        ("rename", PlatformOperation::Replace, 5),
    ] {
        let fs = FakeFs::installed();
        fs.set_record(boothop_core::encode_record(&target()).unwrap());
        let old = fs.record();
        fs.0.borrow_mut().fail = Some((stage, code));
        let mut store = LockedStore::acquire(fs.clone()).unwrap();
        assert_eq!(
            store.save(&target()),
            Err(Error::PlatformIo {
                operation,
                raw_code: code
            })
        );
        assert_eq!(fs.record(), old);
        drop(store);
        assert!(!fs.held());
        assert_eq!(fs.0.borrow().nodes.len(), 6);
    }
}

#[test]
fn temp_fsync_platform_io_preserves_old() {
    let fs = FakeFs::installed();
    fs.set_record(boothop_core::encode_record(&target()).unwrap());
    let old = fs.record();
    fs.0.borrow_mut().fail = Some(("temp_fsync", 5));
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(
        store.save(&target()),
        Err(Error::PlatformIo {
            operation: PlatformOperation::Flush,
            raw_code: 5
        })
    );
    assert_eq!(fs.record(), old);
    assert_eq!(fs.0.borrow().nodes.len(), 6);
}

#[test]
fn post_rename_dir_fsync_store_durability_unknown() {
    let fs = FakeFs::installed();
    fs.set_record(boothop_core::encode_record(&target()).unwrap());
    fs.0.borrow_mut().fail = Some(("dir_fsync", 5));
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    let mut changed = target();
    changed.boot_id = boothop_core::BootId(8);
    assert_eq!(
        store.save(&changed),
        Err(Error::StoreDurabilityUnknown { raw_code: 5 })
    );
    assert_eq!(
        boothop_core::decode_record(&fs.record().unwrap()),
        Ok(changed)
    );
    assert_eq!(
        fs.0.borrow()
            .events
            .iter()
            .filter(|s| s.as_str() == "rename")
            .count(),
        1
    );
    assert!(!fs.0.borrow().events.iter().any(|s| s == "unlink"));
}

#[test]
fn secure_store_roundtrip_full_write_and_fixed_lock_inode() {
    let fs = FakeFs::installed();
    let inode = fs.0.borrow().nodes["/var/lib/boothop/operation.lock"]
        .borrow()
        .meta
        .inode;
    fs.0.borrow_mut().write_limit = Some(7);
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    store.save(&target()).unwrap();
    assert_eq!(store.load(), Ok(RecordState::Ready(target())));
    assert_eq!(
        fs.0.borrow().nodes["/var/lib/boothop/operation.lock"]
            .borrow()
            .meta
            .inode,
        inode
    );
    assert_eq!(
        fs.0.borrow().nodes["/var/lib/boothop/targets.json"]
            .borrow()
            .meta
            .mode,
        0o100600
    );
    assert!(fs.held());
    drop(store);
    assert!(!fs.held());
    let s = fs.0.borrow();
    let names: Vec<_> = s
        .events
        .iter()
        .filter(|e| ["temp_fsync", "rename", "dir_fsync"].contains(&e.as_str()))
        .map(String::as_str)
        .collect();
    assert_eq!(names, ["temp_fsync", "rename", "dir_fsync"]);
}

// A lock conflict must never be a generic I/O error or permit store side effects.
#[test]
fn busy_lock_has_no_record_mutation() {
    let fs = FakeFs::installed();
    let first = LockedStore::acquire(fs.clone()).unwrap();
    let before = fs.0.borrow().events.len();
    assert!(matches!(LockedStore::acquire(fs.clone()), Err(Error::Busy)));
    assert_eq!(fs.record(), None);
    assert!(fs.held());
    assert!(
        !fs.0.borrow().events[before..]
            .iter()
            .any(|e| e == "read" || e == "write" || e == "create")
    );
    drop(first);
    assert!(!fs.held());
    assert_eq!(fs.0.borrow().open_handles, 0);
    drop(LockedStore::acquire(fs.clone()).unwrap());
    assert_eq!(fs.0.borrow().open_handles, 0);
}

#[test]
fn lock_errors_preserve_errno_and_release_open_handles() {
    for (stage, operation, code) in [
        ("root", PlatformOperation::Open, 13),
        ("metadata", PlatformOperation::Metadata, 5),
        ("lock", PlatformOperation::Lock, 4),
        ("lock", PlatformOperation::Lock, 13),
    ] {
        let fs = FakeFs::installed();
        fs.0.borrow_mut().fail = Some((stage, code));
        assert!(
            matches!(LockedStore::acquire(fs.clone()),Err(Error::PlatformIo{operation: actual,raw_code}) if actual == operation&&raw_code==code)
        );
        assert_eq!(fs.record(), None);
        assert!(!fs.held());
        assert_eq!(fs.0.borrow().open_handles, 0);
    }
}

// A fresh load must reject bytes that changed size after opening instead of trusting the first stat.
#[test]
fn changed_record_size_is_not_a_complete_read() {
    for delta in [-1_i64, 1] {
        let fs = FakeFs::installed();
        fs.set_record(boothop_core::encode_record(&target()).unwrap());
        {
            let s = fs.0.borrow();
            let mut n = s.nodes["/var/lib/boothop/targets.json"].borrow_mut();
            n.meta.size = (n.meta.size as i64 + delta) as u64;
        }
        let mut store = LockedStore::acquire(fs.clone()).unwrap();
        assert_eq!(
            store.load(),
            Err(Error::PlatformIo {
                operation: PlatformOperation::Read,
                raw_code: 5
            })
        );
    }
}

#[test]
fn record_limit_applies_to_stream_not_only_initial_metadata() {
    let fs = FakeFs::installed();
    fs.set_record(vec![b' '; 1_048_577]);
    fs.0.borrow().nodes["/var/lib/boothop/targets.json"]
        .borrow_mut()
        .meta
        .size = 1;
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(store.load(), Err(Error::ResourceLimit));
}

#[test]
fn record_at_limit_and_short_reads_are_complete() {
    let fs = FakeFs::installed();
    let mut bytes = boothop_core::encode_record(&target()).unwrap();
    bytes.resize(1_048_576, b' ');
    fs.set_record(bytes);
    fs.0.borrow_mut().read_limit = Some(701);
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(store.load(), Ok(RecordState::Ready(target())));
}

#[test]
fn save_reloads_version_after_an_earlier_successful_load() {
    let fs = FakeFs::installed();
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(store.load(), Ok(RecordState::Missing));
    fs.set_record(br#"{"version":999}"#.to_vec());
    let old = fs.record();
    assert_eq!(
        store.save(&target()),
        Err(Error::UnsupportedRecordVersion { found: 999 })
    );
    assert_eq!(fs.record(), old);
    assert!(!fs.0.borrow().events.iter().any(|e| e == "create"));
}

#[test]
fn zero_write_and_partial_write_error_preserve_old_bytes() {
    for zero in [true, false] {
        let fs = FakeFs::installed();
        fs.set_record(boothop_core::encode_record(&target()).unwrap());
        let old = fs.record();
        fs.0.borrow_mut().write_limit = Some(if zero { 0 } else { 7 });
        if !zero {
            fs.0.borrow_mut().fail_after = Some(("write", 1, 28));
        }
        let mut store = LockedStore::acquire(fs.clone()).unwrap();
        assert_eq!(
            store.save(&target()),
            Err(Error::PlatformIo {
                operation: PlatformOperation::Write,
                raw_code: if zero { 5 } else { 28 }
            })
        );
        assert_eq!(fs.record(), old);
        assert_eq!(fs.0.borrow().nodes.len(), 6);
        assert!(!fs.0.borrow().events.iter().any(|e| e == "rename"));
    }
}

// Cleanup must leave an unrelated inode at the temporary name alone.
#[test]
fn cleanup_never_deletes_replaced_temporary_name() {
    let fs = FakeFs::installed();
    fs.0.borrow_mut().fail = Some(("write", 28));
    fs.0.borrow_mut().replace_temp_on_write_failure = true;
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(
        store.save(&target()),
        Err(Error::PlatformIo {
            operation: PlatformOperation::Write,
            raw_code: 28
        })
    );
    assert!(
        fs.0.borrow()
            .nodes
            .values()
            .any(|n| n.borrow().bytes == b"external replacement")
    );
    assert_eq!(fs.record(), None);
}

#[test]
fn growing_record_is_bounded_and_never_returned_as_complete() {
    for (growth, error) in [
        (
            vec![b' '],
            Error::PlatformIo {
                operation: PlatformOperation::Read,
                raw_code: 5,
            },
        ),
        (vec![b' '; 1_048_576], Error::ResourceLimit),
    ] {
        let fs = FakeFs::installed();
        fs.set_record(boothop_core::encode_record(&target()).unwrap());
        fs.0.borrow_mut().read_limit = Some(17);
        fs.0.borrow_mut().grow_on_read = Some(growth);
        let mut store = LockedStore::acquire(fs.clone()).unwrap();
        assert_eq!(store.load(), Err(error));
        assert!(fs.0.borrow().bytes_read <= 1_048_577);
    }
}

#[test]
fn exclusive_temp_collision_is_preserved_without_retry_or_rename() {
    let fs = FakeFs::installed();
    fs.0.borrow_mut().collide_temp = true;
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(
        store.save(&target()),
        Err(Error::PlatformIo {
            operation: PlatformOperation::Open,
            raw_code: 17
        })
    );
    assert_eq!(fs.record(), None);
    assert!(
        fs.0.borrow()
            .nodes
            .values()
            .any(|n| n.borrow().bytes == b"existing unrelated temp")
    );
    assert_eq!(
        fs.0.borrow()
            .events
            .iter()
            .filter(|e| e.as_str() == "create")
            .count(),
        1
    );
}

#[test]
fn insecure_temporary_object_is_not_published_or_repaired() {
    for meta in [
        (1000, 0, 0o100600, 1),
        (0, 1000, 0o100600, 1),
        (0, 0, 0o100644, 1),
        (0, 0, 0o100600, 2),
        (0, 0, 0o010600, 1),
    ] {
        let fs = FakeFs::installed();
        fs.set_record(boothop_core::encode_record(&target()).unwrap());
        let old = fs.record();
        fs.0.borrow_mut().temp_metadata = Some(meta);
        let mut store = LockedStore::acquire(fs.clone()).unwrap();
        assert_eq!(
            store.save(&target()),
            Err(Error::PlatformIo {
                operation: PlatformOperation::Metadata,
                raw_code: 1
            })
        );
        assert_eq!(fs.record(), old);
        assert!(
            !fs.0
                .borrow()
                .events
                .iter()
                .any(|e| e == "write" || e == "rename")
        );
    }
}

#[test]
fn metadata_or_cleanup_failure_preserves_primary_error_and_old_record() {
    for metadata in [true, false] {
        let fs = FakeFs::installed();
        fs.set_record(boothop_core::encode_record(&target()).unwrap());
        let old = fs.record();
        if metadata {
            fs.0.borrow_mut().fail = Some(("temp_metadata", 5));
        } else {
            let mut s = fs.0.borrow_mut();
            s.fail_after = Some(("write", 0, 28));
            s.fail = Some(("unlink", 13));
        }
        let mut store = LockedStore::acquire(fs.clone()).unwrap();
        assert_eq!(
            store.save(&target()),
            Err(Error::PlatformIo {
                operation: if metadata {
                    PlatformOperation::Metadata
                } else {
                    PlatformOperation::Write
                },
                raw_code: if metadata { 5 } else { 28 }
            })
        );
        assert_eq!(fs.record(), old);
        drop(store);
        assert_eq!(fs.0.borrow().open_handles, 0);
        assert_eq!(fs.0.borrow().nodes.len(), 7); // retained private temp when safe cleanup is unavailable
    }
}

#[test]
fn unsupported_identity_component_cannot_be_overwritten() {
    let fs = FakeFs::installed();
    let bytes = String::from_utf8(boothop_core::encode_record(&target()).unwrap())
        .unwrap()
        .replace("Sha256", "FutureHash");
    fs.set_record(bytes.into_bytes());
    let old = fs.record();
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(
        store.save(&target()),
        Err(Error::UnsupportedIdentityComponent)
    );
    assert_eq!(fs.record(), old);
}

#[test]
fn invalid_large_target_rejected_before_temp_creation() {
    let fs = FakeFs::installed();
    let mut huge = target();
    let boothop_core::CanonicalDevicePathNode::FilePath(path) = &mut huge.identity.nodes[1] else {
        unreachable!()
    };
    path.path_utf16 = vec![b'x' as u16; 1_048_577];
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(store.save(&huge), Err(Error::CorruptRecord));
    assert_eq!(fs.record(), None);
    assert!(!fs.0.borrow().events.iter().any(|e| e == "create"));
}

#[test]
fn maximum_supported_path_is_saved_completely() {
    let fs = FakeFs::installed();
    let mut large = target();
    let boothop_core::CanonicalDevicePathNode::FilePath(path) = &mut large.identity.nodes[1] else {
        unreachable!()
    };
    path.path_utf16 = vec![65535; 32741];
    path.path_utf16[0] = 92;
    path.length = 65488;
    large.identity.file_path_list_length = 65534;
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    store.save(&large).unwrap();
    assert_eq!(
        boothop_core::decode_record(&fs.record().unwrap()),
        Ok(large)
    );
    assert!(fs.record().unwrap().len() <= 1_048_576);
}

// Catches ignoring second- or nanosecond-resolution mtime/ctime changes during a read.
#[test]
fn same_length_in_place_change_during_short_read_is_rejected() {
    for stamp in 0..4 {
        let fs = FakeFs::installed();
        let original = boothop_core::encode_record(&target()).unwrap();
        let replacement = String::from_utf8(original.clone())
            .unwrap()
            .replace("\"boot_id\":7", "\"boot_id\":8")
            .into_bytes();
        assert_ne!(replacement, original);
        assert_eq!(replacement.len(), original.len());
        fs.set_record(original);
        let before = fs.0.borrow().nodes["/var/lib/boothop/targets.json"]
            .borrow()
            .meta;
        fs.0.borrow_mut().read_limit = Some(8);
        fs.0.borrow_mut().rewrite_on_read = Some((replacement.clone(), stamp));
        let mut store = LockedStore::acquire(fs.clone()).unwrap();
        let result = store.load();
        assert_eq!(fs.record(), Some(replacement));
        let after = fs.0.borrow().nodes["/var/lib/boothop/targets.json"]
            .borrow()
            .meta;
        assert_eq!(
            (
                before.uid,
                before.gid,
                before.mode,
                before.links,
                before.device,
                before.inode,
                before.size
            ),
            (
                after.uid,
                after.gid,
                after.mode,
                after.links,
                after.device,
                after.inode,
                after.size
            )
        );
        assert_ne!(before, after); // only the selected change stamp advanced
        assert_eq!(
            result,
            Err(Error::PlatformIo {
                operation: PlatformOperation::Read,
                raw_code: 5
            }),
            "timestamp component {stamp}"
        );
        drop(store);
        assert_eq!(fs.0.borrow().open_handles, 0);
    }
}

#[test]
fn unchanged_change_stamps_allow_normal_short_reads() {
    let fs = FakeFs::installed();
    fs.set_record(boothop_core::encode_record(&target()).unwrap());
    fs.0.borrow_mut().read_limit = Some(8);
    let before = fs.0.borrow().nodes["/var/lib/boothop/targets.json"]
        .borrow()
        .meta;
    let mut store = LockedStore::acquire(fs.clone()).unwrap();
    assert_eq!(store.load(), Ok(RecordState::Ready(target())));
    assert_eq!(
        fs.0.borrow().nodes["/var/lib/boothop/targets.json"]
            .borrow()
            .meta,
        before
    );
}
