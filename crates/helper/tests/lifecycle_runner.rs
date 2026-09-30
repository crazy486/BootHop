#![cfg(target_os = "linux")]

#[allow(dead_code)]
#[path = "../../platform/tests/support/mod.rs"]
mod support;

use boothop_core::{ArchProvisionState, Error, Residual};
use boothop_helper::dispatch::{self, SessionIo};
use boothop_helper::protocol::{
    LifecycleOperation, LifecycleStatus, RequestId, decode_hello,
    decode_lifecycle_response_envelope, encode_lifecycle_request_with_id,
};
use boothop_platform::linux::arch_provision_store::ArchProvisionStore;
use boothop_platform::linux::coordinator::{
    BootEntryCreatePermit, BootEntryRemovePermit, BootOrderAppendPermit, BootOrderRemovePermit,
    LifecycleBackend, LifecycleFailure, LifecycleReadback, ProvisionIntent, UkiPublishPermit,
    UkiRemovePermit,
};
use boothop_platform::linux::uki::PreparedUkiArtifact;
use std::cell::Cell;
use support::{FakeFs, ready_state};

struct Io {
    input: Vec<u8>,
    output: Vec<Vec<u8>>,
}

impl SessionIo for Io {
    fn receive(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.input.clone())
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.output.push(bytes.to_vec());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailurePoint {
    ProvisionPrepare,
    UninstallPrepare,
}

struct Backend {
    fs: FakeFs,
    failure: FailurePoint,
    provision_prepares: usize,
    uninstall_prepares: usize,
    mutations: usize,
}

impl Backend {
    fn assert_locked(&self) {
        assert!(self.fs.held(), "the journal lock must span backend access");
    }

    fn rejected() -> Error {
        Error::ResourceLimit
    }
}

impl LifecycleBackend for Backend {
    fn prepare_uki_publication(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<(PreparedUkiArtifact, LifecycleReadback), Error> {
        self.assert_locked();
        self.provision_prepares += 1;
        assert_eq!(self.failure, FailurePoint::ProvisionPrepare);
        Err(Self::rejected())
    }

    fn publish_uki(
        &mut self,
        _artifact: PreparedUkiArtifact,
        _permit: UkiPublishPermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutations += 1;
        unreachable!("prepare failure must stop before publication")
    }

    fn prepare_boot_entry(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_locked();
        Err(Self::rejected())
    }

    fn create_boot_entry(
        &mut self,
        _permit: BootEntryCreatePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutations += 1;
        unreachable!("unused in these tests")
    }

    fn prepare_boot_order_append(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_locked();
        Err(Self::rejected())
    }

    fn append_boot_order(
        &mut self,
        _permit: BootOrderAppendPermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutations += 1;
        unreachable!("unused in these tests")
    }

    fn prepare_boot_order_remove(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_locked();
        self.uninstall_prepares += 1;
        assert_eq!(self.failure, FailurePoint::UninstallPrepare);
        Err(Self::rejected())
    }

    fn remove_boot_order(
        &mut self,
        _permit: BootOrderRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutations += 1;
        unreachable!("prepare failure must stop before mutation")
    }

    fn prepare_boot_entry_remove(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_locked();
        Err(Self::rejected())
    }

    fn remove_boot_entry(
        &mut self,
        _permit: BootEntryRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutations += 1;
        unreachable!("unused in these tests")
    }

    fn prepare_uki_remove(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_locked();
        Err(Self::rejected())
    }

    fn remove_uki(
        &mut self,
        _permit: UkiRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutations += 1;
        unreachable!("unused in these tests")
    }

    fn observe(&mut self, _state: &ArchProvisionState) -> Result<LifecycleReadback, Error> {
        self.assert_locked();
        Err(Self::rejected())
    }

    fn observe_uki_ownership(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_locked();
        Err(Self::rejected())
    }
}

fn backend(fs: &FakeFs, failure: FailurePoint) -> Backend {
    Backend {
        fs: fs.clone(),
        failure,
        provision_prepares: 0,
        uninstall_prepares: 0,
        mutations: 0,
    }
}

fn provision_intent() -> ProvisionIntent {
    let ArchProvisionState::Ready(mut entry) = ready_state() else {
        unreachable!()
    };
    entry.publish = None;
    ProvisionIntent {
        operation_id: "runner-provision".into(),
        owned_entry: entry,
    }
}

#[test]
fn provision_derivation_and_coordinator_run_under_one_lock_and_stop_with_residual() {
    let fs = FakeFs::installed();
    let mut backend = backend(&fs, FailurePoint::ProvisionPrepare);
    let derived = Cell::new(0);

    let status = dispatch::run_lifecycle_with(
        LifecycleOperation::ProvisionArchEntry,
        fs.clone(),
        &mut backend,
        |initial| {
            assert_eq!(initial, &ArchProvisionState::Unprovisioned);
            assert!(fs.held(), "intent is derived only after lock acquisition");
            derived.set(derived.get() + 1);
            Ok(provision_intent())
        },
        |_| panic!("provision must not derive an uninstall id"),
    );

    assert_eq!(status, LifecycleStatus::RecoveryRequired);
    assert_eq!(derived.get(), 1);
    assert_eq!(
        backend.provision_prepares, 1,
        "a failed operation is never retried"
    );
    assert_eq!(backend.mutations, 0);
    assert!(matches!(
        boothop_core::decode_arch_provision_state(fs.journal().as_deref()),
        Ok(ArchProvisionState::Provisioning(ref record))
            if record.residual == [Residual::UkiMayRemain]
    ));
    assert!(!fs.held(), "the lock is released only after status mapping");
}

#[test]
fn uninstall_derivation_and_coordinator_run_under_one_lock_and_stop_with_residual() {
    let fs = FakeFs::installed();
    let ArchProvisionState::Ready(entry) = ready_state() else {
        unreachable!()
    };
    fs.set_journal(
        boothop_core::encode_arch_provision_state(&ArchProvisionState::Ready(entry)).unwrap(),
    );
    let mut backend = backend(&fs, FailurePoint::UninstallPrepare);
    let derived = Cell::new(0);

    let status = dispatch::run_lifecycle_with(
        LifecycleOperation::UninstallArchEntry,
        fs.clone(),
        &mut backend,
        |_| panic!("uninstall must not derive a provision intent"),
        |initial| {
            assert!(matches!(initial, ArchProvisionState::Ready(_)));
            assert!(
                fs.held(),
                "uninstall id is derived only after lock acquisition"
            );
            derived.set(derived.get() + 1);
            Ok("runner-uninstall".into())
        },
    );

    assert_eq!(status, LifecycleStatus::RecoveryRequired);
    assert_eq!(derived.get(), 1);
    assert_eq!(
        backend.uninstall_prepares, 1,
        "a failed operation is never retried"
    );
    assert_eq!(backend.mutations, 0);
    assert!(matches!(
        boothop_core::decode_arch_provision_state(fs.journal().as_deref()),
        Ok(ArchProvisionState::Uninstalling(ref record))
            if record.residual == [Residual::BootEntryMayExist, Residual::BootOrderMayContainEntry]
    ));
    assert!(!fs.held(), "the lock is released only after status mapping");
}

#[test]
fn clean_terminal_state_routing_skips_unneeded_trusted_derivation() {
    let ready_fs = FakeFs::installed();
    let ArchProvisionState::Ready(entry) = ready_state() else {
        unreachable!()
    };
    ready_fs.set_journal(
        boothop_core::encode_arch_provision_state(&ArchProvisionState::Ready(entry)).unwrap(),
    );
    let mut provision_backend = backend(&ready_fs, FailurePoint::ProvisionPrepare);
    assert_eq!(
        dispatch::run_lifecycle_with(
            LifecycleOperation::ProvisionArchEntry,
            ready_fs.clone(),
            &mut provision_backend,
            |_| panic!("already-ready provisioning must not derive intent"),
            |_| panic!("provision must not derive an uninstall id"),
        ),
        LifecycleStatus::AlreadyPresent
    );
    assert_eq!(provision_backend.provision_prepares, 0);

    let empty_fs = FakeFs::installed();
    let mut uninstall_backend = backend(&empty_fs, FailurePoint::UninstallPrepare);
    assert_eq!(
        dispatch::run_lifecycle_with(
            LifecycleOperation::UninstallArchEntry,
            empty_fs,
            &mut uninstall_backend,
            |_| panic!("uninstall must not derive provision intent"),
            |_| panic!("unprovisioned uninstall must not derive id"),
        ),
        LifecycleStatus::NotPresent
    );
}

#[test]
fn busy_shared_lock_is_a_clean_failure_without_discovery_or_backend_access() {
    let fs = FakeFs::installed();
    let incumbent = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let mut backend = backend(&fs, FailurePoint::ProvisionPrepare);
    let derivations = Cell::new(0);

    let status = dispatch::run_lifecycle_with(
        LifecycleOperation::ProvisionArchEntry,
        fs.clone(),
        &mut backend,
        |_| {
            derivations.set(derivations.get() + 1);
            Err(Error::ResourceLimit)
        },
        |_| {
            derivations.set(derivations.get() + 1);
            Err(Error::ResourceLimit)
        },
    );

    assert_eq!(status, LifecycleStatus::Failed);
    assert_eq!(derivations.get(), 0);
    assert_eq!(backend.provision_prepares, 0);
    assert_eq!(backend.uninstall_prepares, 0);
    assert_eq!(backend.mutations, 0);
    assert!(fs.held(), "the incumbent operation still owns the lock");
    assert_eq!(
        fs.journal(),
        None,
        "lock contention must not invent residual state"
    );

    drop(incumbent);
    assert!(!fs.held());
}

#[test]
fn unreadable_journal_maps_to_recovery_without_deriving_or_touching_backend() {
    let fs = FakeFs::installed();
    fs.set_journal(b"{\"version\":999}".to_vec());
    let mut backend = backend(&fs, FailurePoint::ProvisionPrepare);
    let status = dispatch::run_lifecycle_with(
        LifecycleOperation::ProvisionArchEntry,
        fs.clone(),
        &mut backend,
        |_| panic!("unknown state must not derive intent"),
        |_| panic!("wrong operation closure"),
    );

    assert_eq!(status, LifecycleStatus::RecoveryRequired);
    assert_eq!(backend.provision_prepares, 0);
    assert_eq!(backend.mutations, 0);
    assert!(!fs.held());
}

#[test]
fn lifecycle_ipc_frame_routes_through_runner_and_returns_typed_status() {
    let request_id = RequestId::parse("0123456789abcdef0123456789abcde2").unwrap();
    let cases = [
        (
            LifecycleOperation::ProvisionArchEntry,
            FailurePoint::ProvisionPrepare,
            LifecycleStatus::RecoveryRequired,
            false,
        ),
        (
            LifecycleOperation::UninstallArchEntry,
            FailurePoint::UninstallPrepare,
            LifecycleStatus::RecoveryRequired,
            true,
        ),
    ];

    for (operation, failure, expected_status, ready) in cases {
        let fs = FakeFs::installed();
        if ready {
            let ArchProvisionState::Ready(entry) = ready_state() else {
                unreachable!()
            };
            fs.set_journal(
                boothop_core::encode_arch_provision_state(&ArchProvisionState::Ready(entry))
                    .unwrap(),
            );
        }
        let mut backend = backend(&fs, failure);
        let input = encode_lifecycle_request_with_id(&request_id, operation.clone()).unwrap();
        let mut io = Io {
            input,
            output: Vec::new(),
        };

        dispatch::serve_lifecycle(0, &mut io, |decoded_operation| {
            dispatch::run_lifecycle_with(
                decoded_operation,
                fs.clone(),
                &mut backend,
                |initial| {
                    assert!(matches!(
                        initial,
                        ArchProvisionState::Unprovisioned | ArchProvisionState::Uninstalled(_)
                    ));
                    Ok(provision_intent())
                },
                |initial| {
                    assert!(matches!(initial, ArchProvisionState::Ready(_)));
                    Ok("ipc-uninstall".into())
                },
            )
        })
        .unwrap();

        assert_eq!(io.output.len(), 2);
        decode_hello(&io.output[0]).unwrap();
        let response = decode_lifecycle_response_envelope(&io.output[1]).unwrap();
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.status, expected_status);
        match operation {
            LifecycleOperation::ProvisionArchEntry => {
                assert_eq!(backend.provision_prepares, 1);
                assert_eq!(backend.uninstall_prepares, 0);
            }
            LifecycleOperation::UninstallArchEntry => {
                assert_eq!(backend.provision_prepares, 0);
                assert_eq!(backend.uninstall_prepares, 1);
            }
        }
    }
}

#[test]
fn invalid_uninstall_id_is_a_clean_failure_without_backend_or_retry() {
    let fs = FakeFs::installed();
    let ArchProvisionState::Ready(entry) = ready_state() else {
        unreachable!()
    };
    let original = ArchProvisionState::Ready(entry);
    fs.set_journal(boothop_core::encode_arch_provision_state(&original).unwrap());
    let mut backend = backend(&fs, FailurePoint::UninstallPrepare);

    assert_eq!(
        dispatch::run_lifecycle_with(
            LifecycleOperation::UninstallArchEntry,
            fs.clone(),
            &mut backend,
            |_| panic!("uninstall must not derive a provision intent"),
            |initial| {
                assert_eq!(initial, &original);
                assert!(fs.held());
                Ok(String::new())
            },
        ),
        LifecycleStatus::Failed
    );

    assert_eq!(backend.uninstall_prepares, 0);
    assert_eq!(backend.mutations, 0);
    assert_eq!(
        boothop_core::decode_arch_provision_state(fs.journal().as_deref()),
        Ok(original)
    );
    assert!(!fs.held());
}
