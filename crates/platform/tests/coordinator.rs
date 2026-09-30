#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod support;

use boothop_core::{ArchProvisionState, Error, ProvisioningStep, Residual, UninstallingStep};
use boothop_platform::linux::arch_provision_store::ArchProvisionStore;
use boothop_platform::linux::coordinator::{
    LifecycleBackend, LifecycleFailure, LifecycleReadback, ProvisionIntent, provision, recover,
    uninstall,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailAt {
    None,
    Uki,
    Entry,
    Order,
}

struct FakeBackend {
    fs: support::FakeFs,
    fail: FailAt,
    mutations: Vec<&'static str>,
    events: Vec<&'static str>,
    observations: usize,
}

impl FakeBackend {
    fn new(fs: support::FakeFs) -> Self {
        Self {
            fs,
            fail: FailAt::None,
            mutations: Vec::new(),
            events: Vec::new(),
            observations: 0,
        }
    }

    fn assert_lock(&self) {
        assert!(
            self.fs.0.borrow().held,
            "backend called after operation lock release"
        );
    }

    fn mutation(
        &mut self,
        stage: &'static str,
        residual: Residual,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.assert_lock();
        self.events.push(match stage {
            "uki" => "mutate-uki",
            "entry" => "mutate-entry",
            "order" => "mutate-order",
            _ => unreachable!(),
        });
        self.mutations.push(stage);
        let fail = match stage {
            "uki" => self.fail == FailAt::Uki,
            "entry" => self.fail == FailAt::Entry,
            "order" => self.fail == FailAt::Order,
            _ => false,
        };
        if fail {
            return Err(LifecycleFailure::uncertain(Error::ReadbackFailed, residual));
        }
        self.events.push(match stage {
            "uki" => "readback-uki",
            "entry" => "readback-entry",
            "order" => "readback-order",
            _ => unreachable!(),
        });
        Ok(match stage {
            "uki" => LifecycleReadback::UkiPresent(boothop_core::PublishMetadata {
                sha256: [0x22; 32],
                size: 42,
            }),
            "entry" => LifecycleReadback::BootEntryPresent,
            "order" => LifecycleReadback::BootOrderContains,
            _ => unreachable!(),
        })
    }
}

impl LifecycleBackend for FakeBackend {
    fn prepare_uki_publication(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<(boothop_core::PublishMetadata, LifecycleReadback), Error> {
        self.assert_lock();
        self.events.push("read-uki");
        Ok((
            boothop_core::PublishMetadata {
                sha256: [0x22; 32],
                size: 42,
            },
            LifecycleReadback::UkiAbsent,
        ))
    }
    fn publish_uki(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
        _expected: &boothop_core::PublishMetadata,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation("uki", Residual::UkiMayRemain)
    }
    fn prepare_boot_entry(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        self.events.push("read-entry");
        Ok(LifecycleReadback::BootEntryAbsent)
    }
    fn create_boot_entry(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation("entry", Residual::BootEntryMayExist)
    }
    fn prepare_boot_order_append(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        self.events.push("read-order");
        Ok(LifecycleReadback::BootOrderAbsent)
    }
    fn append_boot_order(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation("order", Residual::BootOrderMayContainEntry)
    }
    fn prepare_boot_order_remove(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        self.events.push("read-order");
        Ok(LifecycleReadback::BootOrderContains)
    }
    fn remove_boot_order(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation("order", Residual::BootOrderMayContainEntry)
            .map(|_| LifecycleReadback::BootOrderAbsent)
    }
    fn prepare_boot_entry_remove(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        self.events.push("read-entry");
        Ok(LifecycleReadback::BootEntryPresent)
    }
    fn remove_boot_entry(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation("entry", Residual::BootEntryMayExist)
            .map(|_| LifecycleReadback::BootEntryAbsent)
    }
    fn prepare_uki_remove(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        self.events.push("read-uki");
        Ok(LifecycleReadback::UkiPresent(
            boothop_core::PublishMetadata {
                sha256: [0x22; 32],
                size: 42,
            },
        ))
    }
    fn remove_uki(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation("uki", Residual::UkiMayRemain)
            .map(|_| LifecycleReadback::UkiAbsent)
    }
    fn observe(&mut self, state: &ArchProvisionState) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        self.observations += 1;
        Ok(match state {
            ArchProvisionState::Provisioning(record) => match record.step {
                ProvisioningStep::UkiPublicationAttempted => {
                    LifecycleReadback::UkiPresent(boothop_core::PublishMetadata {
                        sha256: [0x22; 32],
                        size: 42,
                    })
                }
                ProvisioningStep::BootEntryCreateAttempted => LifecycleReadback::BootEntryPresent,
                ProvisioningStep::BootOrderAppendAttempted => LifecycleReadback::BootOrderContains,
                _ => LifecycleReadback::UkiAbsent,
            },
            ArchProvisionState::Uninstalling(record) => match record.step {
                UninstallingStep::BootOrderRemovalAttempted => LifecycleReadback::BootOrderContains,
                UninstallingStep::BootEntryRemovalAttempted => LifecycleReadback::BootEntryPresent,
                UninstallingStep::UkiRemovalAttempted => {
                    LifecycleReadback::UkiPresent(boothop_core::PublishMetadata {
                        sha256: [0x22; 32],
                        size: 42,
                    })
                }
                _ => LifecycleReadback::UkiAbsent,
            },
            _ => LifecycleReadback::UkiAbsent,
        })
    }
}

fn pending_intent() -> ProvisionIntent {
    let ArchProvisionState::Ready(mut entry) = support::ready_state() else {
        unreachable!()
    };
    entry.publish = None;
    ProvisionIntent {
        operation_id: "provision-1".into(),
        owned_entry: entry,
    }
}

#[test]
fn full_provision_and_uninstall_hold_one_lock_and_reach_tombstone() {
    let fs = support::FakeFs::installed();
    let mut backend = FakeBackend::new(fs.clone());
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let ready = provision(&mut store, &mut backend, pending_intent()).unwrap();
    assert!(matches!(ready, ArchProvisionState::Ready(_)));
    assert_eq!(backend.mutations, ["uki", "entry", "order"]);
    assert_eq!(
        backend.events,
        [
            "read-uki",
            "mutate-uki",
            "readback-uki",
            "read-entry",
            "mutate-entry",
            "readback-entry",
            "read-order",
            "mutate-order",
            "readback-order",
        ]
    );
    let tombstone = uninstall(&mut store, &mut backend, "uninstall-1".into()).unwrap();
    assert!(matches!(tombstone, ArchProvisionState::Uninstalled(_)));
    assert_eq!(
        backend.mutations,
        ["uki", "entry", "order", "order", "entry", "uki"]
    );
    assert!(fs.0.borrow().held);
    drop(store);
    assert!(!fs.0.borrow().held);
}

#[test]
fn each_mutation_failure_keeps_attempt_and_residual_and_cannot_retry() {
    for fail in [FailAt::Uki, FailAt::Entry, FailAt::Order] {
        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        backend.fail = fail;
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        assert!(provision(&mut store, &mut backend, pending_intent()).is_err());
        let first_count = backend.mutations.len();
        let state = store.load().unwrap();
        assert!(
            matches!(state, ArchProvisionState::Provisioning(ref r) if matches!(r.step,
            ProvisioningStep::UkiPublicationAttempted | ProvisioningStep::BootEntryCreateAttempted | ProvisioningStep::BootOrderAppendAttempted)
            && !r.residual.is_empty())
        );
        assert_eq!(
            provision(&mut store, &mut backend, pending_intent()),
            Err(Error::NotConfigured)
        );
        assert_eq!(backend.mutations.len(), first_count);
    }
}

#[test]
fn uninstall_mutation_failures_keep_cleanup_attempt_and_never_retry() {
    for fail in [FailAt::Order, FailAt::Entry, FailAt::Uki] {
        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        provision(&mut store, &mut backend, pending_intent()).unwrap();
        backend.fail = fail;
        let before = backend.mutations.len();
        assert!(uninstall(&mut store, &mut backend, "uninstall-1".into()).is_err());
        let state = store.load().unwrap();
        assert!(
            matches!(state, ArchProvisionState::Uninstalling(ref r) if matches!(r.step,
            UninstallingStep::BootOrderRemovalAttempted | UninstallingStep::BootEntryRemovalAttempted | UninstallingStep::UkiRemovalAttempted)
            && !r.residual.is_empty())
        );
        let after_failure = backend.mutations.len();
        assert!(after_failure > before);
        assert_eq!(
            uninstall(&mut store, &mut backend, "uninstall-2".into()),
            Err(Error::NotConfigured)
        );
        assert_eq!(backend.mutations.len(), after_failure);
    }
}

#[test]
fn restart_recovery_observes_attempt_only_and_never_mutates_or_advances() {
    let fs = support::FakeFs::installed();
    let mut backend = FakeBackend::new(fs.clone());
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    backend.fail = FailAt::Order;
    assert!(provision(&mut store, &mut backend, pending_intent()).is_err());
    let before = store.load().unwrap();
    let mutations = backend.mutations.len();
    let observed = recover(&mut store, &mut backend).unwrap();
    assert_eq!(backend.mutations.len(), mutations);
    assert_eq!(backend.observations, 1);
    assert!(matches!(observed, ArchProvisionState::Provisioning(ref r)
        if r.step == ProvisioningStep::BootOrderAppendAttempted
            && r.residual.contains(&Residual::BootOrderMayContainEntry)));
    assert!(matches!(before, ArchProvisionState::Provisioning(ref r)
        if r.step == ProvisioningStep::BootOrderAppendAttempted));
}

#[test]
fn mismatched_prepare_readback_stops_before_attempt_checkpoint() {
    struct Wrong(FakeBackend);
    impl LifecycleBackend for Wrong {
        fn prepare_uki_publication(
            &mut self,
            _: &boothop_core::OwnedArchEntry,
        ) -> Result<(boothop_core::PublishMetadata, LifecycleReadback), Error> {
            self.0.assert_lock();
            Ok((
                boothop_core::PublishMetadata {
                    sha256: [0x22; 32],
                    size: 42,
                },
                LifecycleReadback::UkiPresent(boothop_core::PublishMetadata {
                    sha256: [0x22; 32],
                    size: 42,
                }),
            ))
        }
        fn publish_uki(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
            m: &boothop_core::PublishMetadata,
        ) -> Result<LifecycleReadback, LifecycleFailure> {
            self.0.publish_uki(e, m)
        }
        fn prepare_boot_entry(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
        ) -> Result<LifecycleReadback, Error> {
            self.0.prepare_boot_entry(e)
        }
        fn create_boot_entry(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
        ) -> Result<LifecycleReadback, LifecycleFailure> {
            self.0.create_boot_entry(e)
        }
        fn prepare_boot_order_append(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
        ) -> Result<LifecycleReadback, Error> {
            self.0.prepare_boot_order_append(e)
        }
        fn append_boot_order(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
        ) -> Result<LifecycleReadback, LifecycleFailure> {
            self.0.append_boot_order(e)
        }
        fn prepare_boot_order_remove(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
        ) -> Result<LifecycleReadback, Error> {
            self.0.prepare_boot_order_remove(e)
        }
        fn remove_boot_order(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
        ) -> Result<LifecycleReadback, LifecycleFailure> {
            self.0.remove_boot_order(e)
        }
        fn prepare_boot_entry_remove(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
        ) -> Result<LifecycleReadback, Error> {
            self.0.prepare_boot_entry_remove(e)
        }
        fn remove_boot_entry(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
        ) -> Result<LifecycleReadback, LifecycleFailure> {
            self.0.remove_boot_entry(e)
        }
        fn prepare_uki_remove(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
        ) -> Result<LifecycleReadback, Error> {
            self.0.prepare_uki_remove(e)
        }
        fn remove_uki(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
        ) -> Result<LifecycleReadback, LifecycleFailure> {
            self.0.remove_uki(e)
        }
        fn observe(&mut self, s: &ArchProvisionState) -> Result<LifecycleReadback, Error> {
            self.0.observe(s)
        }
    }
    let fs = support::FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let mut backend = Wrong(FakeBackend::new(fs.clone()));
    assert_eq!(
        provision(&mut store, &mut backend, pending_intent()),
        Err(Error::ReadbackFailed)
    );
    assert!(
        matches!(store.load().unwrap(), ArchProvisionState::Provisioning(ref r) if r.step == ProvisioningStep::UkiPublicationPending)
    );
}
