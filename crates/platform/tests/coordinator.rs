#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod support;

use boothop_core::{ArchProvisionState, Error, ProvisioningStep, Residual, UninstallingStep};
use boothop_platform::linux::arch_provision_store::ArchProvisionStore;
use boothop_platform::linux::boot_order::BootOrderValue;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrderShape {
    Reordered,
    PrefixOmitted,
    DuplicateOwned,
    ForeignId,
    WrongAttributes,
}

struct FakeBackend {
    fs: support::FakeFs,
    fail: FailAt,
    mismatch: FailAt,
    prepare_fail: FailAt,
    prepare_mismatch: FailAt,
    observe_absent: FailAt,
    observe_error: bool,
    uki_mismatch: bool,
    observe_uki_absent: bool,
    observed_order_override: Option<BootOrderValue>,
    uninstalling: bool,
    order_shape: Option<OrderShape>,
    mutations: Vec<&'static str>,
    events: Vec<&'static str>,
    observations: usize,
}

impl FakeBackend {
    fn new(fs: support::FakeFs) -> Self {
        Self {
            fs,
            fail: FailAt::None,
            mismatch: FailAt::None,
            prepare_fail: FailAt::None,
            prepare_mismatch: FailAt::None,
            observe_absent: FailAt::None,
            observe_error: false,
            uki_mismatch: false,
            observe_uki_absent: false,
            observed_order_override: None,
            uninstalling: false,
            order_shape: None,
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

    fn trace(&self, event: &'static str) {
        self.fs.0.borrow_mut().events.push(event.into());
    }

    fn mutation(
        &mut self,
        stage: &'static str,
        residual: Residual,
        entry: Option<&boothop_core::OwnedArchEntry>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.assert_lock();
        self.trace(match stage {
            "uki" => "external-mutate-uki",
            "entry" => "external-mutate-entry",
            "order" => "external-mutate-order",
            _ => unreachable!(),
        });
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
        if self.mismatch
            == match stage {
                "uki" => FailAt::Uki,
                "entry" => FailAt::Entry,
                "order" => FailAt::Order,
                _ => FailAt::None,
            }
        {
            return Ok(match stage {
                "uki" => LifecycleReadback::UkiPresent(boothop_core::PublishMetadata {
                    sha256: [0x33; 32],
                    size: 43,
                }),
                "entry" => {
                    let mut identity = entry.expect("entry readback identity").identity.clone();
                    identity.file_path_list_length = identity.file_path_list_length.wrapping_add(1);
                    LifecycleReadback::BootEntryPresent(identity)
                }
                "order" => LifecycleReadback::BootOrder(match self.order_shape {
                    Some(OrderShape::DuplicateOwned) => BootOrderValue {
                        attributes: 7,
                        ids: vec![
                            boothop_core::BootId(7),
                            boothop_core::BootId(8),
                            boothop_core::BootId(0x1234),
                            boothop_core::BootId(0x1234),
                        ],
                    },
                    Some(OrderShape::WrongAttributes) => BootOrderValue {
                        attributes: 0,
                        ids: vec![
                            boothop_core::BootId(7),
                            boothop_core::BootId(8),
                            boothop_core::BootId(0x1234),
                        ],
                    },
                    Some(OrderShape::PrefixOmitted) => {
                        BootOrderValue::new(7, vec![boothop_core::BootId(0x1234)]).unwrap()
                    }
                    Some(OrderShape::ForeignId) => BootOrderValue::new(
                        7,
                        vec![
                            boothop_core::BootId(7),
                            boothop_core::BootId(8),
                            boothop_core::BootId(0x1234),
                            boothop_core::BootId(9),
                        ],
                    )
                    .unwrap(),
                    Some(OrderShape::Reordered) | None if self.uninstalling => BootOrderValue::new(
                        7,
                        vec![
                            boothop_core::BootId(8),
                            boothop_core::BootId(7),
                            boothop_core::BootId(0x1234),
                        ],
                    )
                    .unwrap(),
                    Some(OrderShape::Reordered) | None => BootOrderValue::new(
                        7,
                        vec![
                            boothop_core::BootId(0x1234),
                            boothop_core::BootId(7),
                            boothop_core::BootId(8),
                        ],
                    )
                    .unwrap(),
                }),
                _ => unreachable!(),
            });
        }
        self.events.push(match stage {
            "uki" => "readback-uki",
            "entry" => "readback-entry",
            "order" => "readback-order",
            _ => unreachable!(),
        });
        self.trace(match stage {
            "uki" => "external-readback-uki",
            "entry" => "external-readback-entry",
            "order" => "external-readback-order",
            _ => unreachable!(),
        });
        Ok(match stage {
            "uki" => LifecycleReadback::UkiPresent(boothop_core::PublishMetadata {
                sha256: [0x22; 32],
                size: 42,
            }),
            "entry" => LifecycleReadback::BootEntryPresent(
                entry.expect("entry readback identity").identity.clone(),
            ),
            "order" => LifecycleReadback::BootOrder(
                BootOrderValue::new(
                    7,
                    if self.uninstalling {
                        vec![boothop_core::BootId(7), boothop_core::BootId(8)]
                    } else {
                        vec![
                            boothop_core::BootId(7),
                            boothop_core::BootId(8),
                            boothop_core::BootId(0x1234),
                        ]
                    },
                )
                .unwrap(),
            ),
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
        if self.prepare_fail == FailAt::Uki {
            return Err(Error::Busy);
        }
        self.trace("external-read-uki");
        self.events.push("read-uki");
        if self.prepare_mismatch == FailAt::Uki {
            return Ok((
                boothop_core::PublishMetadata {
                    sha256: [0x22; 32],
                    size: 42,
                },
                LifecycleReadback::UkiPresent(boothop_core::PublishMetadata {
                    sha256: [0x33; 32],
                    size: 43,
                }),
            ));
        }
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
        self.mutation("uki", Residual::UkiMayRemain, None)
    }
    fn prepare_boot_entry(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        if self.prepare_fail == FailAt::Entry {
            return Err(Error::Busy);
        }
        self.trace("external-read-entry");
        self.events.push("read-entry");
        if self.prepare_mismatch == FailAt::Entry {
            let mut identity = _entry.identity.clone();
            identity.file_path_list_length = identity.file_path_list_length.wrapping_add(1);
            return Ok(LifecycleReadback::BootEntryPresent(identity));
        }
        Ok(LifecycleReadback::BootEntryAbsent)
    }
    fn create_boot_entry(
        &mut self,
        entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation("entry", Residual::BootEntryMayExist, Some(entry))
    }
    fn prepare_boot_order_append(
        &mut self,
        entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        if self.prepare_fail == FailAt::Order {
            return Err(Error::Busy);
        }
        self.trace("external-read-order");
        self.events.push("read-order");
        if self.prepare_mismatch == FailAt::Order {
            return Ok(LifecycleReadback::BootOrder(
                BootOrderValue::new(
                    7,
                    vec![
                        boothop_core::BootId(7),
                        boothop_core::BootId(8),
                        entry.boot_id,
                    ],
                )
                .unwrap(),
            ));
        }
        Ok(LifecycleReadback::BootOrder(
            BootOrderValue::new(7, vec![boothop_core::BootId(7), boothop_core::BootId(8)]).unwrap(),
        ))
    }
    fn append_boot_order(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation("order", Residual::BootOrderMayContainEntry, None)
    }
    fn prepare_boot_order_remove(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        self.uninstalling = true;
        if self.prepare_fail == FailAt::Order {
            return Err(Error::Busy);
        }
        self.trace("external-read-order");
        self.events.push("read-order");
        if self.prepare_mismatch == FailAt::Order {
            return Ok(LifecycleReadback::BootOrder(
                BootOrderValue::new(7, vec![boothop_core::BootId(7), boothop_core::BootId(8)])
                    .unwrap(),
            ));
        }
        Ok(LifecycleReadback::BootOrder(
            BootOrderValue::new(
                7,
                vec![
                    boothop_core::BootId(7),
                    boothop_core::BootId(8),
                    boothop_core::BootId(0x1234),
                ],
            )
            .unwrap(),
        ))
    }
    fn remove_boot_order(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        let observed = self.mutation("order", Residual::BootOrderMayContainEntry, None)?;
        if self.mismatch == FailAt::Order {
            Ok(observed)
        } else {
            Ok(LifecycleReadback::BootOrder(
                BootOrderValue::new(7, vec![boothop_core::BootId(7), boothop_core::BootId(8)])
                    .unwrap(),
            ))
        }
    }
    fn prepare_boot_entry_remove(
        &mut self,
        entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        if self.prepare_fail == FailAt::Entry {
            return Err(Error::Busy);
        }
        self.trace("external-read-entry");
        self.events.push("read-entry");
        if self.prepare_mismatch == FailAt::Entry {
            return Ok(LifecycleReadback::BootEntryAbsent);
        }
        Ok(LifecycleReadback::BootEntryPresent(entry.identity.clone()))
    }
    fn remove_boot_entry(
        &mut self,
        entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation("entry", Residual::BootEntryMayExist, Some(entry))
            .map(|_| {
                if self.mismatch == FailAt::Entry {
                    LifecycleReadback::BootEntryPresent(entry.identity.clone())
                } else {
                    LifecycleReadback::BootEntryAbsent
                }
            })
    }
    fn prepare_uki_remove(
        &mut self,
        entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        if self.prepare_fail == FailAt::Uki {
            return Err(Error::Busy);
        }
        self.trace("external-read-uki");
        self.events.push("read-uki");
        if self.prepare_mismatch == FailAt::Uki {
            return Ok(LifecycleReadback::UkiAbsent);
        }
        Ok(LifecycleReadback::UkiPresent(
            entry.publish.clone().expect("published fixture"),
        ))
    }
    fn remove_uki(
        &mut self,
        entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation("uki", Residual::UkiMayRemain, None).map(|_| {
            if self.mismatch == FailAt::Uki {
                LifecycleReadback::UkiPresent(entry.publish.clone().expect("published fixture"))
            } else {
                LifecycleReadback::UkiAbsent
            }
        })
    }
    fn observe_uki_ownership(
        &mut self,
        entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        if self.observe_uki_absent {
            return Ok(LifecycleReadback::UkiAbsent);
        }
        let mut metadata = entry.publish.clone().expect("published fixture");
        if self.uki_mismatch {
            metadata.size += 1;
        }
        Ok(LifecycleReadback::UkiPresent(metadata))
    }
    fn observe(&mut self, state: &ArchProvisionState) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        self.observations += 1;
        if self.observe_error {
            return Err(Error::Busy);
        }
        if let Some(order) = self.observed_order_override.clone() {
            return Ok(LifecycleReadback::BootOrder(order));
        }
        Ok(match state {
            ArchProvisionState::Provisioning(record) => match record.step {
                ProvisioningStep::UkiPublicationAttempted => {
                    LifecycleReadback::UkiPresent(boothop_core::PublishMetadata {
                        sha256: [0x22; 32],
                        size: 42,
                    })
                }
                ProvisioningStep::BootEntryCreateAttempted => {
                    if self.observe_absent == FailAt::Entry {
                        LifecycleReadback::BootEntryAbsent
                    } else {
                        LifecycleReadback::BootEntryPresent(record.owned_entry.identity.clone())
                    }
                }
                ProvisioningStep::BootOrderAppendAttempted => {
                    if self.observe_absent == FailAt::Order {
                        LifecycleReadback::BootOrder(
                            BootOrderValue::new(
                                7,
                                vec![boothop_core::BootId(7), boothop_core::BootId(8)],
                            )
                            .unwrap(),
                        )
                    } else {
                        LifecycleReadback::BootOrder(
                            BootOrderValue::new(
                                7,
                                vec![
                                    boothop_core::BootId(7),
                                    boothop_core::BootId(8),
                                    boothop_core::BootId(0x1234),
                                ],
                            )
                            .unwrap(),
                        )
                    }
                }
                _ => LifecycleReadback::UkiAbsent,
            },
            ArchProvisionState::Uninstalling(record) => match record.step {
                UninstallingStep::BootOrderRemovalAttempted => LifecycleReadback::BootOrder(
                    BootOrderValue::new(
                        7,
                        vec![
                            boothop_core::BootId(7),
                            boothop_core::BootId(8),
                            boothop_core::BootId(0x1234),
                        ],
                    )
                    .unwrap(),
                ),
                UninstallingStep::BootEntryRemovalAttempted => {
                    LifecycleReadback::BootEntryPresent(record.owned_entry.identity.clone())
                }
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
    let journal_events = fs.0.borrow().events.clone();
    for (stage, attempted, verified) in [
        (
            "uki",
            "journal:provisioning:uki_publication_attempted",
            "journal:provisioning:uki_published",
        ),
        (
            "entry",
            "journal:provisioning:boot_entry_create_attempted",
            "journal:provisioning:boot_entry_read_back_verified",
        ),
        (
            "order",
            "journal:provisioning:boot_order_append_attempted",
            "journal:provisioning:boot_order_read_back_verified",
        ),
    ] {
        let mutation = journal_events
            .iter()
            .position(|event| event == &format!("external-mutate-{stage}"))
            .unwrap();
        let readback = journal_events
            .iter()
            .position(|event| event == &format!("external-readback-{stage}"))
            .unwrap();
        let durable_attempt = journal_events[..mutation]
            .iter()
            .rposition(|event| event.starts_with("journal:"))
            .unwrap();
        assert_eq!(journal_events[durable_attempt], attempted);
        let durable_verified = journal_events[readback + 1..]
            .iter()
            .position(|event| event.starts_with("journal:"))
            .map(|index| readback + 1 + index)
            .unwrap();
        assert_eq!(journal_events[durable_verified], verified);
    }
    let tombstone = uninstall(&mut store, &mut backend, "uninstall-1".into()).unwrap();
    assert!(matches!(tombstone, ArchProvisionState::Uninstalled(_)));
    assert_eq!(
        backend.mutations,
        ["uki", "entry", "order", "order", "entry", "uki"]
    );
    let all_events = fs.0.borrow().events.clone();
    let ready = all_events
        .iter()
        .rposition(|event| event == "journal:ready")
        .unwrap();
    let uninstall_trace: Vec<_> = all_events[ready + 1..]
        .iter()
        .filter(|event| event.starts_with("journal:") || event.starts_with("external-"))
        .map(String::as_str)
        .collect();
    let uninstall_events = [
        "journal:uninstalling:started",
        "external-read-order",
        "journal:uninstalling:boot_order_removal_attempted",
        "external-mutate-order",
        "external-readback-order",
        "journal:uninstalling:boot_order_removed",
        "journal:uninstalling:boot_order_removal_read_back_verified",
        "external-read-entry",
        "journal:uninstalling:boot_entry_removal_attempted",
        "external-mutate-entry",
        "external-readback-entry",
        "journal:uninstalling:boot_entry_removed",
        "journal:uninstalling:boot_entry_removal_read_back_verified",
        "external-read-uki",
        "journal:uninstalling:uki_removal_attempted",
        "external-mutate-uki",
        "external-readback-uki",
        "journal:uninstalling:uki_removed",
        "journal:uninstalled",
    ];
    assert_eq!(uninstall_trace, uninstall_events);
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
fn every_attempted_checkpoint_recovers_read_only_and_keeps_checkpoint() {
    for (fail, expected_step, expected_residual) in [
        (
            FailAt::Uki,
            ProvisioningStep::UkiPublicationAttempted,
            Residual::UkiMayRemain,
        ),
        (
            FailAt::Entry,
            ProvisioningStep::BootEntryCreateAttempted,
            Residual::BootEntryMayExist,
        ),
        (
            FailAt::Order,
            ProvisioningStep::BootOrderAppendAttempted,
            Residual::BootOrderMayContainEntry,
        ),
    ] {
        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        backend.fail = fail;
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        assert!(provision(&mut store, &mut backend, pending_intent()).is_err());
        let before = store.load().unwrap();
        let mutations = backend.mutations.len();
        let after = recover(&mut store, &mut backend).unwrap();
        assert_eq!(backend.mutations.len(), mutations);
        assert_eq!(backend.observations, 1);
        assert!(matches!(before, ArchProvisionState::Provisioning(ref r)
            if r.step == expected_step && r.residual == vec![expected_residual]));
        assert!(matches!(after, ArchProvisionState::Provisioning(ref r)
            if r.step == expected_step && r.residual == vec![expected_residual]));
    }

    for (fail, expected_step, expected_residual) in [
        (
            FailAt::Order,
            UninstallingStep::BootOrderRemovalAttempted,
            Residual::BootOrderMayContainEntry,
        ),
        (
            FailAt::Entry,
            UninstallingStep::BootEntryRemovalAttempted,
            Residual::BootEntryMayExist,
        ),
        (
            FailAt::Uki,
            UninstallingStep::UkiRemovalAttempted,
            Residual::UkiMayRemain,
        ),
    ] {
        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        provision(&mut store, &mut backend, pending_intent()).unwrap();
        backend.fail = fail;
        assert!(uninstall(&mut store, &mut backend, "uninstall-1".into()).is_err());
        let before = store.load().unwrap();
        let mutations = backend.mutations.len();
        let after = recover(&mut store, &mut backend).unwrap();
        assert_eq!(backend.mutations.len(), mutations);
        assert_eq!(backend.observations, 1);
        assert!(matches!(before, ArchProvisionState::Uninstalling(ref r)
            if r.step == expected_step && r.residual == vec![expected_residual]));
        assert!(matches!(after, ArchProvisionState::Uninstalling(ref r)
            if r.step == expected_step && r.residual == vec![expected_residual]));
    }
}

#[test]
fn absent_attempt_postconditions_are_retained_as_residual_evidence() {
    for (stage, step, residual) in [
        (
            FailAt::Entry,
            ProvisioningStep::BootEntryCreateAttempted,
            Residual::BootEntryMayExist,
        ),
        (
            FailAt::Order,
            ProvisioningStep::BootOrderAppendAttempted,
            Residual::BootOrderMayContainEntry,
        ),
    ] {
        let fs = support::FakeFs::installed();
        let ArchProvisionState::Ready(entry) = support::ready_state() else {
            unreachable!()
        };
        let state = ArchProvisionState::Provisioning(boothop_core::ProvisioningRecord {
            operation_id: "provision-1".into(),
            operation_version: 1,
            owned_entry: entry,
            step,
            residual: vec![],
        });
        fs.insert(
            "/var/lib/boothop/arch-provision.json",
            0o100600,
            boothop_core::encode_arch_provision_state(&state).unwrap(),
        );
        let mut backend = FakeBackend::new(fs.clone());
        backend.observe_absent = stage;
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        let recovered = recover(&mut store, &mut backend).unwrap();
        assert!(matches!(recovered, ArchProvisionState::Provisioning(ref r)
            if r.step == step && r.residual == vec![residual]));
        assert_eq!(backend.mutations, Vec::<&'static str>::new());
    }
}

#[test]
fn boot_entry_and_order_recovery_requires_exact_journaled_uki_metadata() {
    for fail in [FailAt::Entry, FailAt::Order] {
        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        backend.fail = fail;
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        assert!(provision(&mut store, &mut backend, pending_intent()).is_err());
        backend.uki_mismatch = true;
        let recovered = recover(&mut store, &mut backend).unwrap();
        assert!(
            matches!(recovered, ArchProvisionState::Provisioning(ref record)
            if record.residual.contains(&Residual::UkiMayRemain))
        );
    }
}

#[test]
fn post_mutation_readback_mismatch_retains_stage_residual_and_identity() {
    for mismatch in [FailAt::Uki, FailAt::Entry, FailAt::Order] {
        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        backend.mismatch = mismatch;
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        assert_eq!(
            provision(&mut store, &mut backend, pending_intent()),
            Err(Error::ReadbackFailed)
        );
        let state = store.load().unwrap();
        assert!(matches!(state, ArchProvisionState::Provisioning(ref record)
            if !record.residual.is_empty()
                && matches!(record.step,
                    ProvisioningStep::UkiPublicationAttempted
                    | ProvisioningStep::BootEntryCreateAttempted
                    | ProvisioningStep::BootOrderAppendAttempted)));
    }
}

#[test]
fn uninstall_post_mutation_readback_mismatch_retains_cleanup_attempt() {
    for mismatch in [FailAt::Order, FailAt::Entry, FailAt::Uki] {
        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        provision(&mut store, &mut backend, pending_intent()).unwrap();
        backend.mismatch = mismatch;
        assert_eq!(
            uninstall(&mut store, &mut backend, "uninstall-1".into()),
            Err(Error::ReadbackFailed)
        );
        assert!(
            matches!(store.load().unwrap(), ArchProvisionState::Uninstalling(ref record)
            if !record.residual.is_empty()
                && matches!(record.step,
                    UninstallingStep::BootOrderRemovalAttempted
                    | UninstallingStep::BootEntryRemovalAttempted
                    | UninstallingStep::UkiRemovalAttempted))
        );
    }
}

#[test]
fn provision_prepare_errors_and_mismatches_retain_the_prior_checkpoint() {
    for (stage, expected_step, residual) in [
        (
            FailAt::Uki,
            ProvisioningStep::UkiPublicationPending,
            Residual::UkiMayRemain,
        ),
        (
            FailAt::Entry,
            ProvisioningStep::UkiPublished,
            Residual::BootEntryMayExist,
        ),
        (
            FailAt::Order,
            ProvisioningStep::BootEntryReadBackVerified,
            Residual::BootOrderMayContainEntry,
        ),
    ] {
        for mismatch in [false, true] {
            let fs = support::FakeFs::installed();
            let mut backend = FakeBackend::new(fs.clone());
            if mismatch {
                backend.prepare_mismatch = stage;
            } else {
                backend.prepare_fail = stage;
            }
            let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
            assert_eq!(
                provision(&mut store, &mut backend, pending_intent()),
                Err(if mismatch {
                    Error::ReadbackFailed
                } else {
                    Error::Busy
                })
            );
            assert!(
                matches!(store.load().unwrap(), ArchProvisionState::Provisioning(ref record)
                if record.step == expected_step && record.residual == vec![residual])
            );
            assert_eq!(
                backend.mutations,
                match stage {
                    FailAt::Uki => Vec::<&'static str>::new(),
                    FailAt::Entry => vec!["uki"],
                    FailAt::Order => vec!["uki", "entry"],
                    FailAt::None => unreachable!(),
                }
            );
        }
    }
}

#[test]
fn uninstall_prepare_errors_and_mismatches_retain_the_prior_checkpoint() {
    for (stage, expected_step, residual) in [
        (
            FailAt::Order,
            UninstallingStep::Started,
            Residual::BootOrderMayContainEntry,
        ),
        (
            FailAt::Entry,
            UninstallingStep::BootOrderRemovalReadBackVerified,
            Residual::BootEntryMayExist,
        ),
        (
            FailAt::Uki,
            UninstallingStep::BootEntryRemovalReadBackVerified,
            Residual::UkiMayRemain,
        ),
    ] {
        for mismatch in [false, true] {
            let fs = support::FakeFs::installed();
            let mut backend = FakeBackend::new(fs.clone());
            let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
            provision(&mut store, &mut backend, pending_intent()).unwrap();
            if mismatch {
                backend.prepare_mismatch = stage;
            } else {
                backend.prepare_fail = stage;
            }
            assert_eq!(
                uninstall(&mut store, &mut backend, "uninstall-1".into()),
                Err(if mismatch {
                    Error::ReadbackFailed
                } else {
                    Error::Busy
                })
            );
            assert!(
                matches!(store.load().unwrap(), ArchProvisionState::Uninstalling(ref record)
                if record.step == expected_step && record.residual == vec![residual])
            );
        }
    }
}

#[test]
fn boot_order_proofs_reject_reordering_omission_duplicates_and_foreign_ids() {
    for shape in [
        OrderShape::Reordered,
        OrderShape::PrefixOmitted,
        OrderShape::DuplicateOwned,
        OrderShape::ForeignId,
        OrderShape::WrongAttributes,
    ] {
        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        backend.mismatch = FailAt::Order;
        backend.order_shape = Some(shape);
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        assert_eq!(
            provision(&mut store, &mut backend, pending_intent()),
            Err(Error::ReadbackFailed)
        );
        assert!(
            matches!(store.load().unwrap(), ArchProvisionState::Provisioning(ref record)
            if record.step == ProvisioningStep::BootOrderAppendAttempted
                && record.residual == vec![Residual::BootOrderMayContainEntry])
        );

        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        provision(&mut store, &mut backend, pending_intent()).unwrap();
        backend.mismatch = FailAt::Order;
        backend.order_shape = Some(shape);
        assert_eq!(
            uninstall(&mut store, &mut backend, "uninstall-1".into()),
            Err(Error::ReadbackFailed)
        );
        assert!(
            matches!(store.load().unwrap(), ArchProvisionState::Uninstalling(ref record)
            if record.step == UninstallingStep::BootOrderRemovalAttempted
                && record.residual == vec![Residual::BootOrderMayContainEntry])
        );
    }
}

#[test]
fn recovery_observes_nonterminal_verified_checkpoints_without_advancing() {
    for (step, residual) in [
        (
            ProvisioningStep::BootEntryReadBackVerified,
            Residual::BootEntryMayExist,
        ),
        (
            ProvisioningStep::BootOrderAppended,
            Residual::BootOrderMayContainEntry,
        ),
    ] {
        let fs = support::FakeFs::installed();
        let ArchProvisionState::Ready(mut entry) = support::ready_state() else {
            unreachable!()
        };
        entry.publish = Some(boothop_core::PublishMetadata {
            sha256: [0x22; 32],
            size: 42,
        });
        let state = ArchProvisionState::Provisioning(boothop_core::ProvisioningRecord {
            operation_id: "provision-1".into(),
            operation_version: 1,
            owned_entry: entry,
            step,
            residual: vec![],
        });
        fs.insert(
            "/var/lib/boothop/arch-provision.json",
            0o100600,
            boothop_core::encode_arch_provision_state(&state).unwrap(),
        );
        let mut backend = FakeBackend::new(fs.clone());
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        let recovered = recover(&mut store, &mut backend).unwrap();
        assert!(
            matches!(recovered, ArchProvisionState::Provisioning(ref record)
            if record.step == step && record.residual == vec![residual])
        );
        assert!(backend.mutations.is_empty());
    }
}

#[test]
fn recovery_observation_errors_retain_resource_specific_residuals() {
    let fs = support::FakeFs::installed();
    let ArchProvisionState::Ready(mut entry) = support::ready_state() else {
        unreachable!()
    };
    entry.publish = Some(boothop_core::PublishMetadata {
        sha256: [0x22; 32],
        size: 42,
    });
    let state = ArchProvisionState::Provisioning(boothop_core::ProvisioningRecord {
        operation_id: "provision-1".into(),
        operation_version: 1,
        owned_entry: entry,
        step: ProvisioningStep::BootEntryReadBackVerified,
        residual: vec![],
    });
    fs.insert(
        "/var/lib/boothop/arch-provision.json",
        0o100600,
        boothop_core::encode_arch_provision_state(&state).unwrap(),
    );
    let mut backend = FakeBackend::new(fs.clone());
    backend.observe_error = true;
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let recovered = recover(&mut store, &mut backend).unwrap();
    assert!(
        matches!(recovered, ArchProvisionState::Provisioning(ref record)
        if record.step == ProvisioningStep::BootEntryReadBackVerified
            && record.residual == vec![Residual::BootEntryMayExist])
    );
    assert!(backend.mutations.is_empty());
}

#[test]
fn uninstall_boot_order_removed_recovery_requires_exact_durable_full_order_evidence() {
    for step in [
        UninstallingStep::BootOrderRemoved,
        UninstallingStep::BootOrderRemovalReadBackVerified,
    ] {
        let fs = support::FakeFs::installed();
        let ArchProvisionState::Ready(entry) = support::ready_state() else {
            unreachable!()
        };
        let state = ArchProvisionState::Uninstalling(boothop_core::UninstallingRecord {
            operation_id: "uninstall-1".into(),
            operation_version: 1,
            owned_entry: entry,
            step,
            residual: vec![],
        });
        fs.insert(
            "/var/lib/boothop/arch-provision.json",
            0o100600,
            boothop_core::encode_arch_provision_state(&state).unwrap(),
        );
        let mut backend = FakeBackend::new(fs.clone());
        // The owned ID is absent, but an external writer also reordered the other entries.
        // Since the journal does not durably contain the full post-order proof, this is not
        // enough evidence to clear the recovery residual.
        backend.observed_order_override = Some(
            BootOrderValue::new(7, vec![boothop_core::BootId(8), boothop_core::BootId(7)]).unwrap(),
        );
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        let recovered = recover(&mut store, &mut backend).unwrap();
        assert!(
            matches!(recovered, ArchProvisionState::Uninstalling(ref record)
            if record.step == step
                && record.residual.contains(&Residual::BootOrderMayContainEntry))
        );
        assert!(backend.mutations.is_empty());
    }
}

#[test]
fn uki_removed_recovery_accepts_expected_absence_but_rejects_unknown_presence() {
    for unknown_presence in [false, true] {
        let fs = support::FakeFs::installed();
        let ArchProvisionState::Ready(entry) = support::ready_state() else {
            unreachable!()
        };
        let state = ArchProvisionState::Uninstalling(boothop_core::UninstallingRecord {
            operation_id: "uninstall-1".into(),
            operation_version: 1,
            owned_entry: entry,
            step: UninstallingStep::UkiRemoved,
            residual: vec![],
        });
        fs.insert(
            "/var/lib/boothop/arch-provision.json",
            0o100600,
            boothop_core::encode_arch_provision_state(&state).unwrap(),
        );
        let mut backend = FakeBackend::new(fs.clone());
        backend.observe_uki_absent = !unknown_presence;
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        let recovered = recover(&mut store, &mut backend).unwrap();
        assert!(
            matches!(recovered, ArchProvisionState::Uninstalling(ref record)
            if record.step == UninstallingStep::UkiRemoved
                && record.residual.contains(&Residual::UkiMayRemain) == unknown_presence)
        );
        assert!(backend.mutations.is_empty());
        if unknown_presence {
            assert!(store.complete_uninstall(&recovered).is_err());
        } else {
            store.complete_uninstall(&recovered).unwrap();
            assert!(matches!(
                store.load().unwrap(),
                ArchProvisionState::Uninstalled(_)
            ));
        }
    }
}

#[test]
fn failed_verified_checkpoint_save_preserves_attempt_evidence_without_retry() {
    let fs = support::FakeFs::installed();
    fs.0.borrow_mut().fail_after = Some(("dir_fsync", 2, 5));
    let mut backend = FakeBackend::new(fs.clone());
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    assert!(provision(&mut store, &mut backend, pending_intent()).is_err());
    assert_eq!(backend.mutations, ["uki"]);
    assert!(
        matches!(store.load().unwrap(), ArchProvisionState::Provisioning(ref record)
        if record.step == ProvisioningStep::UkiPublicationAttempted
            || record.step == ProvisioningStep::UkiPublished)
    );
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
        fn observe_uki_ownership(
            &mut self,
            e: &boothop_core::OwnedArchEntry,
        ) -> Result<LifecycleReadback, Error> {
            self.0.observe_uki_ownership(e)
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
