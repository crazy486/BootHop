#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod support;

use boothop_core::{
    ArchProvisionState, BootOrderRemovalProof, BootOrderSnapshot, Error, ProvisioningStep,
    Residual, UninstallingStep,
};
use boothop_platform::linux::arch_provision_store::ArchProvisionStore;
use boothop_platform::linux::boot_order::BootOrderValue;
use boothop_platform::linux::coordinator::{
    BootEntryCreatePermit, BootEntryRemovePermit, BootOrderAppendPermit, BootOrderRemovePermit,
    LifecycleBackend, LifecycleFailure, LifecycleProofBinding, LifecycleReadback, ProvisionIntent,
    UkiPublishPermit, UkiRemovePermit, provision, recover, uninstall,
};
use boothop_platform::linux::uki::{
    PreparedUkiArtifact, UkiBuildBackend, UkiBuildError, UkiBuildError as BuildError, UkiBuildPlan,
    UkiFinalPathState, UkiPublishFs, prepare_uki_artifact, publish_prepared_uki,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailAt {
    None,
    Uki,
    Entry,
    Order,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UkiPublisherFailAt {
    Stage,
    Rename,
    Readback,
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
    prepare_error: Option<Error>,
    prepare_order_calls: usize,
    prepare_mismatch: FailAt,
    preexisting_uki: bool,
    publish_different_artifact: bool,
    foreign_uki_appears_before_publish: bool,
    uki_publisher_fail_at: Option<UkiPublisherFailAt>,
    uki_publisher_calls: Vec<&'static str>,
    uki_stage_remains: bool,
    uki_final_exists: bool,
    last_uki_permit_attempted: Option<ArchProvisionState>,
    observe_absent: FailAt,
    observe_error: bool,
    uki_mismatch: bool,
    observe_uki_absent: bool,
    observed_order_override: Option<BootOrderValue>,
    uninstalling: bool,
    order_shape: Option<OrderShape>,
    mutations: Vec<&'static str>,
    permit_evidence: Vec<(
        &'static str,
        String,
        u64,
        ArchProvisionState,
        boothop_core::OwnedArchEntry,
        LifecycleProofBinding,
        LifecycleProofBinding,
    )>,
    events: Vec<&'static str>,
    observations: usize,
    attempt_commit_failure: Option<(&'static str, i32)>,
    stale_journal: Option<ArchProvisionState>,
}

struct MutationEvidence {
    entry: boothop_core::OwnedArchEntry,
    operation_id: String,
    operation_version: u64,
    attempted_state: ArchProvisionState,
    expected_evidence: LifecycleProofBinding,
    precondition_evidence: LifecycleProofBinding,
}

fn mutation_evidence(
    entry: &boothop_core::OwnedArchEntry,
    operation_id: &str,
    operation_version: u64,
    attempted_state: &ArchProvisionState,
    expected_evidence: &LifecycleProofBinding,
    precondition_evidence: &LifecycleProofBinding,
) -> MutationEvidence {
    MutationEvidence {
        entry: entry.clone(),
        operation_id: operation_id.to_owned(),
        operation_version,
        attempted_state: attempted_state.clone(),
        expected_evidence: expected_evidence.clone(),
        precondition_evidence: precondition_evidence.clone(),
    }
}

impl FakeBackend {
    fn new(fs: support::FakeFs) -> Self {
        Self {
            fs,
            fail: FailAt::None,
            mismatch: FailAt::None,
            prepare_fail: FailAt::None,
            prepare_error: None,
            prepare_order_calls: 0,
            prepare_mismatch: FailAt::None,
            preexisting_uki: false,
            publish_different_artifact: false,
            foreign_uki_appears_before_publish: false,
            uki_publisher_fail_at: None,
            uki_publisher_calls: Vec::new(),
            uki_stage_remains: false,
            uki_final_exists: false,
            last_uki_permit_attempted: None,
            observe_absent: FailAt::None,
            observe_error: false,
            uki_mismatch: false,
            observe_uki_absent: false,
            observed_order_override: None,
            uninstalling: false,
            order_shape: None,
            mutations: Vec::new(),
            permit_evidence: Vec::new(),
            events: Vec::new(),
            observations: 0,
            attempt_commit_failure: None,
            stale_journal: None,
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
        evidence: MutationEvidence,
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
        self.permit_evidence.push((
            stage,
            evidence.operation_id.clone(),
            evidence.operation_version,
            evidence.attempted_state.clone(),
            evidence.entry.clone(),
            evidence.expected_evidence.clone(),
            evidence.precondition_evidence.clone(),
        ));
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
                    let mut identity = evidence.entry.identity.clone();
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
            "uki" => LifecycleReadback::UkiPresent(evidence.entry.publish.clone().unwrap()),
            "entry" => LifecycleReadback::BootEntryPresent(evidence.entry.identity.clone()),
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

struct CoordinatorUkiBuilder(&'static [u8]);
impl UkiBuildBackend for CoordinatorUkiBuilder {
    fn build(&mut self, _: &UkiBuildPlan) -> Result<Vec<u8>, UkiBuildError> {
        Ok(self.0.to_vec())
    }
    fn validate(&mut self, _: &[u8], _: &UkiBuildPlan) -> Result<(), UkiBuildError> {
        Ok(())
    }
    fn sign_if_required(&mut self, _: &mut Vec<u8>, _: &UkiBuildPlan) -> Result<(), UkiBuildError> {
        Ok(())
    }
}

fn prepared_test_uki() -> PreparedUkiArtifact {
    prepared_test_uki_bytes(b"coordinator fake UKI")
}

fn prepared_test_uki_bytes(bytes: &'static [u8]) -> PreparedUkiArtifact {
    let plan = UkiBuildPlan {
        kernel_flavor: "linux".into(),
        kernel_image: "/kernel".into(),
        initramfs_image: "/initramfs".into(),
        config_path: "/config".into(),
        preset_path: "/preset".into(),
        final_uki_path: "EFI/BootHop/arch.efi".into(),
        staged_uki_path: "EFI/BootHop/arch.efi.staging".into(),
        command_line_source: boothop_platform::linux::uki::CmdlineSource::Preset,
        command_line: "root=UUID=test".into(),
        includes_microcode: false,
        secure_boot: boothop_platform::linux::uki::SecureBootPlan {
            signing_required: false,
            signer_already_configured: false,
        },
        validation: boothop_platform::linux::uki::UkiValidation {
            require_efi_application: true,
            require_kernel_section: true,
            require_initrd_section: true,
            require_cmdline_section: true,
            verify_after_signing: false,
        },
        inputs: Vec::new(),
    };
    prepare_uki_artifact(&plan, &mut CoordinatorUkiBuilder(bytes)).unwrap()
}

fn test_publish_metadata() -> boothop_core::PublishMetadata {
    prepared_test_uki().metadata().clone()
}

#[derive(Default)]
struct FakeUkiPublisher {
    staged: Option<Vec<u8>>,
    final_bytes: Option<Vec<u8>>,
    calls: Vec<&'static str>,
    fail_at: Option<UkiPublisherFailAt>,
    final_reads: usize,
}

impl UkiPublishFs for FakeUkiPublisher {
    fn final_path_state(&mut self, _: &str) -> Result<UkiFinalPathState, BuildError> {
        self.calls.push("observe");
        self.final_reads += 1;
        if self.fail_at == Some(UkiPublisherFailAt::Readback) && self.final_reads == 3 {
            return Err(BuildError::Publish("final readback failed".into()));
        }
        Ok(match &self.final_bytes {
            Some(bytes) => UkiFinalPathState::Regular(boothop_core::PublishMetadata {
                sha256: Sha256::digest(bytes).into(),
                size: bytes.len() as u64,
            }),
            None => UkiFinalPathState::Absent,
        })
    }
    fn write_stage(
        &mut self,
        _: &str,
        bytes: &[u8],
        permit: &UkiPublishPermit<'_>,
    ) -> Result<(), BuildError> {
        self.calls.push("stage");
        assert!(
            matches!(permit.attempted_state(), ArchProvisionState::Provisioning(record)
            if record.step == ProvisioningStep::UkiPublicationAttempted)
        );
        self.staged = Some(if self.fail_at == Some(UkiPublisherFailAt::Stage) {
            bytes[..bytes.len().min(5)].to_vec()
        } else {
            bytes.to_vec()
        });
        if self.fail_at == Some(UkiPublisherFailAt::Stage) {
            return Err(BuildError::Publish("stage write failed".into()));
        }
        Ok(())
    }
    fn rename_stage_over_final(
        &mut self,
        _: &str,
        _: &str,
        permit: &UkiPublishPermit<'_>,
    ) -> Result<(), BuildError> {
        self.calls.push("rename");
        assert!(
            matches!(permit.attempted_state(), ArchProvisionState::Provisioning(record)
            if record.step == ProvisioningStep::UkiPublicationAttempted)
        );
        if self.fail_at == Some(UkiPublisherFailAt::Rename) {
            return Err(BuildError::Publish("atomic rename failed".into()));
        }
        self.final_bytes = self.staged.take();
        Ok(())
    }
}

impl LifecycleBackend for FakeBackend {
    fn prepare_uki_publication(
        &mut self,
        _entry: &boothop_core::OwnedArchEntry,
    ) -> Result<(PreparedUkiArtifact, LifecycleReadback), Error> {
        self.assert_lock();
        if self.prepare_fail == FailAt::Uki {
            return Err(Error::Busy);
        }
        let prepared = prepared_test_uki();
        self.events.push("build-uki");
        self.trace("prepare-uki-build");
        self.trace("external-read-uki");
        self.events.push("read-uki");
        if self.prepare_mismatch == FailAt::Uki {
            return Ok((
                prepared,
                LifecycleReadback::UkiPresent(boothop_core::PublishMetadata {
                    sha256: [0x33; 32],
                    size: 43,
                }),
            ));
        }
        if self.preexisting_uki {
            return Ok((
                prepared,
                LifecycleReadback::UkiPresent(test_publish_metadata()),
            ));
        }
        if let Some(state) = self.stale_journal.take() {
            self.fs.insert(
                "/var/lib/boothop/arch-provision.json",
                0o100600,
                boothop_core::encode_arch_provision_state(&state).unwrap(),
            );
        }
        if let Some(failure) = self.attempt_commit_failure {
            self.fs.0.borrow_mut().fail = Some(failure);
        }
        Ok((prepared, LifecycleReadback::UkiAbsent))
    }
    fn publish_uki(
        &mut self,
        artifact: PreparedUkiArtifact,
        permit: UkiPublishPermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.last_uki_permit_attempted = Some(permit.attempted_state().clone());
        let evidence = mutation_evidence(
            permit.owned_entry(),
            permit.operation_id(),
            permit.operation_version(),
            permit.attempted_state(),
            permit.expected_evidence(),
            permit.precondition_evidence(),
        );
        if self.fail == FailAt::Uki {
            return self.mutation("uki", Residual::UkiMayRemain, evidence);
        }
        let prepared_for_publish = if self.publish_different_artifact {
            prepared_test_uki_bytes(b"different artifact B")
        } else {
            artifact
        };
        let mut publisher = FakeUkiPublisher {
            final_bytes: self
                .foreign_uki_appears_before_publish
                .then(|| b"foreign file appeared after prepare".to_vec()),
            fail_at: self.uki_publisher_fail_at,
            ..Default::default()
        };
        let publish_result = publish_prepared_uki(prepared_for_publish, permit, &mut publisher);
        self.uki_publisher_calls = publisher.calls.clone();
        self.uki_stage_remains = publisher.staged.is_some();
        self.uki_final_exists = publisher.final_bytes.is_some();
        let metadata = publish_result.map_err(|_| {
            LifecycleFailure::uncertain(Error::ReadbackFailed, Residual::UkiMayRemain)
        })?;
        assert_eq!(
            self.uki_publisher_calls,
            ["observe", "stage", "observe", "rename", "observe"]
        );
        assert!(!self.uki_stage_remains);
        assert!(self.uki_final_exists);
        assert!(publisher.final_bytes.as_deref().is_some_and(|bytes| {
            let actual: [u8; 32] = Sha256::digest(bytes).into();
            actual == metadata.sha256 && bytes.len() as u64 == metadata.size
        }));
        let result = self.mutation("uki", Residual::UkiMayRemain, evidence)?;
        if self.mismatch != FailAt::Uki {
            assert_eq!(result, LifecycleReadback::UkiPresent(metadata));
        }
        Ok(result)
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
        permit: BootEntryCreatePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation(
            "entry",
            Residual::BootEntryMayExist,
            mutation_evidence(
                permit.owned_entry(),
                permit.operation_id(),
                permit.operation_version(),
                permit.attempted_state(),
                permit.expected_evidence(),
                permit.precondition_evidence(),
            ),
        )
    }
    fn prepare_boot_order_append(
        &mut self,
        entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        self.prepare_order_calls += 1;
        if self.prepare_fail == FailAt::Order {
            return Err(self.prepare_error.clone().unwrap_or(Error::Busy));
        }
        self.trace("external-read-order");
        self.events.push("read-order");
        if self.prepare_mismatch == FailAt::Order {
            return Ok(LifecycleReadback::BootEntryAndOrder {
                identity: entry.identity.clone(),
                order: BootOrderValue::new(
                    7,
                    vec![
                        boothop_core::BootId(7),
                        boothop_core::BootId(8),
                        entry.boot_id,
                    ],
                )
                .unwrap(),
            });
        }
        Ok(LifecycleReadback::BootEntryAndOrder {
            identity: entry.identity.clone(),
            order: BootOrderValue::new(7, vec![boothop_core::BootId(7), boothop_core::BootId(8)])
                .unwrap(),
        })
    }
    fn append_boot_order(
        &mut self,
        permit: BootOrderAppendPermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        self.mutation(
            "order",
            Residual::BootOrderMayContainEntry,
            mutation_evidence(
                permit.owned_entry(),
                permit.operation_id(),
                permit.operation_version(),
                permit.attempted_state(),
                permit.expected_evidence(),
                permit.precondition_evidence(),
            ),
        )
    }
    fn prepare_boot_order_remove(
        &mut self,
        entry: &boothop_core::OwnedArchEntry,
    ) -> Result<LifecycleReadback, Error> {
        self.assert_lock();
        self.uninstalling = true;
        self.prepare_order_calls += 1;
        if self.prepare_fail == FailAt::Order {
            return Err(self.prepare_error.clone().unwrap_or(Error::Busy));
        }
        self.trace("external-read-order");
        self.events.push("read-order");
        if self.prepare_mismatch == FailAt::Order {
            return Ok(LifecycleReadback::BootEntryAndOrder {
                identity: entry.identity.clone(),
                order: BootOrderValue::new(
                    7,
                    vec![boothop_core::BootId(7), boothop_core::BootId(8)],
                )
                .unwrap(),
            });
        }
        Ok(LifecycleReadback::BootEntryAndOrder {
            identity: entry.identity.clone(),
            order: BootOrderValue::new(
                7,
                vec![
                    boothop_core::BootId(7),
                    boothop_core::BootId(8),
                    boothop_core::BootId(0x1234),
                ],
            )
            .unwrap(),
        })
    }
    fn remove_boot_order(
        &mut self,
        permit: BootOrderRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        let observed = self.mutation(
            "order",
            Residual::BootOrderMayContainEntry,
            mutation_evidence(
                permit.owned_entry(),
                permit.operation_id(),
                permit.operation_version(),
                permit.attempted_state(),
                permit.expected_evidence(),
                permit.precondition_evidence(),
            ),
        )?;
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
        permit: BootEntryRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        let entry = permit.owned_entry().clone();
        self.mutation(
            "entry",
            Residual::BootEntryMayExist,
            mutation_evidence(
                &entry,
                permit.operation_id(),
                permit.operation_version(),
                permit.attempted_state(),
                permit.expected_evidence(),
                permit.precondition_evidence(),
            ),
        )
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
        permit: UkiRemovePermit<'_>,
    ) -> Result<LifecycleReadback, LifecycleFailure> {
        let entry = permit.owned_entry().clone();
        self.mutation(
            "uki",
            Residual::UkiMayRemain,
            mutation_evidence(
                &entry,
                permit.operation_id(),
                permit.operation_version(),
                permit.attempted_state(),
                permit.expected_evidence(),
                permit.precondition_evidence(),
            ),
        )
        .map(|_| {
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
                    LifecycleReadback::UkiPresent(test_publish_metadata())
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
                    LifecycleReadback::UkiPresent(test_publish_metadata())
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

fn published_entry() -> boothop_core::OwnedArchEntry {
    let ArchProvisionState::Ready(mut entry) = support::ready_state() else {
        unreachable!()
    };
    entry.publish = Some(test_publish_metadata());
    entry
}

#[test]
fn full_provision_and_uninstall_hold_one_lock_and_reach_tombstone() {
    let fs = support::FakeFs::installed();
    let mut backend = FakeBackend::new(fs.clone());
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let ready = provision(&mut store, &mut backend, pending_intent()).unwrap();
    assert!(matches!(ready, ArchProvisionState::Ready(_)));
    assert_eq!(backend.mutations, ["uki", "entry", "order"]);
    assert_eq!(backend.permit_evidence.len(), 3);
    let expected_entry = published_entry();
    for (
        (stage, operation_id, version, attempted, permit_entry, expected, precondition),
        expected_step,
    ) in backend.permit_evidence.iter().zip([
        ProvisioningStep::UkiPublicationAttempted,
        ProvisioningStep::BootEntryCreateAttempted,
        ProvisioningStep::BootOrderAppendAttempted,
    ]) {
        assert_eq!(operation_id, "provision-1");
        assert_eq!(*version, 1);
        assert!(matches!(attempted, ArchProvisionState::Provisioning(record)
            if record.step == expected_step
                && record.operation_id == *operation_id
                && record.operation_version == *version
                && record.owned_entry == expected_entry));
        assert_eq!(permit_entry, &expected_entry);
        let (expected_binding, precondition_binding) = match expected_step {
            ProvisioningStep::UkiPublicationAttempted => (
                LifecycleProofBinding::Uki(expected_entry.publish.clone().unwrap()),
                LifecycleProofBinding::UkiAbsent,
            ),
            ProvisioningStep::BootEntryCreateAttempted => (
                LifecycleProofBinding::BootEntryPresent,
                LifecycleProofBinding::BootEntryAbsent,
            ),
            ProvisioningStep::BootOrderAppendAttempted => {
                let before =
                    BootOrderValue::new(7, vec![boothop_core::BootId(7), boothop_core::BootId(8)])
                        .unwrap();
                (
                    LifecycleProofBinding::BootEntryAndOrderBefore {
                        identity: expected_entry.identity.clone(),
                        order: before.clone(),
                    },
                    LifecycleProofBinding::BootEntryAndOrderBefore {
                        identity: expected_entry.identity.clone(),
                        order: before,
                    },
                )
            }
            _ => unreachable!(),
        };
        assert_eq!(expected, &expected_binding);
        assert_eq!(precondition, &precondition_binding);
        assert_eq!(
            stage,
            match expected_step {
                ProvisioningStep::UkiPublicationAttempted => &"uki",
                ProvisioningStep::BootEntryCreateAttempted => &"entry",
                ProvisioningStep::BootOrderAppendAttempted => &"order",
                _ => unreachable!(),
            }
        );
    }
    assert_eq!(
        backend.events,
        [
            "build-uki",
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
    let build = journal_events
        .iter()
        .position(|event| event == "prepare-uki-build")
        .unwrap();
    let attempted_uki = journal_events
        .iter()
        .position(|event| event == "journal:provisioning:uki_publication_attempted")
        .unwrap();
    assert!(
        build < attempted_uki,
        "UKI bytes must be prepared before Attempted is committed"
    );
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
    for (stage, operation_id, version, attempted, permit_entry, expected, precondition) in
        backend.permit_evidence.iter().skip(3)
    {
        assert_eq!(operation_id, "uninstall-1");
        assert_eq!(*version, 1);
        assert!(matches!(attempted, ArchProvisionState::Uninstalling(record)
            if record.operation_id == *operation_id
                && record.operation_version == *version
                && record.owned_entry == expected_entry));
        assert_eq!(permit_entry, &expected_entry);
        assert!(
            matches!((*stage, attempted),
            ("order", ArchProvisionState::Uninstalling(record))
                if record.step == UninstallingStep::BootOrderRemovalAttempted)
                || matches!((*stage, attempted),
            ("entry", ArchProvisionState::Uninstalling(record))
                if record.step == UninstallingStep::BootEntryRemovalAttempted)
                || matches!((*stage, attempted),
            ("uki", ArchProvisionState::Uninstalling(record))
                if record.step == UninstallingStep::UkiRemovalAttempted)
        );
        let ArchProvisionState::Uninstalling(record) = attempted else {
            unreachable!()
        };
        if record.step != UninstallingStep::BootOrderRemovalAttempted {
            assert!(record.boot_order_proof.as_ref().is_some_and(|proof| {
                proof.observed_after.as_ref()
                    == Some(&boothop_core::BootOrderSnapshot {
                        attributes: 7,
                        ids: vec![boothop_core::BootId(7), boothop_core::BootId(8)],
                    })
            }));
        }
        match record.step {
            UninstallingStep::BootOrderRemovalAttempted => {
                let before = BootOrderValue::new(
                    7,
                    vec![
                        boothop_core::BootId(7),
                        boothop_core::BootId(8),
                        expected_entry.boot_id,
                    ],
                )
                .unwrap();
                assert_eq!(
                    expected,
                    &LifecycleProofBinding::BootEntryAndOrderBefore {
                        identity: expected_entry.identity.clone(),
                        order: before.clone(),
                    }
                );
                assert_eq!(
                    precondition,
                    &LifecycleProofBinding::BootEntryAndOrderBefore {
                        identity: expected_entry.identity.clone(),
                        order: before,
                    }
                );
            }
            UninstallingStep::BootEntryRemovalAttempted => {
                assert_eq!(expected, &LifecycleProofBinding::BootEntryAbsent);
                assert_eq!(precondition, &LifecycleProofBinding::BootEntryPresent);
            }
            UninstallingStep::UkiRemovalAttempted => {
                assert_eq!(expected, &LifecycleProofBinding::UkiAbsent);
                assert_eq!(
                    precondition,
                    &LifecycleProofBinding::Uki(expected_entry.publish.clone().unwrap())
                );
            }
            _ => unreachable!(),
        }
    }
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
fn uki_stage_rename_and_readback_failures_never_retry_or_rollback() {
    for (failure, expected_calls, stage_remains, final_exists) in [
        (
            UkiPublisherFailAt::Stage,
            vec!["observe", "stage"],
            true,
            false,
        ),
        (
            UkiPublisherFailAt::Rename,
            vec!["observe", "stage", "observe", "rename"],
            true,
            false,
        ),
        (
            UkiPublisherFailAt::Readback,
            vec!["observe", "stage", "observe", "rename", "observe"],
            false,
            true,
        ),
    ] {
        let fs = support::FakeFs::installed();
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        let mut backend = FakeBackend::new(fs.clone());
        backend.uki_publisher_fail_at = Some(failure);
        assert!(provision(&mut store, &mut backend, pending_intent()).is_err());
        assert_eq!(backend.uki_publisher_calls, expected_calls);
        assert_eq!(backend.uki_stage_remains, stage_remains);
        assert_eq!(backend.uki_final_exists, final_exists);
        assert!(
            backend.mutations.is_empty(),
            "failure must not trigger a second publish call"
        );
        assert!(
            matches!(store.load().unwrap(), ArchProvisionState::Provisioning(ref record)
            if record.step == ProvisioningStep::UkiPublicationAttempted
                && record.residual == vec![Residual::UkiMayRemain])
        );
    }
}

#[test]
fn mismatched_artifact_after_attempt_is_rejected_before_stage_or_rename() {
    let fs = support::FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let mut backend = FakeBackend::new(fs);
    backend.publish_different_artifact = true;
    assert_ne!(
        prepared_test_uki_bytes(b"different artifact B").metadata(),
        prepared_test_uki().metadata()
    );
    assert!(provision(&mut store, &mut backend, pending_intent()).is_err());
    assert!(backend.uki_publisher_calls.is_empty());
    assert!(matches!(&backend.last_uki_permit_attempted,
        Some(ArchProvisionState::Provisioning(record))
            if record.step == ProvisioningStep::UkiPublicationAttempted
                && record.owned_entry.publish.as_ref() == Some(&test_publish_metadata())));
    assert!(backend.mutations.is_empty());
    assert!(
        matches!(store.load().unwrap(), ArchProvisionState::Provisioning(ref record)
        if record.step == ProvisioningStep::UkiPublicationAttempted
            && record.residual == vec![Residual::UkiMayRemain])
    );
    assert_eq!(
        provision(&mut store, &mut backend, pending_intent()),
        Err(Error::NotConfigured)
    );
    assert!(backend.uki_publisher_calls.is_empty());
}

#[test]
fn foreign_fixed_path_appearing_after_attempt_stops_before_stage_or_rename() {
    let fs = support::FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let mut backend = FakeBackend::new(fs);
    backend.foreign_uki_appears_before_publish = true;
    assert!(provision(&mut store, &mut backend, pending_intent()).is_err());
    assert_eq!(backend.uki_publisher_calls, ["observe"]);
    assert!(matches!(&backend.last_uki_permit_attempted,
        Some(ArchProvisionState::Provisioning(record))
            if record.step == ProvisioningStep::UkiPublicationAttempted
                && record.owned_entry.publish.as_ref() == Some(&test_publish_metadata())));
    assert!(backend.uki_final_exists);
    assert!(backend.mutations.is_empty());
    assert!(
        matches!(store.load().unwrap(), ArchProvisionState::Provisioning(ref record)
        if record.step == ProvisioningStep::UkiPublicationAttempted
            && record.residual == vec![Residual::UkiMayRemain])
    );
    assert_eq!(
        provision(&mut store, &mut backend, pending_intent()),
        Err(Error::NotConfigured)
    );
    assert_eq!(backend.uki_publisher_calls, ["observe"]);
}

#[test]
fn failed_or_uncertain_attempt_commit_never_grants_a_mutation_permit() {
    for (stage, attempted) in [("write", false), ("dir_fsync", true)] {
        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        backend.attempt_commit_failure = Some((stage, 5));
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();

        assert!(provision(&mut store, &mut backend, pending_intent()).is_err());
        assert!(backend.mutations.is_empty());
        assert!(backend.permit_evidence.is_empty());
        assert!(backend.uki_publisher_calls.is_empty());
        assert!(!backend.uki_stage_remains);
        assert!(!backend.uki_final_exists);
        assert!(
            matches!(store.load().unwrap(), ArchProvisionState::Provisioning(record)
            if if attempted {
                record.step == ProvisioningStep::UkiPublicationAttempted
            } else {
                record.step == ProvisioningStep::UkiPublicationPending
            })
        );
    }
}

#[test]
fn reopened_attempted_checkpoint_recovery_is_read_only_and_never_remints_permits() {
    let fs = support::FakeFs::installed();
    let mut backend = FakeBackend::new(fs.clone());
    backend.attempt_commit_failure = Some(("dir_fsync", 5));
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();

    assert!(provision(&mut store, &mut backend, pending_intent()).is_err());
    assert!(
        matches!(store.load().unwrap(), ArchProvisionState::Provisioning(record)
        if record.step == ProvisioningStep::UkiPublicationAttempted)
    );
    assert!(backend.mutations.is_empty());
    assert!(backend.permit_evidence.is_empty());
    assert!(backend.uki_publisher_calls.is_empty());
    drop(store);

    fs.0.borrow_mut().fail = None;
    let mut reopened = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let recovered = recover(&mut reopened, &mut backend).unwrap();

    assert!(matches!(recovered, ArchProvisionState::Provisioning(record)
        if record.step == ProvisioningStep::UkiPublicationAttempted
            && record.residual == vec![Residual::UkiMayRemain]));
    assert_eq!(backend.observations, 1);
    assert!(backend.mutations.is_empty());
    assert!(backend.permit_evidence.is_empty());
    assert!(backend.uki_publisher_calls.is_empty());
}

#[test]
fn stale_attempt_proof_is_rejected_before_a_mutation_permit_is_minted() {
    let fs = support::FakeFs::installed();
    let mut backend = FakeBackend::new(fs.clone());
    let intent = pending_intent();
    backend.stale_journal = Some(ArchProvisionState::Provisioning(
        boothop_core::ProvisioningRecord {
            operation_id: "stale-operation".into(),
            operation_version: 1,
            owned_entry: intent.owned_entry.clone(),
            step: ProvisioningStep::UkiPublicationPending,
            residual: vec![],
        },
    ));
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();

    assert_eq!(
        provision(&mut store, &mut backend, intent),
        Err(Error::NotConfigured)
    );
    assert!(backend.mutations.is_empty());
    assert!(backend.permit_evidence.is_empty());
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
            let expected_residuals = if stage == FailAt::Order && !mismatch {
                vec![
                    Residual::BootEntryMayExist,
                    Residual::BootOrderMayContainEntry,
                ]
            } else {
                vec![residual]
            };
            assert!(
                matches!(store.load().unwrap(), ArchProvisionState::Provisioning(ref record)
                if record.step == expected_step && record.residual == expected_residuals)
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
fn combined_order_preflight_errors_keep_resource_residuals_without_retry_or_mutation() {
    for error in [
        Error::Busy,
        Error::PlatformIo {
            operation: boothop_core::PlatformOperation::Read,
            raw_code: 5,
        },
        Error::TargetMissing,
        Error::IdentityMismatch,
    ] {
        let expected_residuals = if error == Error::IdentityMismatch {
            vec![Residual::BootEntryMayExist]
        } else {
            vec![
                Residual::BootEntryMayExist,
                Residual::BootOrderMayContainEntry,
            ]
        };
        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        backend.prepare_fail = FailAt::Order;
        backend.prepare_error = Some(error.clone());
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        assert_eq!(
            provision(&mut store, &mut backend, pending_intent()),
            Err(error.clone())
        );
        assert!(
            matches!(store.load().unwrap(), ArchProvisionState::Provisioning(ref record)
            if record.step == ProvisioningStep::BootEntryReadBackVerified
                && record.residual == expected_residuals)
        );
        assert_eq!(backend.mutations, ["uki", "entry"]);
        assert_eq!(backend.prepare_order_calls, 1);
        assert_eq!(
            provision(&mut store, &mut backend, pending_intent()),
            Err(Error::NotConfigured)
        );
        assert_eq!(backend.mutations, ["uki", "entry"]);
        assert_eq!(backend.prepare_order_calls, 1);

        let fs = support::FakeFs::installed();
        let mut backend = FakeBackend::new(fs.clone());
        let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
        provision(&mut store, &mut backend, pending_intent()).unwrap();
        let mutations_before = backend.mutations.clone();
        let order_calls_before = backend.prepare_order_calls;
        backend.prepare_fail = FailAt::Order;
        backend.prepare_error = Some(error.clone());
        assert_eq!(
            uninstall(
                &mut store,
                &mut backend,
                "uninstall-preflight-failure".into()
            ),
            Err(error.clone())
        );
        assert!(
            matches!(store.load().unwrap(), ArchProvisionState::Uninstalling(ref record)
            if record.step == UninstallingStep::Started
                && record.residual == expected_residuals)
        );
        assert_eq!(backend.mutations, mutations_before);
        assert_eq!(backend.prepare_order_calls, order_calls_before + 1);
        assert_eq!(
            uninstall(&mut store, &mut backend, "uninstall-preflight-retry".into()),
            Err(Error::NotConfigured)
        );
        assert_eq!(backend.mutations, mutations_before);
        assert_eq!(backend.prepare_order_calls, order_calls_before + 1);
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
            let expected_residuals = if stage == FailAt::Order && !mismatch {
                vec![
                    Residual::BootEntryMayExist,
                    Residual::BootOrderMayContainEntry,
                ]
            } else {
                vec![residual]
            };
            assert!(
                matches!(store.load().unwrap(), ArchProvisionState::Uninstalling(ref record)
                if record.step == expected_step && record.residual == expected_residuals)
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
        entry.publish = Some(test_publish_metadata());
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
    entry.publish = Some(test_publish_metadata());
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
        let boot_id = entry.boot_id;
        let state = ArchProvisionState::Uninstalling(boothop_core::UninstallingRecord {
            operation_id: "uninstall-1".into(),
            operation_version: 1,
            owned_entry: entry,
            step,
            residual: vec![],
            boot_order_proof: Some(BootOrderRemovalProof {
                operation_id: "uninstall-1".into(),
                operation_version: 1,
                boot_id,
                before: BootOrderSnapshot {
                    attributes: 7,
                    ids: vec![boothop_core::BootId(8), boot_id],
                },
                expected_after: BootOrderSnapshot {
                    attributes: 7,
                    ids: vec![boothop_core::BootId(8)],
                },
                observed_after: Some(BootOrderSnapshot {
                    attributes: 7,
                    ids: vec![boothop_core::BootId(8)],
                }),
            }),
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
fn uninstall_boot_order_recovery_advances_only_on_exact_durable_post_order() {
    let fs = support::FakeFs::installed();
    let ArchProvisionState::Ready(entry) = support::ready_state() else {
        unreachable!()
    };
    let boot_id = entry.boot_id;
    let state = ArchProvisionState::Uninstalling(boothop_core::UninstallingRecord {
        operation_id: "uninstall-exact".into(),
        operation_version: 1,
        owned_entry: entry,
        step: UninstallingStep::BootOrderRemoved,
        residual: vec![],
        boot_order_proof: Some(BootOrderRemovalProof {
            operation_id: "uninstall-exact".into(),
            operation_version: 1,
            boot_id,
            before: BootOrderSnapshot {
                attributes: 7,
                ids: vec![boothop_core::BootId(8), boot_id, boothop_core::BootId(9)],
            },
            expected_after: BootOrderSnapshot {
                attributes: 7,
                ids: vec![boothop_core::BootId(8), boothop_core::BootId(9)],
            },
            observed_after: Some(BootOrderSnapshot {
                attributes: 7,
                ids: vec![boothop_core::BootId(8), boothop_core::BootId(9)],
            }),
        }),
    });
    fs.insert(
        "/var/lib/boothop/arch-provision.json",
        0o100600,
        boothop_core::encode_arch_provision_state(&state).unwrap(),
    );
    let mut backend = FakeBackend::new(fs.clone());
    backend.observed_order_override = Some(
        BootOrderValue::new(7, vec![boothop_core::BootId(8), boothop_core::BootId(9)]).unwrap(),
    );
    let mut store = ArchProvisionStore::acquire(fs).unwrap();
    let recovered = recover(&mut store, &mut backend).unwrap();
    assert!(matches!(
        recovered,
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::BootOrderRemovalReadBackVerified
                && record.residual.is_empty()
    ));
    assert!(backend.mutations.is_empty());
}

#[test]
fn uninstall_restart_after_mutation_before_checkpoint_uses_durable_expected_order() {
    let fs = support::FakeFs::installed();
    let ArchProvisionState::Ready(entry) = support::ready_state() else {
        unreachable!()
    };
    let boot_id = entry.boot_id;
    let state = ArchProvisionState::Uninstalling(boothop_core::UninstallingRecord {
        operation_id: "uninstall-before-checkpoint".into(),
        operation_version: 1,
        owned_entry: entry,
        step: UninstallingStep::BootOrderRemovalAttempted,
        residual: vec![],
        boot_order_proof: Some(BootOrderRemovalProof {
            operation_id: "uninstall-before-checkpoint".into(),
            operation_version: 1,
            boot_id,
            before: BootOrderSnapshot {
                attributes: 7,
                ids: vec![boothop_core::BootId(8), boot_id, boothop_core::BootId(9)],
            },
            expected_after: BootOrderSnapshot {
                attributes: 7,
                ids: vec![boothop_core::BootId(8), boothop_core::BootId(9)],
            },
            observed_after: None,
        }),
    });
    fs.insert(
        "/var/lib/boothop/arch-provision.json",
        0o100600,
        boothop_core::encode_arch_provision_state(&state).unwrap(),
    );
    let mut backend = FakeBackend::new(fs.clone());
    backend.observed_order_override = Some(
        BootOrderValue::new(7, vec![boothop_core::BootId(8), boothop_core::BootId(9)]).unwrap(),
    );
    let writes_before = backend.mutations.len();
    let mut store = ArchProvisionStore::acquire(fs).unwrap();
    let recovered = recover(&mut store, &mut backend).unwrap();
    assert!(matches!(
        recovered,
        ArchProvisionState::Uninstalling(record)
            if record.step == UninstallingStep::BootOrderRemovalReadBackVerified
                && record.residual.is_empty()
                && record.boot_order_proof.as_ref().is_some_and(|proof|
                    proof.observed_after.as_ref() == Some(&BootOrderSnapshot {
                        attributes: 7,
                        ids: vec![boothop_core::BootId(8), boothop_core::BootId(9)],
                    }))
    ));
    assert_eq!(backend.mutations.len(), writes_before);
}

#[test]
fn uki_removed_recovery_accepts_expected_absence_but_rejects_unknown_presence() {
    for unknown_presence in [false, true] {
        let fs = support::FakeFs::installed();
        let ArchProvisionState::Ready(entry) = support::ready_state() else {
            unreachable!()
        };
        let boot_id = entry.boot_id;
        let state = ArchProvisionState::Uninstalling(boothop_core::UninstallingRecord {
            operation_id: "uninstall-1".into(),
            operation_version: 1,
            owned_entry: entry,
            step: UninstallingStep::UkiRemoved,
            residual: vec![],
            boot_order_proof: Some(BootOrderRemovalProof {
                operation_id: "uninstall-1".into(),
                operation_version: 1,
                boot_id,
                before: BootOrderSnapshot {
                    attributes: 7,
                    ids: vec![boot_id],
                },
                expected_after: BootOrderSnapshot {
                    attributes: 7,
                    ids: vec![],
                },
                observed_after: Some(BootOrderSnapshot {
                    attributes: 7,
                    ids: vec![],
                }),
            }),
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
    let fs = support::FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let mut backend = FakeBackend::new(fs.clone());
    backend.prepare_mismatch = FailAt::Uki;
    assert_eq!(
        provision(&mut store, &mut backend, pending_intent()),
        Err(Error::ReadbackFailed)
    );
    assert!(backend.mutations.is_empty());
    assert!(backend.permit_evidence.is_empty());
    assert!(
        matches!(store.load().unwrap(), ArchProvisionState::Provisioning(ref r)
        if r.step == ProvisioningStep::UkiPublicationPending)
    );
}

#[test]
fn preexisting_exact_uki_path_stops_before_any_publication_mutation() {
    let fs = support::FakeFs::installed();
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let mut backend = FakeBackend::new(fs.clone());
    backend.preexisting_uki = true;
    assert_eq!(
        provision(&mut store, &mut backend, pending_intent()),
        Err(Error::ReadbackFailed)
    );
    assert!(backend.mutations.is_empty());
    assert!(backend.permit_evidence.is_empty());
    assert!(
        matches!(store.load().unwrap(), ArchProvisionState::Provisioning(ref record)
        if record.step == ProvisioningStep::UkiPublicationPending)
    );
}

#[test]
fn ready_state_cannot_enter_initial_uki_publication() {
    let fs = support::FakeFs::installed();
    let ready = support::ready_state();
    fs.insert(
        "/var/lib/boothop/arch-provision.json",
        0o100600,
        boothop_core::encode_arch_provision_state(&ready).unwrap(),
    );
    let mut store = ArchProvisionStore::acquire(fs.clone()).unwrap();
    let mut backend = FakeBackend::new(fs);
    assert_eq!(
        provision(&mut store, &mut backend, pending_intent()),
        Err(Error::NotConfigured)
    );
    assert!(backend.events.is_empty());
    assert!(backend.uki_publisher_calls.is_empty());
    assert!(matches!(
        store.load().unwrap(),
        ArchProvisionState::Ready(_)
    ));
}
