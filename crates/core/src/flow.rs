use crate::{
    BootId, Candidate, Classification, Error, OptionInventory, Os, RebootOutcome, RecordDiagnostic,
    RecordState, Report, Request, ResidualAssessment, Stage, TargetRecord, canonicalize,
    expected_target,
};

/// Adapter boundary. All methods except save/write/reboot must be read-only.
pub trait Platform {
    /// Missing is valid only after trusted store/path validation. Reject unsupported/corrupt records.
    fn load_record(&mut self) -> Result<RecordState, Error>;
    fn save_record(&mut self, target: &TargetRecord) -> Result<(), Error>;
    /// Return complete parsed buffers after checking variable attributes and enumeration completeness.
    /// Core additionally validates load-option attributes, structure, and identity.
    /// Duplicate boot IDs are rejected; equal identities under distinct IDs remain selectable.
    fn read_options(&mut self) -> Result<OptionInventory, Error>;
    /// Validate control-variable attributes and shape; only a confirmed absent value is None.
    fn read_next(&mut self) -> Result<Option<BootId>, Error>;
    /// A failed write may still have changed firmware. Never replay or clear it automatically.
    fn write_next(&mut self, target: BootId) -> Result<(), Error>;
    fn reboot(&mut self) -> RebootOutcome;
    /// Called after the trusted record read and before any firmware reads or mutations.
    fn check_environment(&mut self) -> Result<(), Error>;
}

pub fn execute(request: Request, host: Os, platform: &mut impl Platform) -> Result<Report, Error> {
    let record = platform.load_record()?;
    if let RecordState::Ready(target) = &record {
        crate::identity::validate_canonical_identity(&target.identity)
            .map_err(|_| Error::CorruptRecord)?;
    }
    if let Request::Configure { os, .. } | Request::Switch { os } = request
        && os != expected_target(host)
    {
        return Err(Error::UnexpectedOs);
    }
    platform.check_environment()?;
    let OptionInventory {
        entries: options,
        diagnostics,
    } = platform.read_options()?;
    let mut seen = std::collections::HashSet::new();
    if options.iter().any(|(id, _)| !seen.insert(*id)) {
        return Err(Error::UnsupportedFormat);
    }
    let identities: Vec<_> = options
        .iter()
        .map(|(_, option)| canonicalize(option))
        .collect();
    let candidates = options
        .iter()
        .zip(&identities)
        .enumerate()
        .map(|(index, ((id, option), identity))| Candidate {
            boot_id: *id,
            description_utf16: option.description_utf16.clone(),
            classification: if identity.is_ok() {
                Classification::NeedsConfirmation
            } else {
                Classification::Unsupported
            },
            ambiguous: identity.as_ref().is_ok_and(|identity| {
                identities
                    .iter()
                    .enumerate()
                    .any(|(other, value)| other != index && value.as_ref() == Ok(identity))
            }),
        })
        .collect();
    let diagnostic = match &record {
        RecordState::Missing => RecordDiagnostic::Missing,
        RecordState::Ready(target) => RecordDiagnostic::Ready {
            boot_id: target.boot_id,
            os: target.os,
        },
    };
    let mut report = Report {
        candidates,
        record: diagnostic,
        stages: Vec::new(),
        diagnostics,
    };
    match request {
        Request::Inspect => Ok(report),
        Request::Configure { boot_id, os } => {
            let index = options
                .iter()
                .position(|(id, _)| *id == boot_id)
                .ok_or(Error::TargetMissing)?;
            let target = TargetRecord {
                boot_id,
                os,
                identity: identities[index].clone()?,
            };
            report.stages.push(Stage::TargetValidated);
            platform
                .save_record(&target)
                .map_err(|error| failure(error, &report, true))?;
            report.record = RecordDiagnostic::Ready { boot_id, os };
            Ok(report)
        }
        Request::Switch { os } => {
            let RecordState::Ready(target) = record else {
                return Err(Error::NotConfigured);
            };
            if target.os != os {
                return Err(Error::UnexpectedOs);
            }
            let index = options
                .iter()
                .position(|(id, _)| *id == target.boot_id)
                .ok_or(Error::TargetMissing)?;
            if identities[index].as_ref().map_err(Clone::clone)? != &target.identity {
                return Err(Error::IdentityMismatch);
            }
            report.stages.push(Stage::TargetValidated);
            let initial = platform
                .read_next()
                .map_err(|error| failure(error, &report, false))?;
            if initial.is_some_and(|id| id != target.boot_id) {
                return Err(failure(Error::BootNextConflict, &report, false));
            }
            if initial.is_none() {
                // Recheck immediately before attempting a write. This is not an external CAS:
                // the adapter must also reject an object that appears during write preparation.
                match platform
                    .read_next()
                    .map_err(|error| failure(error, &report, false))?
                {
                    Some(id) if id != target.boot_id => {
                        return Err(failure(Error::BootNextConflict, &report, false));
                    }
                    Some(_) => {}
                    None => platform
                        .write_next(target.boot_id)
                        .map_err(|error| failure(error, &report, true))?,
                }
            }
            if platform
                .read_next()
                .map_err(|error| failure(error, &report, true))?
                != Some(target.boot_id)
            {
                return Err(failure(Error::ReadbackFailed, &report, true));
            }
            report.stages.push(Stage::BootNextVerified);
            match platform.reboot() {
                RebootOutcome::Accepted => report.stages.push(Stage::RebootAccepted),
                RebootOutcome::Unknown => {
                    report.stages.push(Stage::RebootUnknown);
                    report.stages.push(Stage::ResidualPossible);
                }
                RebootOutcome::Rejected => {
                    report.stages.push(Stage::RebootRejected);
                    let assessment = match platform.read_next() {
                        Ok(next) => {
                            if next == Some(target.boot_id) {
                                report.stages.push(Stage::ResidualPossible);
                            }
                            ResidualAssessment::Observed(next)
                        }
                        Err(error) => {
                            report.stages.push(Stage::ResidualPossible);
                            ResidualAssessment::ReadFailed(Box::new(error))
                        }
                    };
                    return Err(Error::FlowFailure {
                        cause: Box::new(Error::RebootRejected),
                        stages: report.stages,
                        residual_assessment: assessment,
                        diagnostics: report.diagnostics,
                    });
                }
            }
            Ok(report)
        }
    }
}

fn failure(cause: Error, report: &Report, residual_possible: bool) -> Error {
    let mut stages = report.stages.clone();
    if residual_possible {
        stages.push(Stage::ResidualPossible);
    }
    Error::FlowFailure {
        cause: Box::new(cause),
        stages,
        residual_assessment: ResidualAssessment::NotChecked,
        diagnostics: report.diagnostics.clone(),
    }
}
