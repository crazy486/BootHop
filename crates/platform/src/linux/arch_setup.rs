//! One-shot Arch setup. Every host operation is injected; this module does not open host paths.
use boothop_core::{BootId, Error, arch_uki_load_option, serialize_load_option};
use sha2::{Digest, Sha256};

use super::{
    arch_identity::InstalledIdentity,
    arch_uki::{SetupError, UkiPlan, render_boothop_preset},
    setup_firmware::{SetupFirmware, allocate_unused_id, append_tail_exact, create_exact_entry},
};

pub const PUBLISHER: &str = "/usr/lib/boothop/boothop-uki-publish";
pub const POST_HOOK: &str = "/etc/initcpio/post/boothop-uki";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupIntent {
    pub flavor: String,
}
impl SetupIntent {
    pub fn new(flavor: String) -> Self {
        Self { flavor }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupStage {
    Plan,
    InitialState,
    Publisher,
    Preset,
    Hook,
    ClearStage,
    Build,
    Artifact,
    Entry,
    Order,
    Marker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetupProblem {
    Plan(SetupError),
    Firmware(Error),
    Backend,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Observed<T> {
    Known(T),
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupObservations {
    pub preset_stanza: Observed<Option<String>>,
    pub hook_exact: Observed<bool>,
    pub artifact_present: Observed<bool>,
    pub entry_exact: Observed<Option<bool>>,
    pub boot_order: Observed<Vec<BootId>>,
    pub boot_next: Observed<Option<BootId>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupFailure {
    pub stage: SetupStage,
    pub problem: SetupProblem,
    pub candidate_id: Option<BootId>,
    pub observed: Box<SetupObservations>,
}

/// All mutation methods are single attempts. Observation methods are read-only and must
/// preserve errors as Unknown. Initial build must retain normal package-manager serialization.
pub trait ArchSetupBackend {
    type Firmware: SetupFirmware;
    fn plan(&mut self, flavor: &str) -> Result<UkiPlan, SetupError>;
    fn firmware(&mut self) -> &mut Self::Firmware;
    fn verify_initial_absence(&mut self, plan: &UkiPlan) -> Result<(), SetupProblem>;
    fn verify_publisher(&mut self) -> Result<(), SetupProblem>;
    fn read_preset(&mut self, plan: &UkiPlan) -> Result<String, SetupProblem>;
    fn write_preset_if_exact(
        &mut self,
        plan: &UkiPlan,
        old: &str,
        new: &str,
    ) -> Result<(), SetupProblem>;
    fn install_fixed_hook(&mut self, plan: &UkiPlan) -> Result<(), SetupProblem>;
    fn clear_stage(&mut self, plan: &UkiPlan) -> Result<(), SetupProblem>;
    fn build_initial(&mut self, plan: &UkiPlan) -> Result<(), SetupProblem>;
    fn inspect_published(&mut self, plan: &UkiPlan) -> Result<(), SetupProblem>;
    fn save_identity(&mut self, identity: &InstalledIdentity) -> Result<(), SetupProblem>;
    fn observe_preset_stanza(
        &mut self,
        plan: Option<&UkiPlan>,
    ) -> Result<Option<String>, ObservationError>;
    fn observe_hook_exact(&mut self, plan: Option<&UkiPlan>) -> Result<bool, ObservationError>;
    fn observe_artifact(&mut self, plan: Option<&UkiPlan>) -> Result<bool, ObservationError>;
    fn observe_entry_exact(&mut self, id: BootId, option: &[u8]) -> Result<bool, ObservationError>;
    fn observe_order(&mut self) -> Result<Vec<BootId>, ObservationError>;
    fn observe_next(&mut self) -> Result<Option<BootId>, ObservationError>;
}

fn observed<T>(read: Result<T, ObservationError>) -> Observed<T> {
    read.map_or(Observed::Unknown, Observed::Known)
}

fn failure<B: ArchSetupBackend>(
    backend: &mut B,
    plan: Option<&UkiPlan>,
    entry: Option<(BootId, &[u8])>,
    stage: SetupStage,
    problem: SetupProblem,
) -> SetupFailure {
    SetupFailure {
        stage,
        problem,
        candidate_id: entry.map(|(id, _)| id),
        observed: Box::new(SetupObservations {
            preset_stanza: observed(backend.observe_preset_stanza(plan)),
            hook_exact: observed(backend.observe_hook_exact(plan)),
            artifact_present: observed(backend.observe_artifact(plan)),
            entry_exact: match entry {
                Some((id, bytes)) => observed(backend.observe_entry_exact(id, bytes).map(Some)),
                None => Observed::Known(None),
            },
            boot_order: observed(backend.observe_order()),
            boot_next: observed(backend.observe_next()),
        }),
    }
}

pub fn run_arch_setup<B: ArchSetupBackend>(
    intent: SetupIntent,
    backend: &mut B,
) -> Result<InstalledIdentity, SetupFailure> {
    let plan = backend.plan(&intent.flavor).map_err(|error| {
        failure(
            backend,
            None,
            None,
            SetupStage::Plan,
            SetupProblem::Plan(error),
        )
    })?;
    let fail = |backend: &mut B, entry, stage, problem| {
        failure(backend, Some(&plan), entry, stage, problem)
    };
    backend
        .verify_initial_absence(&plan)
        .map_err(|error| fail(backend, None, SetupStage::InitialState, error))?;
    backend
        .verify_publisher()
        .map_err(|error| fail(backend, None, SetupStage::Publisher, error))?;
    let id = allocate_unused_id(backend.firmware()).map_err(|error| {
        fail(
            backend,
            None,
            SetupStage::InitialState,
            SetupProblem::Firmware(error),
        )
    })?;
    let option = arch_uki_load_option(plan.esp_identity())
        .and_then(|option| serialize_load_option(&option))
        .map_err(|error| {
            fail(
                backend,
                None,
                SetupStage::Plan,
                SetupProblem::Firmware(error),
            )
        })?;
    let entry = Some((id, option.as_slice()));
    let old = backend
        .read_preset(&plan)
        .map_err(|error| fail(backend, entry, SetupStage::Preset, error))?;
    let new = render_boothop_preset(&old, &plan).map_err(|error| {
        fail(
            backend,
            entry,
            SetupStage::Preset,
            SetupProblem::Plan(error),
        )
    })?;
    backend
        .write_preset_if_exact(&plan, &old, &new)
        .map_err(|error| fail(backend, entry, SetupStage::Preset, error))?;
    backend
        .install_fixed_hook(&plan)
        .map_err(|error| fail(backend, entry, SetupStage::Hook, error))?;
    backend
        .clear_stage(&plan)
        .map_err(|error| fail(backend, entry, SetupStage::ClearStage, error))?;
    backend
        .build_initial(&plan)
        .map_err(|error| fail(backend, entry, SetupStage::Build, error))?;
    backend
        .inspect_published(&plan)
        .map_err(|error| fail(backend, entry, SetupStage::Artifact, error))?;
    let created = match create_exact_entry(backend.firmware(), id, &option) {
        Ok(created) => created,
        Err(error) => {
            return Err(fail(
                backend,
                entry,
                SetupStage::Entry,
                SetupProblem::Firmware(error),
            ));
        }
    };
    // The proof owns the firmware borrow and re-checks BootNext and exact Boot#### before
    // reading the latest order. No other backend call is interposed here.
    append_tail_exact(created).map_err(|error| {
        fail(
            backend,
            entry,
            SetupStage::Order,
            SetupProblem::Firmware(error),
        )
    })?;
    let digest: [u8; 32] = Sha256::digest(&option).into();
    let identity = InstalledIdentity::new(id, digest)
        .map_err(|_| fail(backend, entry, SetupStage::Marker, SetupProblem::Backend))?;
    backend
        .save_identity(&identity)
        .map_err(|error| fail(backend, entry, SetupStage::Marker, error))?;
    Ok(identity)
}
