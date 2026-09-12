//! UI state machine. Only explicit intents submit work; cached display data never authorizes it.
use crate::{
    cache::{Cache, CacheError, CachedTarget},
    helper_client::{Boundary, ClientError, HelperClient, TransportError},
};
use boothop_core::{
    BootId, Candidate, Classification, Error, Os, RecordDiagnostic, Report, Request,
    ResidualAssessment, Stage,
};
use std::sync::{Arc, Mutex, mpsc};

pub type Job = Box<dyn FnOnce() + Send>;
pub trait Helper: Send + 'static {
    fn run(&mut self, request: Request) -> Result<Report, ClientError>;
}
impl<B: Boundary + Send + 'static> Helper for HelperClient<B> {
    fn run(&mut self, request: Request) -> Result<Report, ClientError> {
        HelperClient::run(self, request)
    }
}
#[derive(Debug)]
pub struct ScheduleError;
/// An error guarantees the job did not run and will not run later.
pub trait Executor {
    fn execute(&self, job: Job) -> Result<(), ScheduleError>;
}
pub struct ThreadExecutor;
impl Executor for ThreadExecutor {
    fn execute(&self, job: Job) -> Result<(), ScheduleError> {
        std::thread::Builder::new()
            .name("boothop-request".into())
            .spawn(job)
            .map(|_| ())
            .map_err(|_| ScheduleError)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiState {
    Unconfigured,
    CachedTarget(CachedTarget),
    Busy,
    Configured,
    TargetChanged,
    Failed,
    RebootRequested,
    UnknownResult,
    UnsupportedRecord,
    StoreDurabilityUnknown { raw_code: i32 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiIntent {
    Inspect,
    Configure(BootId, Os),
    Switch,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum FailureNotice {
    PreHelloAuthorizationOrLaunch { raw_code: i32 },
}
impl FailureNotice {
    fn status(&self) -> &'static str {
        match self {
            Self::PreHelloAuthorizationOrLaunch { .. } => {
                "授权未完成或 helper 启动失败；请求尚未发送。"
            }
        }
    }
}
type Completion = (Request, Result<Report, ClientError>);
pub struct Controller<H, E, C> {
    helper: Arc<Mutex<H>>,
    executor: E,
    cache: C,
    state: UiState,
    tx: mpsc::Sender<Completion>,
    rx: mpsc::Receiver<Completion>,
    wake: Arc<dyn Fn() + Send + Sync>,
    candidates: Vec<Candidate>,
    selected: Option<BootId>,
    confirmed: bool,
    target: Option<CachedTarget>,
    diagnostic: String,
    failure_notice: Option<FailureNotice>,
    cache_warning: Option<CacheError>,
    inspected: bool,
    recovery_state: Option<UiState>,
}
impl<H: Helper, E: Executor, C: Cache> Controller<H, E, C> {
    pub fn new(helper: H, executor: E, cache: C, wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        let (state, target, warning) = match cache.load() {
            Ok(Some(target)) => (UiState::CachedTarget(target.clone()), Some(target), None),
            Ok(None) => (UiState::Unconfigured, None, None),
            Err(error) => (UiState::Failed, None, Some(error)),
        };
        let (tx, rx) = mpsc::channel();
        Self {
            helper: Arc::new(Mutex::new(helper)),
            executor,
            cache,
            state,
            tx,
            rx,
            wake,
            candidates: vec![],
            selected: None,
            confirmed: false,
            target,
            diagnostic: String::new(),
            failure_notice: None,
            cache_warning: warning,
            inspected: false,
            recovery_state: None,
        }
    }
    pub fn state(&self) -> &UiState {
        &self.state
    }
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }
    pub fn selected(&self) -> Option<BootId> {
        self.selected
    }
    pub fn confirmed(&self) -> bool {
        self.confirmed
    }
    pub fn target(&self) -> Option<&CachedTarget> {
        self.target.as_ref()
    }
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
    pub fn cache_warning(&self) -> Option<&CacheError> {
        self.cache_warning.as_ref()
    }
    fn inspect_only(&self) -> bool {
        if self.state == UiState::TargetChanged {
            return !self.inspected;
        }
        matches!(
            self.state,
            UiState::UnsupportedRecord
                | UiState::StoreDurabilityUnknown { .. }
                | UiState::UnknownResult
                | UiState::RebootRequested
        )
    }
    pub fn can_inspect(&self) -> bool {
        self.state != UiState::Busy
    }
    pub fn can_switch(&self) -> bool {
        self.can_inspect() && !self.inspect_only() && self.state != UiState::TargetChanged
    }
    pub fn configuration_visible(&self) -> bool {
        !self.inspect_only() && self.recovery_state.is_none()
    }
    pub fn can_configure(&self) -> bool {
        self.can_select() && self.selected.is_some() && self.confirmed
    }
    pub fn can_select(&self) -> bool {
        self.can_inspect()
            && self.configuration_visible()
            && self.inspected
            && self
                .candidates
                .iter()
                .any(|candidate| candidate.classification != Classification::Unsupported)
    }
    pub fn select(&mut self, boot_id: BootId) -> bool {
        if !self.can_select() {
            return false;
        }
        self.confirmed = false;
        self.selected = self
            .candidates
            .iter()
            .find(|c| c.boot_id == boot_id && c.classification != Classification::Unsupported)
            .map(|c| c.boot_id);
        self.selected.is_some()
    }
    pub fn confirm_windows(&mut self, confirmed: bool) {
        if self.can_select() {
            self.confirmed = confirmed && self.selected.is_some();
        }
    }
    pub fn status(&self) -> &'static str {
        if let Some(notice) = &self.failure_notice {
            return notice.status();
        }
        match self.state {
            UiState::Unconfigured if self.inspected => {
                "检查完成：未发现登记记录。请选择并确认 Windows；未验证启动链。"
            }
            UiState::Unconfigured => "本地缓存中没有目标；尚未检查受保护配置。请主动检查。",
            UiState::CachedTarget(_) => "缓存状态，切换时将重新验证",
            UiState::Busy => "正在等待授权或处理请求，请勿重复操作。",
            UiState::Configured if self.inspected => "检查完成：展示发现与记录信息；未验证启动链。",
            UiState::Configured => "配置已保存；切换时将重新验证目标。",
            UiState::TargetChanged => "目标启动配置已变化，请重新选择并确认目标。",
            UiState::Failed if self.cache_warning.is_some() => {
                "本地展示缓存不可用；尚未检查受保护配置。"
            }
            UiState::Failed => "操作失败。请查看诊断；不会自动重试或回滚。",
            UiState::RebootRequested => "重启请求已被系统接受",
            UiState::UnknownResult => {
                "请求结果未知，BootNext 或重启请求可能已生效。请先检查，勿重复操作；不会自动重试或回滚。"
            }
            UiState::UnsupportedRecord => {
                "当前 BootHop 版本无法读取该配置，请使用兼容版本或升级；如需恢复，应使用未来明确的管理员恢复流程"
            }
            UiState::StoreDurabilityUnknown { .. } => {
                "配置已替换，但持久化结果未知。请先检查当前配置，勿重复保存。"
            }
        }
    }
    pub fn handle(&mut self, intent: UiIntent) {
        if self.state == UiState::Busy || (self.inspect_only() && intent != UiIntent::Inspect) {
            return;
        }
        let request = match intent {
            UiIntent::Inspect => Request::Inspect,
            UiIntent::Switch if self.can_switch() => Request::Switch { os: Os::Windows },
            UiIntent::Switch => return,
            UiIntent::Configure(_, os) if os != Os::Windows => {
                self.fail(ClientError::Domain(Error::UnexpectedOs));
                return;
            }
            UiIntent::Configure(boot_id, os)
                if self.can_configure() && self.selected == Some(boot_id) =>
            {
                Request::Configure { boot_id, os }
            }
            UiIntent::Configure(_, _) => return,
        };
        self.failure_notice = None;
        // Keep unresolved evidence across failed inspection or attempted reconfiguration.
        if (intent == UiIntent::Inspect && self.inspect_only())
            || self.state == UiState::TargetChanged
        {
            self.latch_recovery_state(self.state.clone());
        }
        self.state = UiState::Busy;
        self.selected = None;
        self.confirmed = false;
        if self.recovery_state != Some(UiState::TargetChanged) {
            self.diagnostic.clear();
        }
        self.cache_warning = None;
        let helper = self.helper.clone();
        let tx = self.tx.clone();
        let wake = self.wake.clone();
        if self
            .executor
            .execute(Box::new(move || {
                // A panic may follow delivery: conservatively report unknown, never retry.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    helper
                        .lock()
                        .map_err(|_| ClientError::BeforeSend(TransportError::Launch))?
                        .run(request)
                }))
                .unwrap_or(Err(ClientError::UnknownAfterSend(TransportError::Io)));
                if tx.send((request, result)).is_ok() {
                    wake();
                }
            }))
            .is_err()
        {
            self.fail(ClientError::BeforeSend(TransportError::Launch));
        }
    }
    /// Called on the UI thread, after an executor completion notification.
    pub fn poll(&mut self) {
        if let Ok((request, result)) = self.rx.try_recv() {
            match result {
                Ok(report) => self.success(request, report),
                Err(error) => self.fail(error),
            }
        }
    }
    fn success(&mut self, request: Request, report: Report) {
        // Validate the entire request/report relationship before trusting any returned display data.
        let Some(outcome) = validate_report(request, &report) else {
            self.fail(ClientError::UnknownAfterSend(TransportError::Protocol));
            return;
        };
        self.target = display_target(&report);
        let previous_diagnostic = std::mem::take(&mut self.diagnostic);
        self.diagnostic = stages_text(&report.stages);
        match outcome {
            ValidatedReport::Inspected | ValidatedReport::InspectedChanged => {
                // Inspect exposes no identity evidence that can clear an earlier mismatch.
                let previously_changed = self.recovery_state == Some(UiState::TargetChanged);
                if previously_changed && self.diagnostic.is_empty() {
                    self.diagnostic = previous_diagnostic;
                }
                self.recovery_state = None;
                self.inspected = true;
                self.state =
                    if previously_changed || matches!(outcome, ValidatedReport::InspectedChanged) {
                        UiState::TargetChanged
                    } else {
                        match report.record {
                            RecordDiagnostic::Missing => UiState::Unconfigured,
                            RecordDiagnostic::Ready { .. } => UiState::Configured,
                        }
                    };
                self.candidates = report.candidates;
            }
            ValidatedReport::Configured => {
                self.recovery_state = None;
                self.inspected = false;
                self.state = UiState::Configured;
                if let Some(target) = &self.target {
                    self.cache_warning = self.cache.save(target).err();
                }
                self.candidates.clear();
            }
            ValidatedReport::RebootAccepted => {
                self.state = UiState::RebootRequested;
                self.candidates.clear();
            }
            ValidatedReport::RebootUnknown => {
                self.state = UiState::UnknownResult;
                self.candidates.clear();
            }
        }
    }
    fn fail(&mut self, error: ClientError) {
        self.failure_notice = match &error {
            ClientError::AuthorizationOrLaunchFailed { raw_code } => {
                Some(FailureNotice::PreHelloAuthorizationOrLaunch {
                    raw_code: *raw_code,
                })
            }
            _ => None,
        };
        if self.state == UiState::TargetChanged {
            self.latch_recovery_state(UiState::TargetChanged);
        }
        self.candidates.clear();
        self.selected = None;
        self.confirmed = false;
        self.inspected = false;
        self.diagnostic.clear();
        self.state = match &error {
            ClientError::UnknownAfterSend(kind) => {
                self.diagnostic = format!("UnknownAfterSend: {kind:?}");
                UiState::UnknownResult
            }
            ClientError::BeforeSend(kind) => {
                self.diagnostic = format!("BeforeSend: {kind:?}");
                UiState::Failed
            }
            ClientError::Cancelled => {
                self.diagnostic = "Cancelled".into();
                UiState::Failed
            }
            ClientError::AuthorizationOrLaunchFailed { raw_code } => {
                self.diagnostic =
                    format!("AuthorizationOrLaunchFailed: raw exit {raw_code}；请求尚未发送");
                UiState::Failed
            }
            ClientError::Domain(error) => {
                // Keep the terminal category/errno ahead of bounded nested detail.
                self.diagnostic = if matches!(error, Error::FlowFailure { .. }) {
                    format!(
                        "{}；{}",
                        domain_text(root_cause(error), 0),
                        domain_text(error, 0)
                    )
                } else {
                    domain_text(error, 0)
                };
                domain_state(error)
            }
        };
        self.diagnostic = bounded(std::mem::take(&mut self.diagnostic), 4096);
        if self.state == UiState::Failed
            && let Some(previous) = &self.recovery_state
        {
            self.state = previous.clone();
        }
    }
    fn latch_recovery_state(&mut self, state: UiState) {
        if state == UiState::TargetChanged || self.recovery_state != Some(UiState::TargetChanged) {
            self.recovery_state = Some(state);
        }
    }
}
enum ValidatedReport {
    Inspected,
    InspectedChanged,
    Configured,
    RebootAccepted,
    RebootUnknown,
}

/// Public report semantics guaranteed by core::execute on a Linux host.
/// Inspect deliberately does not validate the saved identity against current options.
fn validate_report(request: Request, report: &Report) -> Option<ValidatedReport> {
    let target = match report.record {
        RecordDiagnostic::Missing => None,
        RecordDiagnostic::Ready {
            boot_id,
            os: Os::Windows,
        } => Some(boot_id),
        RecordDiagnostic::Ready { os: Os::Linux, .. } => return None,
    };
    let supported_target = target.is_some_and(|id| {
        let mut matches = report
            .candidates
            .iter()
            .filter(|candidate| candidate.boot_id == id);
        matches
            .next()
            .is_some_and(|candidate| candidate.classification != Classification::Unsupported)
            && matches.next().is_none()
    });
    match request {
        Request::Inspect if report.stages.is_empty() => {
            Some(if target.is_some() && !supported_target {
                ValidatedReport::InspectedChanged
            } else {
                ValidatedReport::Inspected
            })
        }
        Request::Configure {
            boot_id,
            os: Os::Windows,
        } if target == Some(boot_id)
            && supported_target
            && report.stages == [Stage::TargetValidated] =>
        {
            Some(ValidatedReport::Configured)
        }
        Request::Switch { os: Os::Windows } if supported_target => match report.stages.as_slice() {
            [
                Stage::TargetValidated,
                Stage::BootNextVerified,
                Stage::RebootAccepted,
            ] => Some(ValidatedReport::RebootAccepted),
            [
                Stage::TargetValidated,
                Stage::BootNextVerified,
                Stage::RebootUnknown,
                Stage::ResidualPossible,
            ] => Some(ValidatedReport::RebootUnknown),
            _ => None,
        },
        _ => None,
    }
}

fn display_target(report: &Report) -> Option<CachedTarget> {
    match report.record {
        RecordDiagnostic::Missing => None,
        RecordDiagnostic::Ready { boot_id, os } => Some(CachedTarget {
            boot_id,
            os,
            description_utf16: report
                .candidates
                .iter()
                .find(|c| c.boot_id == boot_id)
                .map(|c| c.description_utf16.clone()),
        }),
    }
}
fn root_cause(mut error: &Error) -> &Error {
    while let Error::FlowFailure { cause, .. } = error {
        error = cause;
    }
    error
}
fn domain_state(error: &Error) -> UiState {
    if let Error::FlowFailure { stages, .. } = error {
        // A malformed/oversize terminal response can still carry trusted
        // mutation evidence. Never expose it as an ordinary retryable
        // failure; switching stays closed until an explicit inspection.
        if stages
            .iter()
            .any(|stage| !matches!(stage, Stage::TargetValidated))
            && !matches!(root_cause(error), Error::StoreDurabilityUnknown { .. })
        {
            return UiState::UnknownResult;
        }
    }
    match root_cause(error) {
        Error::IdentityMismatch | Error::TargetMissing => UiState::TargetChanged,
        Error::UnsupportedRecordVersion { .. } | Error::UnsupportedIdentityComponent => {
            UiState::UnsupportedRecord
        }
        Error::StoreDurabilityUnknown { raw_code } => UiState::StoreDurabilityUnknown {
            raw_code: *raw_code,
        },
        _ => UiState::Failed,
    }
}
fn stages_text(stages: &[Stage]) -> String {
    stages
        .iter()
        .take(32)
        .map(|s| match s {
            Stage::TargetValidated => "目标配置已验证",
            Stage::BootNextVerified => "BootNext 已验证",
            Stage::RebootAccepted => "重启请求已被系统接受",
            Stage::RebootRejected => "RebootRejected：重启请求被拒绝",
            Stage::RebootUnknown => "重启请求结果未知",
            Stage::ResidualPossible => "BootNext 可能残留",
        })
        .collect::<Vec<_>>()
        .join("；")
}
fn domain_text(error: &Error, depth: usize) -> String {
    if depth > 8 {
        return "ResourceLimit".into();
    }
    match error {
        Error::FlowFailure {
            cause,
            stages,
            residual_assessment,
            ..
        } => {
            let assessment = match residual_assessment {
                ResidualAssessment::NotChecked => "残留未检查".into(),
                ResidualAssessment::Observed(Some(id)) => {
                    format!("残留观察 Boot{:04X}（非未来保证）", id.0)
                }
                ResidualAssessment::Observed(None) => "残留观察：未设置（非未来保证）".into(),
                ResidualAssessment::ReadFailed(e) => {
                    format!("残留读取失败：{}", domain_text(e, depth + 1))
                }
            };
            bounded(
                format!(
                    "FlowFailure: {}；{}；{}",
                    domain_text(cause, depth + 1),
                    stages_text(stages),
                    assessment
                ),
                4096,
            )
        }
        Error::PlatformIo {
            operation,
            raw_code,
        } => {
            let safe = match operation.as_str() {
                "open" | "read" | "write" | "metadata" | "lock" | "fsync" | "rename" | "ipc"
                | "reboot" => operation.as_str(),
                _ => "unknown",
            };
            format!("PlatformIo: {safe}, errno={raw_code}")
        }
        Error::StoreDurabilityUnknown { raw_code } => {
            format!("StoreDurabilityUnknown: errno={raw_code}")
        }
        Error::UnsupportedRecordVersion { found } => format!("UnsupportedRecordVersion: {found}"),
        // These variants contain no firmware data or free-form strings.
        other => format!("{other:?}"),
    }
}
fn bounded(mut text: String, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text
}
