use boothop_core::{
    BootId, Candidate, Classification, Error, Os, RecordDiagnostic, Report, Request,
    ResidualAssessment, Stage,
};
use boothop_gui::{
    cache::{Cache, CacheError, CachedTarget},
    controller::{Controller, Executor, Helper, Job, ScheduleError, UiIntent, UiState},
    helper_client::{ClientError, TransportError},
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct FakeHelper {
    calls: Arc<Mutex<Vec<Request>>>,
    replies: Arc<Mutex<VecDeque<Result<Report, ClientError>>>>,
}
impl Helper for FakeHelper {
    fn run(&mut self, request: Request) -> Result<Report, ClientError> {
        self.calls.lock().unwrap().push(request);
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected helper request")
    }
}
#[derive(Clone, Default)]
struct Manual(Arc<Mutex<Vec<Job>>>);
impl Executor for Manual {
    fn execute(&self, job: Job) -> Result<(), ScheduleError> {
        self.0.lock().unwrap().push(job);
        Ok(())
    }
}
impl Manual {
    fn finish(&self) {
        let job = self.0.lock().unwrap().remove(0);
        job();
    }
}
#[derive(Clone)]
struct FakeCache {
    loaded: Result<Option<CachedTarget>, CacheError>,
    writes: Arc<Mutex<Vec<CachedTarget>>>,
    fail_write: bool,
}
impl Default for FakeCache {
    fn default() -> Self {
        Self {
            loaded: Ok(None),
            writes: Default::default(),
            fail_write: false,
        }
    }
}
impl Cache for FakeCache {
    fn load(&self) -> Result<Option<CachedTarget>, CacheError> {
        self.loaded.clone()
    }
    fn save(&self, target: &CachedTarget) -> Result<(), CacheError> {
        self.writes.lock().unwrap().push(target.clone());
        if self.fail_write {
            Err(CacheError::Unavailable)
        } else {
            Ok(())
        }
    }
}
type TestController = Controller<FakeHelper, Manual, FakeCache>;
fn setup(cache: FakeCache) -> (TestController, FakeHelper, Manual, FakeCache) {
    let helper = FakeHelper::default();
    let executor = Manual::default();
    (
        Controller::new(
            helper.clone(),
            executor.clone(),
            cache.clone(),
            Arc::new(|| {}),
        ),
        helper,
        executor,
        cache,
    )
}
fn report() -> Report {
    Report {
        candidates: vec![Candidate {
            boot_id: BootId(7),
            description_utf16: "Windows GRUB".encode_utf16().collect(),
            classification: Classification::NeedsConfirmation,
            ambiguous: false,
        }],
        record: RecordDiagnostic::Missing,
        stages: vec![],
        diagnostics: vec![],
    }
}
fn finish(c: &mut TestController, h: &FakeHelper, e: &Manual, result: Result<Report, ClientError>) {
    h.replies.lock().unwrap().push_back(result);
    e.finish();
    c.poll();
}
fn inspect(c: &mut TestController, h: &FakeHelper, e: &Manual, r: Report) {
    c.handle(UiIntent::Inspect);
    finish(c, h, e, Ok(r));
}
fn select(c: &mut TestController) {
    assert!(c.select(BootId(7)));
    c.confirm_windows(true);
}
fn nested(error: Error) -> Error {
    Error::FlowFailure {
        cause: Box::new(error),
        stages: vec![
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::ResidualPossible,
        ],
        residual_assessment: ResidualAssessment::ReadFailed(Box::new(Error::PlatformIo {
            operation: "read".into(),
            raw_code: 5,
        })),
        diagnostics: vec![],
    }
}

#[test]
fn ordinary_open_never_calls_helper() {
    let (c, h, e, _) = setup(FakeCache::default());
    assert_eq!(c.state(), &UiState::Unconfigured);
    assert!(c.status().contains("本地缓存"));
    assert!(h.calls.lock().unwrap().is_empty());
    assert!(e.0.lock().unwrap().is_empty());
}
#[test]
fn busy_duplicate_switch_sends_exactly_one_request() {
    let (mut c, h, e, _) = setup(FakeCache::default());
    c.handle(UiIntent::Switch);
    c.handle(UiIntent::Switch);
    c.handle(UiIntent::Inspect);
    assert_eq!(c.state(), &UiState::Busy);
    assert_eq!(e.0.lock().unwrap().len(), 1);
    finish(&mut c, &h, &e, Err(ClientError::Cancelled));
    assert_eq!(
        *h.calls.lock().unwrap(),
        vec![Request::Switch { os: Os::Windows }]
    );
}
#[test]
fn unsupported_record_has_no_ordinary_configure_recovery() {
    for error in [
        Error::UnsupportedRecordVersion { found: 2 },
        Error::UnsupportedIdentityComponent,
        nested(Error::UnsupportedIdentityComponent),
        nested(Error::UnsupportedRecordVersion { found: 99 }),
    ] {
        let (mut c, h, e, cache) = setup(FakeCache::default());
        c.handle(UiIntent::Inspect);
        finish(&mut c, &h, &e, Err(ClientError::Domain(error)));
        assert_eq!(c.state(), &UiState::UnsupportedRecord);
        assert!(!c.configuration_visible());
        assert!(c.status().contains("未来明确的管理员恢复流程"));
        c.handle(UiIntent::Configure(BootId(7), Os::Windows));
        c.handle(UiIntent::Switch);
        assert_eq!(h.calls.lock().unwrap().len(), 1);
        assert!(e.0.lock().unwrap().is_empty());
        assert!(cache.writes.lock().unwrap().is_empty());
    }
}
#[test]
fn cached_display_is_untrusted_and_never_becomes_request_identity() {
    let target = CachedTarget {
        boot_id: BootId(65535),
        os: Os::Windows,
        description_utf16: Some("FAKE".encode_utf16().collect()),
    };
    let (mut c, h, e, _) = setup(FakeCache {
        loaded: Ok(Some(target.clone())),
        ..Default::default()
    });
    assert_eq!(c.state(), &UiState::CachedTarget(target));
    assert!(c.status().contains("缓存状态，切换时将重新验证"));
    assert!(h.calls.lock().unwrap().is_empty());
    c.handle(UiIntent::Configure(BootId(65535), Os::Windows));
    assert!(e.0.lock().unwrap().is_empty());
    c.handle(UiIntent::Switch);
    finish(&mut c, &h, &e, Err(ClientError::Cancelled));
    assert_eq!(
        *h.calls.lock().unwrap(),
        vec![Request::Switch { os: Os::Windows }]
    );
}
#[test]
fn cache_unavailable_is_local_failure_without_helper() {
    let (c, h, e, _) = setup(FakeCache {
        loaded: Err(CacheError::Unavailable),
        ..Default::default()
    });
    assert_eq!(c.state(), &UiState::Failed);
    assert!(c.status().contains("缓存"));
    assert!(h.calls.lock().unwrap().is_empty());
    assert!(e.0.lock().unwrap().is_empty());
}
#[test]
fn unique_or_named_candidate_never_auto_selects_or_configures() {
    let (mut c, h, e, _) = setup(FakeCache::default());
    inspect(&mut c, &h, &e, report());
    assert!(!c.can_configure());
    assert_eq!(c.selected(), None);
    c.confirm_windows(true);
    c.handle(UiIntent::Configure(BootId(7), Os::Windows));
    assert!(e.0.lock().unwrap().is_empty());
    assert_eq!(h.calls.lock().unwrap().len(), 1);
}
#[test]
fn configure_requires_matching_selection_and_explicit_confirmation() {
    let (mut c, h, e, cache) = setup(FakeCache::default());
    inspect(&mut c, &h, &e, report());
    assert!(c.select(BootId(7)));
    c.handle(UiIntent::Configure(BootId(7), Os::Windows));
    assert!(e.0.lock().unwrap().is_empty());
    c.confirm_windows(true);
    c.handle(UiIntent::Configure(BootId(8), Os::Windows));
    assert!(e.0.lock().unwrap().is_empty());
    c.handle(UiIntent::Configure(BootId(7), Os::Windows));
    let mut saved = report();
    saved.record = RecordDiagnostic::Ready {
        boot_id: BootId(7),
        os: Os::Windows,
    };
    saved.stages.push(Stage::TargetValidated);
    finish(&mut c, &h, &e, Ok(saved));
    assert_eq!(c.state(), &UiState::Configured);
    assert_eq!(cache.writes.lock().unwrap().len(), 1);
    assert_eq!(
        h.calls.lock().unwrap()[1],
        Request::Configure {
            boot_id: BootId(7),
            os: Os::Windows
        }
    );
}
#[test]
fn linux_configuration_fails_closed_for_wrong_os() {
    let (mut c, h, e, cache) = setup(FakeCache::default());
    inspect(&mut c, &h, &e, report());
    select(&mut c);
    c.handle(UiIntent::Configure(BootId(7), Os::Linux));
    assert_eq!(c.state(), &UiState::Failed);
    assert!(c.diagnostic().contains("UnexpectedOs"));
    assert!(e.0.lock().unwrap().is_empty());
    assert!(cache.writes.lock().unwrap().is_empty());
}
#[test]
fn unsupported_candidate_cannot_be_selected() {
    let (mut c, h, e, _) = setup(FakeCache::default());
    let mut r = report();
    r.candidates[0].classification = Classification::Unsupported;
    inspect(&mut c, &h, &e, r);
    assert!(!c.select(BootId(7)));
    c.confirm_windows(true);
    c.handle(UiIntent::Configure(BootId(7), Os::Windows));
    assert!(!c.can_configure());
    assert!(e.0.lock().unwrap().is_empty());
}
#[test]
fn ambiguous_candidate_requires_manual_selection_and_confirmation() {
    let (mut c, h, e, _) = setup(FakeCache::default());
    let mut r = report();
    r.candidates[0].ambiguous = true;
    inspect(&mut c, &h, &e, r);
    assert_eq!(c.selected(), None);
    assert!(!c.can_configure());
    assert!(c.select(BootId(7)));
    assert!(!c.can_configure());
    c.confirm_windows(true);
    assert!(c.can_configure());
    c.handle(UiIntent::Configure(BootId(7), Os::Windows));
    assert_eq!(e.0.lock().unwrap().len(), 1);
}
#[test]
fn changed_target_requires_fresh_inspect_selection_and_confirmation() {
    for error in [
        Error::IdentityMismatch,
        Error::TargetMissing,
        nested(Error::IdentityMismatch),
        nested(Error::TargetMissing),
    ] {
        let (mut c, h, e, cache) = setup(FakeCache::default());
        inspect(&mut c, &h, &e, report());
        select(&mut c);
        c.handle(UiIntent::Switch);
        finish(&mut c, &h, &e, Err(ClientError::Domain(error)));
        assert_eq!(c.state(), &UiState::TargetChanged);
        assert_eq!(c.status(), "目标启动配置已变化，请重新选择并确认目标。");
        assert!(c.candidates().is_empty());
        assert!(!c.select(BootId(7)));
        c.handle(UiIntent::Configure(BootId(7), Os::Windows));
        assert!(e.0.lock().unwrap().is_empty());
        assert!(cache.writes.lock().unwrap().is_empty());
        inspect(&mut c, &h, &e, report());
        assert!(!c.can_configure());
        select(&mut c);
        c.handle(UiIntent::Configure(BootId(7), Os::Windows));
        assert_eq!(e.0.lock().unwrap().len(), 1);
    }
}
#[test]
fn durability_unknown_preserves_errno_and_only_allows_explicit_inspect() {
    for error in [
        Error::StoreDurabilityUnknown { raw_code: 5 },
        nested(Error::StoreDurabilityUnknown { raw_code: 28 }),
    ] {
        let expected = if matches!(error, Error::FlowFailure { .. }) {
            28
        } else {
            5
        };
        let (mut c, h, e, cache) = setup(FakeCache::default());
        inspect(&mut c, &h, &e, report());
        select(&mut c);
        c.handle(UiIntent::Configure(BootId(7), Os::Windows));
        finish(&mut c, &h, &e, Err(ClientError::Domain(error)));
        assert_eq!(
            c.state(),
            &UiState::StoreDurabilityUnknown { raw_code: expected }
        );
        assert_eq!(
            c.status(),
            "配置已替换，但持久化结果未知。请先检查当前配置，勿重复保存。"
        );
        assert!(cache.writes.lock().unwrap().is_empty());
        assert!(!c.configuration_visible());
        c.handle(UiIntent::Switch);
        c.handle(UiIntent::Configure(BootId(7), Os::Windows));
        assert!(e.0.lock().unwrap().is_empty());
        c.handle(UiIntent::Inspect);
        assert_eq!(e.0.lock().unwrap().len(), 1);
    }
}
#[test]
fn uncertain_configure_never_writes_cache_or_replays() {
    let (mut c, h, e, cache) = setup(FakeCache::default());
    inspect(&mut c, &h, &e, report());
    select(&mut c);
    c.handle(UiIntent::Configure(BootId(7), Os::Windows));
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::UnknownAfterSend(TransportError::Timeout)),
    );
    assert_eq!(c.state(), &UiState::UnknownResult);
    assert!(c.status().contains("BootNext"));
    assert!(c.diagnostic().contains("UnknownAfterSend"));
    c.handle(UiIntent::Switch);
    c.handle(UiIntent::Configure(BootId(7), Os::Windows));
    assert!(e.0.lock().unwrap().is_empty());
    assert!(cache.writes.lock().unwrap().is_empty());
}
#[test]
fn accepted_and_unknown_reports_have_distinct_claims_and_stages() {
    for (stage, state, message) in [
        (
            Stage::RebootAccepted,
            UiState::RebootRequested,
            "重启请求已被系统接受",
        ),
        (Stage::RebootUnknown, UiState::UnknownResult, "BootNext"),
    ] {
        let (mut c, h, e, cache) = setup(FakeCache::default());
        c.handle(UiIntent::Switch);
        let mut r = report();
        r.stages = vec![Stage::TargetValidated, Stage::BootNextVerified, stage];
        finish(&mut c, &h, &e, Ok(r));
        assert_eq!(c.state(), &state);
        assert!(c.status().contains(message));
        assert!(c.diagnostic().contains("BootNext 已验证"));
        assert!(!c.status().contains("已进入"));
        assert!(cache.writes.lock().unwrap().is_empty());
    }
}
#[test]
fn rejected_report_or_flow_failure_never_claims_reboot_accepted() {
    for result in [
        Err(ClientError::Domain(nested(Error::RebootRejected))),
        Ok(Report {
            stages: vec![
                Stage::BootNextVerified,
                Stage::RebootRejected,
                Stage::ResidualPossible,
            ],
            ..report()
        }),
    ] {
        let (mut c, h, e, cache) = setup(FakeCache::default());
        c.handle(UiIntent::Switch);
        finish(&mut c, &h, &e, result);
        assert_eq!(c.state(), &UiState::Failed);
        assert!(c.diagnostic().contains("RebootRejected"));
        assert!(c.diagnostic().contains("可能残留"));
        assert!(!c.status().contains("已被系统接受"));
        assert!(cache.writes.lock().unwrap().is_empty());
    }
}
#[test]
fn all_determinate_errors_preserve_category_without_cache_writes() {
    for error in [
        Error::MalformedLoadOption,
        Error::MalformedDevicePath,
        Error::ResourceLimit,
        Error::UnsupportedFormat,
        Error::CorruptRecord,
        Error::UnexpectedOs,
        Error::NotConfigured,
        Error::BootNextConflict,
        Error::Busy,
        Error::ReadbackFailed,
        Error::RebootRejected,
        Error::PlatformIo {
            operation: "write".into(),
            raw_code: 13,
        },
    ] {
        for wrapped in [false, true] {
            let (mut c, h, e, cache) = setup(FakeCache::default());
            c.handle(UiIntent::Switch);
            finish(
                &mut c,
                &h,
                &e,
                Err(ClientError::Domain(if wrapped {
                    nested(error.clone())
                } else {
                    error.clone()
                })),
            );
            assert_eq!(c.state(), &UiState::Failed);
            assert!(!c.diagnostic().is_empty());
            assert!(cache.writes.lock().unwrap().is_empty());
        }
    }
}
#[test]
fn client_failures_preserve_phase_and_dont_replay() {
    for (error, diagnostic) in [
        (ClientError::Cancelled, "Cancelled"),
        (
            ClientError::AuthorizationOrLaunchFailed,
            "AuthorizationOrLaunchFailed",
        ),
        (ClientError::BeforeSend(TransportError::Io), "BeforeSend"),
        (ClientError::BeforeSend(TransportError::Launch), "Launch"),
    ] {
        let (mut c, h, e, cache) = setup(FakeCache::default());
        c.handle(UiIntent::Inspect);
        finish(&mut c, &h, &e, Err(error));
        assert_eq!(c.state(), &UiState::Failed);
        assert!(c.diagnostic().contains(diagnostic));
        assert!(e.0.lock().unwrap().is_empty());
        assert!(cache.writes.lock().unwrap().is_empty());
    }
}
#[test]
fn inspect_record_is_display_only_and_does_not_update_cache() {
    let (mut c, h, e, cache) = setup(FakeCache::default());
    let mut r = report();
    r.record = RecordDiagnostic::Ready {
        boot_id: BootId(7),
        os: Os::Windows,
    };
    inspect(&mut c, &h, &e, r);
    assert_eq!(c.state(), &UiState::Configured);
    assert!(c.status().contains("未验证启动链"));
    assert!(cache.writes.lock().unwrap().is_empty());
}
#[test]
fn cache_write_failure_does_not_reverse_configure_success() {
    let (mut c, h, e, cache) = setup(FakeCache {
        fail_write: true,
        ..Default::default()
    });
    inspect(&mut c, &h, &e, report());
    select(&mut c);
    c.handle(UiIntent::Configure(BootId(7), Os::Windows));
    finish(
        &mut c,
        &h,
        &e,
        Ok(Report {
            record: RecordDiagnostic::Ready {
                boot_id: BootId(7),
                os: Os::Windows,
            },
            stages: vec![Stage::TargetValidated],
            ..report()
        }),
    );
    assert_eq!(c.state(), &UiState::Configured);
    assert!(c.cache_warning().is_some());
    assert_eq!(cache.writes.lock().unwrap().len(), 1);
    assert!(e.0.lock().unwrap().is_empty());
}
#[test]
fn malformed_success_does_not_write_cache_or_claim_reboot() {
    let (mut c, h, e, cache) = setup(FakeCache::default());
    inspect(&mut c, &h, &e, report());
    select(&mut c);
    c.handle(UiIntent::Configure(BootId(7), Os::Windows));
    finish(&mut c, &h, &e, Ok(report()));
    assert_eq!(c.state(), &UiState::UnknownResult);
    assert!(c.diagnostic().contains("UnknownAfterSend"));
    assert!(cache.writes.lock().unwrap().is_empty());
    let (mut c, h, e, _) = setup(FakeCache::default());
    c.handle(UiIntent::Switch);
    finish(&mut c, &h, &e, Ok(report()));
    assert_eq!(c.state(), &UiState::UnknownResult);
}
#[test]
fn public_diagnostics_are_bounded_and_redact_untrusted_operation_strings() {
    let (mut c, h, e, _) = setup(FakeCache::default());
    c.handle(UiIntent::Switch);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::Domain(nested(Error::PlatformIo {
            operation: "secret identity digest OptionalData\n".repeat(10000),
            raw_code: 42,
        }))),
    );
    assert!(c.diagnostic().len() <= 4096);
    assert!(!c.diagnostic().contains("secret"));
    assert!(c.diagnostic().contains("42"));
    assert!(c.diagnostic().contains("5"));
}
#[test]
fn completion_notifies_but_only_poll_mutates_ui_state() {
    let h = FakeHelper::default();
    let e = Manual::default();
    let wakes = Arc::new(Mutex::new(0));
    let w = wakes.clone();
    let mut c = Controller::new(
        h.clone(),
        e.clone(),
        FakeCache::default(),
        Arc::new(move || *w.lock().unwrap() += 1),
    );
    c.handle(UiIntent::Inspect);
    h.replies.lock().unwrap().push_back(Ok(report()));
    e.finish();
    assert_eq!(c.state(), &UiState::Busy);
    assert_eq!(*wakes.lock().unwrap(), 1);
    c.poll();
    assert_eq!(c.state(), &UiState::Unconfigured);
}

#[test]
fn failed_inspect_does_not_unlock_an_uncertain_or_unsupported_record() {
    for error in [
        Error::StoreDurabilityUnknown { raw_code: 5 },
        Error::UnsupportedIdentityComponent,
        Error::IdentityMismatch,
    ] {
        let (mut c, h, e, _) = setup(FakeCache::default());
        c.handle(UiIntent::Inspect);
        finish(&mut c, &h, &e, Err(ClientError::Domain(error)));
        c.handle(UiIntent::Inspect);
        finish(&mut c, &h, &e, Err(ClientError::Cancelled));
        assert!(!c.can_switch());
        assert!(!c.configuration_visible());
        c.handle(UiIntent::Switch);
        assert!(e.0.lock().unwrap().is_empty());
        inspect(&mut c, &h, &e, report());
        assert!(c.configuration_visible());
    }
}

#[test]
fn executor_failure_is_before_send_and_never_runs_helper() {
    struct Reject;
    impl Executor for Reject {
        fn execute(&self, _: Job) -> Result<(), ScheduleError> {
            Err(ScheduleError)
        }
    }
    let h = FakeHelper::default();
    let mut c = Controller::new(h.clone(), Reject, FakeCache::default(), Arc::new(|| {}));
    c.handle(UiIntent::Switch);
    assert_eq!(c.state(), &UiState::Failed);
    assert!(c.diagnostic().contains("BeforeSend"));
    assert!(h.calls.lock().unwrap().is_empty());
}

#[test]
fn thread_executor_runs_only_fake_helper_away_from_ui_thread() {
    use boothop_gui::controller::ThreadExecutor;
    struct ThreadHelper(std::sync::mpsc::Sender<std::thread::ThreadId>);
    impl Helper for ThreadHelper {
        fn run(&mut self, _: Request) -> Result<Report, ClientError> {
            self.0.send(std::thread::current().id()).unwrap();
            Ok(report())
        }
    }
    let (id_tx, id_rx) = std::sync::mpsc::channel();
    let (wake_tx, wake_rx) = std::sync::mpsc::channel();
    let mut c = Controller::new(
        ThreadHelper(id_tx),
        ThreadExecutor,
        FakeCache::default(),
        Arc::new(move || {
            wake_tx.send(()).unwrap();
        }),
    );
    c.handle(UiIntent::Inspect);
    assert_ne!(
        id_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap(),
        std::thread::current().id()
    );
    wake_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert_eq!(c.state(), &UiState::Busy);
    c.poll();
    assert_eq!(c.state(), &UiState::Unconfigured);
}

#[test]
fn deeply_nested_unsupported_cause_and_busy_inspect_keep_recovery_hidden() {
    let (mut c, h, e, _) = setup(FakeCache::default());
    let mut error = Error::UnsupportedIdentityComponent;
    for _ in 0..12 {
        error = nested(error);
    }
    c.handle(UiIntent::Inspect);
    finish(&mut c, &h, &e, Err(ClientError::Domain(error)));
    assert_eq!(c.state(), &UiState::UnsupportedRecord);
    c.handle(UiIntent::Inspect);
    assert_eq!(c.state(), &UiState::Busy);
    assert!(!c.configuration_visible());
    finish(&mut c, &h, &e, Err(ClientError::Cancelled));
    assert_eq!(c.state(), &UiState::UnsupportedRecord);
}

#[test]
fn inspect_cannot_claim_reboot_and_deep_durability_keeps_primary_errno() {
    let (mut c, h, e, _) = setup(FakeCache::default());
    c.handle(UiIntent::Inspect);
    finish(
        &mut c,
        &h,
        &e,
        Ok(Report {
            stages: vec![Stage::RebootAccepted],
            ..report()
        }),
    );
    assert_eq!(c.state(), &UiState::UnknownResult);
    assert!(!c.diagnostic().contains("已被系统接受"));
    let (mut c, h, e, _) = setup(FakeCache::default());
    let mut error = Error::StoreDurabilityUnknown { raw_code: 12345 };
    for _ in 0..12 {
        error = nested(error);
    }
    c.handle(UiIntent::Inspect);
    finish(&mut c, &h, &e, Err(ClientError::Domain(error)));
    assert_eq!(
        c.state(),
        &UiState::StoreDurabilityUnknown { raw_code: 12345 }
    );
    assert!(c.diagnostic().contains("12345"));
}

#[test]
fn successful_switch_displays_report_target_without_rewriting_cache() {
    for outcome in [Stage::RebootAccepted, Stage::RebootUnknown] {
        let (mut c, h, e, cache) = setup(FakeCache {
            loaded: Ok(Some(CachedTarget {
                boot_id: BootId(65535),
                os: Os::Windows,
                description_utf16: None,
            })),
            ..Default::default()
        });
        c.handle(UiIntent::Switch);
        finish(
            &mut c,
            &h,
            &e,
            Ok(Report {
                record: RecordDiagnostic::Ready {
                    boot_id: BootId(7),
                    os: Os::Windows,
                },
                stages: vec![Stage::TargetValidated, Stage::BootNextVerified, outcome],
                ..report()
            }),
        );
        assert_eq!(c.target().unwrap().boot_id, BootId(7));
        assert!(cache.writes.lock().unwrap().is_empty());
    }
}
