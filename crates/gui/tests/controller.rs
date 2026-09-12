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
fn switched(outcome: Stage) -> Report {
    let stages = if outcome == Stage::RebootUnknown {
        vec![
            Stage::TargetValidated,
            Stage::BootNextVerified,
            Stage::RebootUnknown,
            Stage::ResidualPossible,
        ]
    } else {
        vec![Stage::TargetValidated, Stage::BootNextVerified, outcome]
    };
    Report {
        record: RecordDiagnostic::Ready {
            boot_id: BootId(7),
            os: Os::Windows,
        },
        stages,
        ..report()
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
        // This fixture models a pre-mutation validation failure. Mutation
        // evidence is covered separately by the accepted/unknown tests.
        stages: vec![Stage::TargetValidated],
        residual_assessment: ResidualAssessment::NotChecked,
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
        finish(&mut c, &h, &e, Ok(switched(stage)));
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
        let domain_failure = result.is_err();
        finish(&mut c, &h, &e, result);
        if domain_failure {
            assert_eq!(c.state(), &UiState::Failed);
            assert!(c.diagnostic().contains("RebootRejected"));
            assert!(!c.diagnostic().contains("已被系统接受"));
        } else {
            assert_eq!(c.state(), &UiState::UnknownResult);
            assert_eq!(c.diagnostic(), "UnknownAfterSend: Protocol");
        }
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
            ClientError::AuthorizationOrLaunchFailed { raw_code: 127 },
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
fn authorization_launch_exit_127_is_neutral_and_explicitly_not_sent() {
    let (mut c, h, e, cache) = setup(FakeCache::default());
    c.handle(UiIntent::Inspect);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::AuthorizationOrLaunchFailed { raw_code: 127 }),
    );
    assert_eq!(c.state(), &UiState::Failed);
    assert_eq!(c.status(), "授权未完成或 helper 启动失败；请求尚未发送。");
    assert!(c.diagnostic().contains("127"));
    assert!(c.diagnostic().contains("请求尚未发送"));
    assert!(!c.diagnostic().contains("取消"));
    assert!(cache.writes.lock().unwrap().is_empty());
    assert!(e.0.lock().unwrap().is_empty());
}

#[test]
fn prehello_127_overrides_target_changed_recovery_status_without_unlocking() {
    let (mut c, h, e, cache) = setup(FakeCache::default());
    c.handle(UiIntent::Switch);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::Domain(Error::IdentityMismatch)),
    );
    assert_eq!(c.state(), &UiState::TargetChanged);

    c.handle(UiIntent::Inspect);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::AuthorizationOrLaunchFailed { raw_code: 127 }),
    );
    assert_eq!(c.state(), &UiState::TargetChanged);
    assert_eq!(c.status(), "授权未完成或 helper 启动失败；请求尚未发送。");
    assert!(c.diagnostic().contains("127"));
    assert!(c.diagnostic().contains("请求尚未发送"));
    assert!(cache.writes.lock().unwrap().is_empty());
}

#[test]
fn prehello_127_overrides_unsupported_record_recovery_status_without_unlocking() {
    let (mut c, h, e, cache) = setup(FakeCache::default());
    c.handle(UiIntent::Inspect);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::Domain(Error::UnsupportedIdentityComponent)),
    );
    assert_eq!(c.state(), &UiState::UnsupportedRecord);

    c.handle(UiIntent::Inspect);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::AuthorizationOrLaunchFailed { raw_code: 127 }),
    );
    assert_eq!(c.state(), &UiState::UnsupportedRecord);
    assert_eq!(c.status(), "授权未完成或 helper 启动失败；请求尚未发送。");
    assert!(c.diagnostic().contains("127"));
    assert!(c.diagnostic().contains("请求尚未发送"));
    assert!(cache.writes.lock().unwrap().is_empty());
}

#[test]
fn invalid_configure_does_not_clear_prehello_127_notice_or_schedule_work() {
    let (mut c, h, e, cache) = setup(FakeCache::default());
    c.handle(UiIntent::Inspect);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::AuthorizationOrLaunchFailed { raw_code: 127 }),
    );
    let status = c.status();
    let diagnostic = c.diagnostic().to_owned();
    assert_eq!(status, "授权未完成或 helper 启动失败；请求尚未发送。");
    assert!(diagnostic.contains("127"));
    assert!(diagnostic.contains("请求尚未发送"));

    c.handle(UiIntent::Configure(BootId(999), Os::Windows));

    assert_eq!(c.state(), &UiState::Failed);
    assert_eq!(c.status(), status);
    assert_eq!(c.diagnostic(), diagnostic);
    assert!(e.0.lock().unwrap().is_empty());
    assert!(cache.writes.lock().unwrap().is_empty());
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
        finish(&mut c, &h, &e, Ok(switched(outcome)));
        assert_eq!(c.target().unwrap().boot_id, BootId(7));
        assert!(cache.writes.lock().unwrap().is_empty());
    }
}

fn reject_success(intent: UiIntent, response: Report) {
    let (mut c, h, e, cache) = setup(FakeCache {
        loaded: Ok(Some(CachedTarget {
            boot_id: BootId(99),
            os: Os::Windows,
            description_utf16: None,
        })),
        ..Default::default()
    });
    if matches!(intent, UiIntent::Configure(..)) {
        inspect(&mut c, &h, &e, report());
        select(&mut c);
    }
    let displayed = c.target().cloned();
    c.handle(intent);
    finish(&mut c, &h, &e, Ok(response));
    assert_eq!(c.state(), &UiState::UnknownResult);
    assert_eq!(
        c.target(),
        displayed.as_ref(),
        "invalid report changed display target"
    );
    assert_eq!(c.diagnostic(), "UnknownAfterSend: Protocol");
    assert!(cache.writes.lock().unwrap().is_empty());
    assert!(c.candidates().is_empty());
    assert!(!c.configuration_visible());
    assert!(!c.can_switch());
    c.handle(UiIntent::Switch);
    c.handle(UiIntent::Configure(BootId(7), Os::Windows));
    assert!(e.0.lock().unwrap().is_empty());
    c.handle(UiIntent::Inspect);
    finish(&mut c, &h, &e, Err(ClientError::Cancelled));
    assert_eq!(c.state(), &UiState::UnknownResult);
    assert!(!c.can_switch());
}

#[test]
fn switch_success_requires_ready_windows_and_one_supported_target_candidate() {
    let valid = switched(Stage::RebootAccepted);
    let mut missing = valid.clone();
    missing.record = RecordDiagnostic::Missing;
    let mut wrong_os = valid.clone();
    wrong_os.record = RecordDiagnostic::Ready {
        boot_id: BootId(7),
        os: Os::Linux,
    };
    let mut absent = valid.clone();
    absent.candidates.clear();
    let mut unsupported = valid.clone();
    unsupported.candidates[0].classification = Classification::Unsupported;
    let mut duplicate = valid.clone();
    duplicate.candidates.push(duplicate.candidates[0].clone());
    for invalid in [missing, wrong_os, absent, unsupported, duplicate] {
        reject_success(UiIntent::Switch, invalid);
    }
}

#[test]
fn switch_success_rejects_missing_unordered_duplicate_and_contradictory_stages() {
    use Stage::*;
    for stages in [
        vec![],
        vec![RebootAccepted],
        vec![BootNextVerified, RebootAccepted],
        vec![TargetValidated, RebootAccepted],
        vec![TargetValidated, BootNextVerified],
        vec![BootNextVerified, TargetValidated, RebootAccepted],
        vec![
            TargetValidated,
            BootNextVerified,
            RebootAccepted,
            RebootAccepted,
        ],
        vec![
            TargetValidated,
            TargetValidated,
            BootNextVerified,
            RebootAccepted,
        ],
        vec![
            TargetValidated,
            BootNextVerified,
            BootNextVerified,
            RebootAccepted,
        ],
        vec![
            TargetValidated,
            BootNextVerified,
            RebootAccepted,
            ResidualPossible,
        ],
        vec![
            TargetValidated,
            BootNextVerified,
            RebootAccepted,
            RebootUnknown,
        ],
        vec![TargetValidated, BootNextVerified, RebootRejected],
        vec![TargetValidated, BootNextVerified, RebootUnknown],
        vec![
            TargetValidated,
            BootNextVerified,
            ResidualPossible,
            RebootUnknown,
        ],
        vec![BootNextVerified, RebootUnknown, ResidualPossible],
        vec![TargetValidated, RebootUnknown, ResidualPossible],
        vec![
            TargetValidated,
            BootNextVerified,
            RebootUnknown,
            ResidualPossible,
            ResidualPossible,
        ],
    ] {
        reject_success(
            UiIntent::Switch,
            Report {
                stages,
                ..switched(RebootAccepted)
            },
        );
    }
}

#[test]
fn configure_success_requires_exact_record_candidate_and_single_validated_stage() {
    let valid = Report {
        stages: vec![Stage::TargetValidated],
        ..switched(Stage::RebootAccepted)
    };
    let mut missing = valid.clone();
    missing.record = RecordDiagnostic::Missing;
    let mut wrong_os = valid.clone();
    wrong_os.record = RecordDiagnostic::Ready {
        boot_id: BootId(7),
        os: Os::Linux,
    };
    let mut wrong_id = valid.clone();
    wrong_id.record = RecordDiagnostic::Ready {
        boot_id: BootId(8),
        os: Os::Windows,
    };
    let mut absent = valid.clone();
    absent.candidates.clear();
    let mut unsupported = valid.clone();
    unsupported.candidates[0].classification = Classification::Unsupported;
    let mut duplicate = valid.clone();
    duplicate.candidates.push(duplicate.candidates[0].clone());
    for invalid in [missing, wrong_os, wrong_id, absent, unsupported, duplicate] {
        reject_success(UiIntent::Configure(BootId(7), Os::Windows), invalid);
    }
    for stages in [
        vec![],
        vec![Stage::TargetValidated, Stage::TargetValidated],
        vec![Stage::BootNextVerified],
        vec![Stage::TargetValidated, Stage::RebootRejected],
        vec![Stage::TargetValidated, Stage::RebootAccepted],
        vec![
            Stage::TargetValidated,
            Stage::RebootUnknown,
            Stage::ResidualPossible,
        ],
    ] {
        reject_success(
            UiIntent::Configure(BootId(7), Os::Windows),
            Report {
                stages,
                ..valid.clone()
            },
        );
    }
}

#[test]
fn inspect_wrong_os_or_any_stages_are_protocol_unknown_before_display_update() {
    reject_success(
        UiIntent::Inspect,
        Report {
            record: RecordDiagnostic::Ready {
                boot_id: BootId(7),
                os: Os::Linux,
            },
            ..report()
        },
    );
    for stage in [
        Stage::TargetValidated,
        Stage::BootNextVerified,
        Stage::RebootAccepted,
        Stage::RebootRejected,
        Stage::RebootUnknown,
        Stage::ResidualPossible,
    ] {
        reject_success(
            UiIntent::Inspect,
            Report {
                stages: vec![stage],
                ..report()
            },
        );
    }
}

#[test]
fn inspect_changed_target_allows_fresh_explicit_reselection_but_never_switch() {
    for unsupported in [false, true] {
        let (mut c, h, e, cache) = setup(FakeCache::default());
        let mut r = report();
        r.record = RecordDiagnostic::Ready {
            boot_id: BootId(99),
            os: Os::Windows,
        };
        if unsupported {
            r.candidates.push(Candidate {
                boot_id: BootId(99),
                classification: Classification::Unsupported,
                ..r.candidates[0].clone()
            });
        }
        inspect(&mut c, &h, &e, r);
        assert_eq!(c.state(), &UiState::TargetChanged);
        assert!(c.configuration_visible());
        assert!(!c.can_switch());
        assert!(!c.can_configure());
        c.handle(UiIntent::Switch);
        assert!(e.0.lock().unwrap().is_empty());
        assert!(c.select(BootId(7)));
        c.handle(UiIntent::Configure(BootId(7), Os::Windows));
        assert!(e.0.lock().unwrap().is_empty());
        c.confirm_windows(true);
        assert!(c.can_configure());
        c.handle(UiIntent::Configure(BootId(7), Os::Windows));
        finish(
            &mut c,
            &h,
            &e,
            Ok(Report {
                stages: vec![Stage::TargetValidated],
                ..switched(Stage::RebootAccepted)
            }),
        );
        assert_eq!(c.state(), &UiState::Configured);
        assert!(c.can_switch());
        assert_eq!(cache.writes.lock().unwrap().len(), 1);
    }
}

#[test]
fn prior_identity_change_is_not_cleared_by_inspect_display_only_evidence() {
    let (mut c, h, e, _) = setup(FakeCache::default());
    c.handle(UiIntent::Switch);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::Domain(Error::IdentityMismatch)),
    );
    inspect(
        &mut c,
        &h,
        &e,
        Report {
            stages: vec![],
            ..switched(Stage::RebootAccepted)
        },
    );
    assert_eq!(c.state(), &UiState::TargetChanged);
    assert!(!c.can_switch());
    assert!(c.can_select());
    assert!(!c.can_configure());
    c.handle(UiIntent::Inspect);
    finish(&mut c, &h, &e, Err(ClientError::Cancelled));
    assert_eq!(c.state(), &UiState::TargetChanged);
    assert!(!c.can_select());
    assert!(!c.can_switch());
}

fn supported_same_id_inspect() -> Report {
    Report {
        record: RecordDiagnostic::Ready {
            boot_id: BootId(7),
            os: Os::Windows,
        },
        ..report()
    }
}

#[test]
fn changed_target_latch_survives_unknown_configure_then_supported_inspect() {
    let (mut c, h, e, _) = setup(FakeCache::default());
    c.handle(UiIntent::Switch);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::Domain(Error::IdentityMismatch)),
    );
    assert_eq!(c.state(), &UiState::TargetChanged);

    inspect(&mut c, &h, &e, supported_same_id_inspect());
    select(&mut c);
    c.handle(UiIntent::Configure(BootId(7), Os::Windows));
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::UnknownAfterSend(TransportError::Timeout)),
    );
    assert_eq!(c.state(), &UiState::UnknownResult);
    assert!(c.diagnostic().contains("UnknownAfterSend"));

    inspect(&mut c, &h, &e, supported_same_id_inspect());
    assert_eq!(c.state(), &UiState::TargetChanged);
    assert!(!c.can_switch());
    assert!(c.diagnostic().contains("UnknownAfterSend"));
}

#[test]
fn changed_target_latch_survives_unknown_inspect_then_supported_inspect() {
    let (mut c, h, e, _) = setup(FakeCache::default());
    c.handle(UiIntent::Switch);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::Domain(Error::IdentityMismatch)),
    );
    assert_eq!(c.state(), &UiState::TargetChanged);

    c.handle(UiIntent::Inspect);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::UnknownAfterSend(TransportError::Timeout)),
    );
    assert_eq!(c.state(), &UiState::UnknownResult);
    assert!(c.diagnostic().contains("UnknownAfterSend"));

    inspect(&mut c, &h, &e, supported_same_id_inspect());
    assert_eq!(c.state(), &UiState::TargetChanged);
    assert!(!c.can_switch());
    assert!(c.diagnostic().contains("UnknownAfterSend"));
}

#[test]
fn changed_target_latch_preserves_unknown_or_failure_diagnostic() {
    for (error, reason) in [
        (
            ClientError::UnknownAfterSend(TransportError::Timeout),
            "UnknownAfterSend",
        ),
        (ClientError::Domain(Error::CorruptRecord), "CorruptRecord"),
    ] {
        let (mut c, h, e, _) = setup(FakeCache::default());
        c.handle(UiIntent::Switch);
        finish(
            &mut c,
            &h,
            &e,
            Err(ClientError::Domain(Error::IdentityMismatch)),
        );
        inspect(&mut c, &h, &e, supported_same_id_inspect());
        select(&mut c);
        c.handle(UiIntent::Configure(BootId(7), Os::Windows));
        finish(&mut c, &h, &e, Err(error));
        assert!(c.diagnostic().contains(reason));

        inspect(&mut c, &h, &e, supported_same_id_inspect());
        assert_eq!(c.state(), &UiState::TargetChanged);
        assert!(!c.can_switch());
        assert!(c.diagnostic().contains(reason));
    }
}

#[test]
fn only_determinate_configure_success_clears_changed_target_latch() {
    let (mut c, h, e, _) = setup(FakeCache::default());
    c.handle(UiIntent::Switch);
    finish(
        &mut c,
        &h,
        &e,
        Err(ClientError::Domain(Error::IdentityMismatch)),
    );
    inspect(&mut c, &h, &e, supported_same_id_inspect());
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
    assert!(c.can_switch());
}

#[test]
fn failed_reconfiguration_cannot_reenable_switch_for_a_known_changed_target() {
    for error in [ClientError::Cancelled, ClientError::Domain(Error::Busy)] {
        let (mut c, h, e, _) = setup(FakeCache::default());
        inspect(
            &mut c,
            &h,
            &e,
            Report {
                record: RecordDiagnostic::Ready {
                    boot_id: BootId(99),
                    os: Os::Windows,
                },
                ..report()
            },
        );
        select(&mut c);
        c.handle(UiIntent::Configure(BootId(7), Os::Windows));
        finish(&mut c, &h, &e, Err(error));
        assert_eq!(c.state(), &UiState::TargetChanged);
        assert!(!c.can_switch());
        assert!(!c.can_select());
    }
}
