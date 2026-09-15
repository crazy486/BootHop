use boothop_core::Error;
use boothop_platform::windows::privilege::{
    ERROR_NOT_ALL_ASSIGNED, Luid, Privilege, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, TokenCalls,
    TokenHandle, TokenPrivileges, with_system_environment_privilege,
};

#[derive(Debug)]
struct FakeToken {
    open: Result<TokenHandle, i32>,
    lookup: Result<Luid, i32>,
    enable_success: bool,
    enable_error: i32,
    prior: TokenPrivileges,
    restore_success: bool,
    restore_error: i32,
    close_success: bool,
    close_count: usize,
    adjustments: Vec<TokenPrivileges>,
    events: Vec<&'static str>,
}

impl FakeToken {
    fn ready() -> Self {
        Self {
            open: Ok(TokenHandle(7)),
            lookup: Ok(Luid(11)),
            enable_success: true,
            enable_error: 0,
            prior: TokenPrivileges::single(Luid(11), 0),
            restore_success: true,
            restore_error: 0,
            close_success: true,
            close_count: 0,
            adjustments: Vec::new(),
            events: Vec::new(),
        }
    }
}

impl TokenCalls for FakeToken {
    fn open_process_token(&mut self, desired_access: u32) -> Result<TokenHandle, i32> {
        assert_eq!(desired_access, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY);
        self.events.push("open");
        self.open
    }

    fn lookup_privilege_value(&mut self, privilege: Privilege) -> Result<Luid, i32> {
        assert_eq!(privilege, Privilege::SystemEnvironment);
        self.events.push("lookup");
        self.lookup
    }

    fn set_last_error(&mut self, code: i32) {
        assert_eq!(code, 0);
        self.events.push("set-last-error");
    }

    fn last_error(&mut self) -> i32 {
        self.events.push("get-last-error");
        if self.adjustments.len() <= 1 {
            self.enable_error
        } else {
            self.restore_error
        }
    }

    fn adjust_token_privileges(
        &mut self,
        _: TokenHandle,
        new_state: &TokenPrivileges,
        previous_state: &mut TokenPrivileges,
    ) -> bool {
        self.events.push("adjust");
        self.adjustments.push(new_state.clone());
        if self.adjustments.len() == 1 {
            *previous_state = self.prior.clone();
            self.enable_success
        } else {
            self.restore_success
        }
    }

    fn close_handle(&mut self, _: TokenHandle) -> Result<(), i32> {
        self.events.push("close");
        self.close_count += 1;
        if self.close_success {
            Ok(())
        } else {
            Err(self.restore_error)
        }
    }
}

#[test]
fn absent_privilege_fails_closed_and_closes_once() {
    let mut fake = FakeToken::ready();
    fake.lookup = Err(1313);
    assert_eq!(
        with_system_environment_privilege(&mut fake, |_| Ok::<_, Error>(())),
        Err(Error::PrivilegeUnavailable)
    );
    assert_eq!(fake.close_count, 1);
    assert!(!fake.events.contains(&"adjust"));
}

#[test]
fn lookup_failure_is_returned_and_closes_once() {
    let mut fake = FakeToken::ready();
    fake.lookup = Err(5);
    assert_eq!(
        with_system_environment_privilege(&mut fake, |_| Ok::<_, Error>(())),
        Err(Error::PrivilegeEnableFailed { raw_code: 5 })
    );
    assert_eq!(fake.close_count, 1);
}

#[test]
fn not_all_assigned_fails_closed_and_restores_prior_state() {
    let mut fake = FakeToken::ready();
    fake.enable_error = ERROR_NOT_ALL_ASSIGNED;
    assert_eq!(
        with_system_environment_privilege(&mut fake, |_| Ok::<_, Error>(())),
        Err(Error::PrivilegeEnableFailed {
            raw_code: ERROR_NOT_ALL_ASSIGNED,
        })
    );
    assert_eq!(fake.adjustments.len(), 2);
    assert_eq!(fake.adjustments[1], fake.prior);
    assert_eq!(fake.close_count, 1);
}

#[test]
fn already_enabled_and_enable_success_restore_the_complete_prior_state() {
    for prior in [
        TokenPrivileges::single(Luid(11), 2),
        TokenPrivileges::new(vec![(Luid(11), 0), (Luid(99), 1)]),
    ] {
        let mut fake = FakeToken::ready();
        fake.prior = prior.clone();
        let result = with_system_environment_privilege(&mut fake, |_| Ok::<_, Error>(42));
        assert_eq!(result, Ok(42));
        assert_eq!(fake.adjustments.last(), Some(&prior));
        assert_eq!(fake.close_count, 1);
    }
}

#[test]
fn operation_error_still_restores_and_restore_failure_wins() {
    let mut fake = FakeToken::ready();
    assert_eq!(
        with_system_environment_privilege(&mut fake, |_| {
            Err::<(), _>(Error::FirmwareReadFailed { raw_code: 55 })
        }),
        Err(Error::FirmwareReadFailed { raw_code: 55 })
    );

    let mut fake = FakeToken::ready();
    fake.restore_success = false;
    fake.restore_error = 77;
    assert_eq!(
        with_system_environment_privilege(&mut fake, |_| {
            Err::<(), _>(Error::FirmwareReadFailed { raw_code: 55 })
        }),
        Err(Error::PrivilegeRestoreFailed { raw_code: 77 })
    );
    assert_eq!(fake.close_count, 1);
}

#[test]
fn native_backend_is_not_constructed_by_fake_tests() {
    // This test intentionally exercises only the injected TokenCalls seam.
    let mut fake = FakeToken::ready();
    assert_eq!(
        with_system_environment_privilege(&mut fake, |_| Ok::<_, Error>(())),
        Ok(())
    );
}

#[test]
fn native_surface_is_fixed_direct_imports_and_has_no_process_or_reboot_path() {
    let firmware = include_str!("../src/windows/firmware.rs");
    let privilege = include_str!("../src/windows/privilege.rs");
    assert!(firmware.contains("GetFirmwareEnvironmentVariableExW"));
    assert!(firmware.contains("SetFirmwareEnvironmentVariableExW"));
    assert!(firmware.contains("GetFirmwareType"));
    assert!(firmware.contains("GLOBAL_VARIABLE_GUID"));
    assert_eq!(
        firmware
            .matches("SetFirmwareEnvironmentVariableExW")
            .count(),
        3,
        "one import, one private BootNext call, and its boundary comment"
    );
    assert!(privilege.contains("AdjustTokenPrivileges"));
    assert!(privilege.contains("LookupPrivilegeValueW"));
    assert!(privilege.contains("OpenProcessToken"));
    assert!(privilege.contains("CloseHandle"));
    assert!(privilege.contains("SetLastError"));
    assert!(privilege.contains("GetLastError"));
    for forbidden in [
        "LoadLibrary",
        "GetProcAddress",
        "CreateProcess",
        "ShellExecute",
        "bcdedit",
        "InitiateSystemShutdown",
        "ExitWindows",
    ] {
        assert!(
            !firmware.contains(forbidden),
            "forbidden API in firmware: {forbidden}"
        );
        assert!(
            !privilege.contains(forbidden),
            "forbidden API in privilege: {forbidden}"
        );
    }
    assert_eq!(
        boothop_platform::windows::GLOBAL_VARIABLE_GUID,
        "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
    );
}
