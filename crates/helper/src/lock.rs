//! Operation lifetime integration; dispatch belongs to a later task.
use boothop_core::Error;
use boothop_platform::{
    ProtectedStore,
    linux::store::{Filesystem, LinuxStore, LockedStore},
};

#[cfg(test)]
#[path = "../../platform/tests/support/mod.rs"]
mod support;

/// The callback includes the full operation and its safe cleanup/reporting.
pub fn with_operation<F: Filesystem, T>(
    fs: F,
    operation: impl FnOnce(&mut dyn ProtectedStore) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut store = LockedStore::acquire(fs)?;
    operation(&mut store)
}

/// Production entry point: the installation location cannot be overridden by a caller.
pub fn with_linux_operation<T>(
    operation: impl FnOnce(&mut dyn ProtectedStore) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut store = LinuxStore::open()?;
    operation(&mut store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boothop_core::{
        BootId, LoadOption, Os, Platform, RebootOutcome, RecordState, Request, Stage, TargetRecord,
        execute,
    };

    struct Flow<'a> {
        store: &'a mut dyn ProtectedStore,
        fs: support::FakeFs,
        events: Vec<&'static str>,
    }
    impl Platform for Flow<'_> {
        fn load_record(&mut self) -> Result<RecordState, Error> {
            assert!(self.fs.held());
            self.store.load()
        }
        fn save_record(&mut self, t: &TargetRecord) -> Result<(), Error> {
            assert!(self.fs.held());
            self.store.save(t)
        }
        fn read_options(&mut self) -> Result<Vec<(BootId, LoadOption)>, Error> {
            assert!(self.fs.held());
            self.events.push("options");
            Ok(vec![(BootId(7), option())])
        }
        fn check_environment(&mut self) -> Result<(), Error> {
            assert!(self.fs.held());
            Ok(())
        }
        fn read_next(&mut self) -> Result<Option<BootId>, Error> {
            assert!(self.fs.held());
            self.events.push("next");
            Ok(None)
        }
        fn write_next(&mut self, _: BootId) -> Result<(), Error> {
            assert!(self.fs.held());
            self.events.push("write");
            Ok(())
        }
        fn reboot(&mut self) -> RebootOutcome {
            assert!(self.fs.held());
            self.events.push("reboot");
            RebootOutcome::Accepted
        }
    }
    fn option() -> LoadOption {
        let hex = include_str!("../../../fixtures/uefi/synthetic/task1-shape.hex").trim();
        let bytes: Vec<_> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        boothop_core::parse_load_option(&bytes).unwrap()
    }

    #[test]
    fn operation_lock_held_through_flow_and_safe_cleanup() {
        let fs = support::FakeFs::installed();
        let report = with_operation(fs.clone(), |store| {
            let mut flow = Flow {
                store,
                fs: fs.clone(),
                events: vec![],
            };
            let report = execute(Request::Inspect, Os::Linux, &mut flow)?;
            assert!(matches!(LockedStore::acquire(fs.clone()), Err(Error::Busy)));
            assert!(fs.held()); // safe cleanup/report construction is still inside the callback.
            Ok(report)
        })
        .unwrap();
        assert_eq!(report.record, boothop_core::RecordDiagnostic::Missing);
        assert!(!fs.held());
        assert_eq!(fs.0.borrow().open_handles, 0);
    }

    #[test]
    fn busy_prevents_the_operation_callback_and_mutations() {
        let fs = support::FakeFs::installed();
        let first = LockedStore::acquire(fs.clone()).unwrap();
        let mut entered = false;
        let result = with_operation(fs.clone(), |store| {
            entered = true;
            store.save(&support::target())
        });
        assert_eq!(result, Err(Error::Busy));
        assert!(!entered);
        assert_eq!(fs.record(), None);
        assert!(fs.held());
        drop(first);
        assert_eq!(fs.0.borrow().open_handles, 0);
    }

    #[test]
    fn unknown_record_configure_keeps_original_bytes_and_releases_lock() {
        let fs = support::FakeFs::installed();
        fs.set_record(br#"{"version":999}"#.to_vec());
        let old = fs.record();
        let result = with_operation(fs.clone(), |store| {
            let mut flow = Flow {
                store,
                fs: fs.clone(),
                events: vec![],
            };
            let result = execute(
                Request::Configure {
                    boot_id: BootId(7),
                    os: Os::Windows,
                },
                Os::Linux,
                &mut flow,
            );
            assert!(flow.events.is_empty());
            result
        });
        assert_eq!(result, Err(Error::UnsupportedRecordVersion { found: 999 }));
        assert_eq!(fs.record(), old);
        assert!(!fs.held());
        assert_eq!(fs.0.borrow().open_handles, 0);
    }

    #[test]
    fn flow_report_preserves_store_durability_unknown_without_retry_or_firmware_mutation() {
        let fs = support::FakeFs::installed();
        fs.0.borrow_mut().fail = Some(("dir_fsync", 5));
        let result = with_operation(fs.clone(), |store| {
            let mut flow = Flow {
                store,
                fs: fs.clone(),
                events: vec![],
            };
            let result = execute(
                Request::Configure {
                    boot_id: BootId(7),
                    os: Os::Windows,
                },
                Os::Linux,
                &mut flow,
            );
            assert!(fs.held());
            assert_eq!(flow.events, ["options"]);
            result
        });
        let Error::FlowFailure { cause, stages, .. } = result.unwrap_err() else {
            panic!("flow stage context missing")
        };
        assert_eq!(*cause, Error::StoreDurabilityUnknown { raw_code: 5 });
        assert_eq!(stages, [Stage::TargetValidated, Stage::ResidualPossible]);
        assert_eq!(
            boothop_core::decode_record(&fs.record().unwrap()),
            Ok(support::target())
        );
        assert_eq!(
            fs.0.borrow()
                .events
                .iter()
                .filter(|e| e.as_str() == "rename")
                .count(),
            1
        );
        assert!(!fs.held());
        assert_eq!(fs.0.borrow().open_handles, 0);
    }

    #[test]
    fn lock_released_on_callback_error_and_panic() {
        let fs = support::FakeFs::installed();
        let result: Result<(), Error> = with_operation(fs.clone(), |_| {
            assert!(fs.held());
            Err(Error::ResourceLimit)
        });
        assert_eq!(result, Err(Error::ResourceLimit));
        assert_eq!(fs.0.borrow().open_handles, 0);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), Error> = with_operation(fs.clone(), |_| {
                assert!(fs.held());
                panic!("synthetic unwind")
            });
        }));
        assert!(panic.is_err());
        assert!(!fs.held());
        assert_eq!(fs.0.borrow().open_handles, 0);
        drop(LockedStore::acquire(fs.clone()).unwrap());
    }
}
