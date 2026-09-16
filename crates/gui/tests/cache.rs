#[cfg(target_os = "linux")]
mod linux_tests {
    use boothop_core::{BootId, Os};
    use boothop_gui::cache::{
        Cache, CachedTarget, LinuxCache, resolve_cache_path, safe_description,
    };
    use std::{
        ffi::OsStr,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "boothop-gui-cache-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn cache(&self) -> LinuxCache {
            LinuxCache::at(self.0.join("state/boothop/cache-v1.json"))
        }
        fn file(&self) -> PathBuf {
            self.0.join("state/boothop/cache-v1.json")
        }
        fn write(&self, bytes: &[u8]) {
            fs::create_dir_all(self.file().parent().unwrap()).unwrap();
            fs::write(self.file(), bytes).unwrap();
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn target() -> CachedTarget {
        CachedTarget {
            boot_id: BootId(7),
            os: Os::Windows,
            description_utf16: Some(vec![0x4e2d, 0xd800, 10, 0x41]),
        }
    }
    #[test]
    fn xdg_paths_require_an_absolute_trusted_base() {
        assert_eq!(
            resolve_cache_path(Some(OsStr::new("/tmp/state")), Some(OsStr::new("/ignored")))
                .unwrap(),
            PathBuf::from("/tmp/state/boothop/cache-v1.json")
        );
        assert_eq!(
            resolve_cache_path(Some(OsStr::new("relative")), Some(OsStr::new("/tmp/home")))
                .unwrap(),
            PathBuf::from("/tmp/home/.local/state/boothop/cache-v1.json")
        );
        assert!(resolve_cache_path(None, None).is_err());
        assert!(resolve_cache_path(None, Some(OsStr::new("relative"))).is_err());
        assert!(resolve_cache_path(Some(OsStr::new("/tmp/../etc")), None).is_err());
    }
    #[test]
    fn missing_cache_is_read_only_and_atomic_round_trip_is_display_only() {
        let temp = Temp::new();
        let cache = temp.cache();
        assert_eq!(cache.load().unwrap(), None);
        assert!(!temp.file().parent().unwrap().exists());
        cache.save(&target()).unwrap();
        assert_eq!(cache.load().unwrap(), Some(target()));
        let json = fs::read_to_string(temp.file()).unwrap();
        for forbidden in ["identity", "digest", "optional_data", "path", "command"] {
            assert!(!json.contains(forbidden));
        }
        let mut next = target();
        next.boot_id = BootId(8);
        cache.save(&next).unwrap();
        assert_eq!(cache.load().unwrap(), Some(next));
        assert_eq!(
            fs::read_dir(temp.file().parent().unwrap()).unwrap().count(),
            1
        );
    }
    #[test]
    fn corrupt_unknown_and_extra_fields_are_unavailable() {
        for json in [
            "not json",
            r#"{"version":2,"boot_id":7,"os":"Windows"}"#,
            r#"{"version":1,"boot_id":7,"os":"Windows","identity":"fake"}"#,
            r#"{"version":1,"boot_id":7,"os":"Other"}"#,
            r#"{"version":1,"boot_id":65536,"os":"Windows"}"#,
        ] {
            let temp = Temp::new();
            temp.write(json.as_bytes());
            assert!(temp.cache().load().is_err());
        }
    }
    #[test]
    fn cache_size_is_bounded_on_both_read_and_write() {
        let temp = Temp::new();
        temp.write(&vec![b' '; 65537]);
        assert!(temp.cache().load().is_err());
        let mut huge = target();
        huge.description_utf16 = Some(vec![65535; 65536]);
        assert!(temp.cache().save(&huge).is_err());
        assert_eq!(fs::metadata(temp.file()).unwrap().len(), 65537);
    }
    #[test]
    fn symlink_files_and_directories_are_never_followed_or_replaced() {
        use std::os::unix::fs::symlink;
        let temp = Temp::new();
        temp.write(b"sentinel");
        let outside = temp.0.join("outside");
        fs::rename(temp.file(), &outside).unwrap();
        symlink(&outside, temp.file()).unwrap();
        assert!(temp.cache().load().is_err());
        assert!(temp.cache().save(&target()).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"sentinel");
        let temp = Temp::new();
        fs::create_dir(temp.0.join("outside")).unwrap();
        symlink(temp.0.join("outside"), temp.0.join("state")).unwrap();
        assert!(temp.cache().load().is_err());
        assert!(temp.cache().save(&target()).is_err());
        assert_eq!(fs::read_dir(temp.0.join("outside")).unwrap().count(), 0);
    }
    #[test]
    fn nonregular_files_and_invalid_paths_fail_closed() {
        let temp = Temp::new();
        fs::create_dir_all(temp.file()).unwrap();
        assert!(temp.cache().load().is_err());
        assert!(temp.cache().save(&target()).is_err());
        assert!(LinuxCache::at(PathBuf::from("relative")).load().is_err());
        let temp = Temp::new();
        temp.write(b"invalid");
        fs::remove_file(temp.file()).unwrap();
        let fifo = std::ffi::CString::new(temp.file().as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(temp.cache().load().is_err());
        assert!(temp.cache().save(&target()).is_err());
    }
    #[test]
    fn arbitrary_utf16_cannot_forge_lines_or_bidi_labels() {
        assert_eq!(
            safe_description(&[
                0x4e2d, 0xd83d, 0xde00, 0xd800, 10, 13, 9, 0x2028, 0x202e, 0x41
            ]),
            "中😀�\u{fffd}\u{fffd}\u{fffd}\u{fffd}\u{fffd}A"
        );
        assert!(safe_description(&vec![0x4e2d; 10000]).len() <= 2048);
    }
}

mod windows_tests {
    use boothop_core::{BootId, Os};
    use boothop_gui::cache::{Cache, CachedTarget, WindowsCache, resolve_windows_cache_path};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "boothop-gui-windows-cache-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn cache(&self) -> WindowsCache {
            WindowsCache::at(self.0.join("BootHop/cache-v1.json"))
        }
        fn file(&self) -> PathBuf {
            self.0.join("BootHop/cache-v1.json")
        }
        fn write(&self, bytes: &[u8]) {
            fs::create_dir_all(self.file().parent().unwrap()).unwrap();
            fs::write(self.file(), bytes).unwrap();
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn target() -> CachedTarget {
        CachedTarget {
            boot_id: BootId(7),
            os: Os::Windows,
            description_utf16: Some(vec![0x4e2d, 0xd800, 10, 0x202e, 0x41]),
        }
    }

    #[test]
    fn windows_cache_uses_fixed_absolute_local_app_data_containment() {
        let root = std::env::temp_dir().join("boothop-cache-root");
        assert_eq!(
            resolve_windows_cache_path(root.as_os_str()).unwrap(),
            root.join("BootHop/cache-v1.json")
        );
        assert!(resolve_windows_cache_path(std::ffi::OsStr::new("relative")).is_err());
        assert!(resolve_windows_cache_path(root.join("../escape").as_os_str()).is_err());
    }

    #[test]
    fn windows_cache_persists_only_sanitized_bounded_display_data_atomically() {
        let temp = Temp::new();
        let cache = temp.cache();
        assert_eq!(cache.load().unwrap(), None);
        cache.save(&target()).unwrap();
        let bytes = fs::read(temp.file()).unwrap();
        let json = String::from_utf8(bytes).unwrap();
        assert!(!json.contains("identity"));
        assert!(!json.contains("optional_data"));
        assert!(!json.contains("path"));
        assert!(!json.contains("command"));
        assert!(!json.contains("202e"));
        assert_eq!(
            cache.load().unwrap().unwrap().description_utf16,
            Some("中���A".encode_utf16().collect())
        );
        let mut next = target();
        next.boot_id = BootId(8);
        cache.save(&next).unwrap();
        assert_eq!(cache.load().unwrap().unwrap().boot_id, BootId(8));
        assert_eq!(
            fs::read_dir(temp.file().parent().unwrap()).unwrap().count(),
            1
        );
    }

    #[test]
    fn windows_cache_rejects_malformed_oversize_and_unexpected_objects() {
        for json in [
            "not json",
            r#"{\"version\":2,\"boot_id\":7,\"os\":\"Windows\"}"#,
            r#"{\"version\":1,\"boot_id\":7,\"os\":\"Windows\",\"identity\":\"fake\"}"#,
            r#"{\"version\":1,\"boot_id\":65536,\"os\":\"Windows\"}"#,
        ] {
            let temp = Temp::new();
            temp.write(json.as_bytes());
            assert!(temp.cache().load().is_err());
        }
        let temp = Temp::new();
        temp.write(&vec![b' '; 65_537]);
        assert!(temp.cache().load().is_err());
        let mut huge = target();
        huge.description_utf16 = Some(vec![0x41; 65_536]);
        assert!(temp.cache().save(&huge).is_err());
        let temp = Temp::new();
        fs::create_dir_all(temp.file()).unwrap();
        assert!(temp.cache().load().is_err());
        assert!(temp.cache().save(&target()).is_err());
    }
}
