#![cfg(target_os = "linux")]

use boothop_platform::linux::{
    arch_config_fs::{ArchConfigFsAdapter, ArchConfigFsCalls, EntryType},
    uki::ArchConfigFs,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "boothop-arch-config-fs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }

    fn write(&self, absolute: &str, contents: &[u8]) {
        let path = self.0.join(absolute.trim_start_matches('/'));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn adapter(root: &TempRoot) -> ArchConfigFsAdapter {
    ArchConfigFsAdapter::rooted_at(root.path()).unwrap()
}

#[test]
fn reads_regular_file_lists_directory_and_recognizes_mounted_vfat_esp() {
    let root = TempRoot::new();
    root.write("etc/mkinitcpio.conf", b"HOOKS=(base)\n");
    root.write("etc/mkinitcpio.conf.d/10-extra.conf", b"HOOKS+=(foo)\n");
    root.write("mnt/esp/EFI/BootHop/.keep", b"");
    root.write(
        "proc/self/mountinfo",
        b"36 25 8:1 / /mnt/esp rw,relatime - vfat /dev/sda1 rw\n",
    );
    let fs = adapter(&root);

    assert_eq!(
        fs.read_text("/etc/mkinitcpio.conf").unwrap().as_deref(),
        Some("HOOKS=(base)\n")
    );
    assert_eq!(
        fs.files_in_directory("/etc/mkinitcpio.conf.d").unwrap(),
        vec!["10-extra.conf"]
    );
    assert!(fs.is_file("/etc/mkinitcpio.conf"));
    assert!(fs.is_directory("/mnt/esp/EFI/BootHop"));
    assert!(fs.is_mounted_esp("/mnt/esp"));
}

#[test]
fn missing_file_is_distinct_from_unreadable_file() {
    let fs = ArchConfigFsAdapter::new(DeniedReadCalls).unwrap();

    assert_eq!(fs.read_text("/etc/missing").unwrap(), None);
    assert!(fs.read_text("/etc/secret").is_err());
}

struct FakeHandle(&'static str);
struct DeniedReadCalls;

impl ArchConfigFsCalls for DeniedReadCalls {
    type Handle = FakeHandle;

    fn root(&self) -> Result<Self::Handle, i32> {
        Ok(FakeHandle(""))
    }

    fn open_directory(&self, parent: &Self::Handle, name: &str) -> Result<Self::Handle, i32> {
        match (parent.0, name) {
            ("", "etc") => Ok(FakeHandle("etc")),
            _ => Err(2),
        }
    }

    fn open_file(&self, parent: &Self::Handle, name: &str) -> Result<Self::Handle, i32> {
        match (parent.0, name) {
            ("etc", "secret") => Ok(FakeHandle("etc/secret")),
            _ => Err(2),
        }
    }

    fn entry_type(&self, handle: &Self::Handle) -> Result<EntryType, i32> {
        Ok(match handle.0 {
            "" | "etc" => EntryType::Directory,
            _ => EntryType::RegularFile,
        })
    }

    fn names(&self, _directory: &Self::Handle) -> Result<Vec<Vec<u8>>, String> {
        Ok(Vec::new())
    }

    fn read(&self, _file: &mut Self::Handle, _buffer: &mut [u8]) -> Result<usize, i32> {
        Err(13)
    }
}

#[test]
fn rejects_non_normalized_traversal_and_symlinked_components() {
    let root = TempRoot::new();
    root.write("etc/real.conf", b"safe\n");
    std::os::unix::fs::symlink("real.conf", root.path().join("etc/link.conf")).unwrap();
    std::os::unix::fs::symlink("etc", root.path().join("etc-link")).unwrap();
    let fs = adapter(&root);

    assert!(fs.read_text("/etc/../etc/real.conf").is_err());
    assert!(fs.read_text("/etc//real.conf").is_err());
    assert!(fs.read_text("/etc/link.conf").is_err());
    assert!(fs.read_text("/etc-link/real.conf").is_err());
}

#[test]
fn rejects_oversized_files_directories_and_invalid_or_ambiguous_mounts() {
    let root = TempRoot::new();
    root.write("etc/large", &vec![b'x'; 1_048_577]);
    fs::create_dir_all(root.path().join("etc/many")).unwrap();
    for index in 0..4_097 {
        fs::write(root.path().join(format!("etc/many/{index}")), b"").unwrap();
    }
    root.write(
        "proc/self/mountinfo",
        b"36 25 8:1 / /mnt/esp rw - ext4 /dev/sda1 rw\n",
    );
    let fs = adapter(&root);

    assert!(fs.read_text("/etc/large").is_err());
    assert!(fs.files_in_directory("/etc/many").is_err());
    assert!(!fs.is_mounted_esp("/mnt/esp"));
    root.write("proc/self/mountinfo", b"36 25 8:1 / /mnt/esp rw - vfat /dev/sda1 rw\n37 25 8:2 / /mnt/esp rw - vfat /dev/sda2 rw\n");
    assert!(!fs.is_mounted_esp("/mnt/esp"));
    root.write("proc/self/mountinfo", b"broken\n");
    assert!(!fs.is_mounted_esp("/mnt/esp"));
}

#[test]
fn malformed_mount_ids_fail_closed() {
    let root = TempRoot::new();
    let fs = adapter(&root);
    root.write(
        "proc/self/mountinfo",
        b"not-a-number 25 8:1 / /mnt/esp rw - vfat /dev/sda1 rw\n",
    );
    assert!(!fs.is_mounted_esp("/mnt/esp"));

    root.write(
        "proc/self/mountinfo",
        b"36 not-a-number 8:1 / /mnt/esp rw - vfat /dev/sda1 rw\n",
    );
    assert!(!fs.is_mounted_esp("/mnt/esp"));
}

#[test]
fn out_of_range_octal_mount_escape_fails_closed_without_panicking() {
    let root = TempRoot::new();
    root.write(
        "proc/self/mountinfo",
        b"36 25 8:1 / /mnt\\777esp rw - vfat /dev/sda1 rw\n",
    );
    let fs = adapter(&root);

    assert!(!fs.is_mounted_esp("/mnt/esp"));
}

#[test]
fn mountinfo_numeric_fields_require_ascii_decimal_digits() {
    let root = TempRoot::new();
    let fs = adapter(&root);
    for mountinfo in [
        b"+36 25 8:1 / /mnt/esp rw - vfat /dev/sda1 rw\n".as_slice(),
        b"36 +25 8:1 / /mnt/esp rw - vfat /dev/sda1 rw\n".as_slice(),
        b"36 25 +8:1 / /mnt/esp rw - vfat /dev/sda1 rw\n".as_slice(),
        b"36 25 8:+1 / /mnt/esp rw - vfat /dev/sda1 rw\n".as_slice(),
    ] {
        root.write("proc/self/mountinfo", mountinfo);
        assert!(!fs.is_mounted_esp("/mnt/esp"));
    }
}

#[test]
fn mountinfo_root_path_must_be_absolute() {
    let root = TempRoot::new();
    root.write(
        "proc/self/mountinfo",
        b"36 25 8:1 relative /mnt/esp rw - vfat /dev/sda1 rw\n",
    );
    let fs = adapter(&root);

    assert!(!fs.is_mounted_esp("/mnt/esp"));
}

#[test]
fn mountinfo_requires_exactly_three_fields_after_separator() {
    let root = TempRoot::new();
    root.write(
        "proc/self/mountinfo",
        b"36 25 8:1 / /mnt/esp rw - vfat /dev/sda1 rw unexpected\n",
    );
    let fs = adapter(&root);

    assert!(!fs.is_mounted_esp("/mnt/esp"));
}

#[test]
fn mountinfo_accepts_unknown_optional_fields_before_separator() {
    let root = TempRoot::new();
    root.write(
        "proc/self/mountinfo",
        b"36 25 8:1 / /mnt/esp rw shared:17 master:1 custom:flag - vfat /dev/sda1 rw\n",
    );
    let fs = adapter(&root);

    assert!(fs.is_mounted_esp("/mnt/esp"));
}

#[test]
fn adapter_exposes_only_the_read_only_contract() {
    fn read_only_contract(_: &impl ArchConfigFs) {}
    let root = TempRoot::new();
    let fs = adapter(&root);
    read_only_contract(&fs);
}
