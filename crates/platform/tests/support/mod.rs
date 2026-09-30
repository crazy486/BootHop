use boothop_core::{
    ArchProvisionState, BootId, BuildMetadata, CanonicalDevicePathNode, Os, OwnedArchEntry,
    PublishMetadata, TargetRecord, canonicalize, parse_load_option,
};
use boothop_platform::linux::store::{Filesystem, Metadata, OpenKind};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

pub fn target() -> TargetRecord {
    let hex = include_str!("../../../../fixtures/uefi/synthetic/task1-shape.hex").trim();
    let bytes: Vec<_> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    TargetRecord {
        boot_id: BootId(7),
        os: Os::Windows,
        identity: canonicalize(&parse_load_option(&bytes).unwrap()).unwrap(),
    }
}

#[allow(dead_code)]
pub fn ready_state() -> ArchProvisionState {
    let mut identity = target().identity;
    let file_length = {
        let CanonicalDevicePathNode::FilePath(file) = &mut identity.nodes[1] else {
            unreachable!()
        };
        file.path_utf16 = "\\EFI\\BootHop\\arch.efi".encode_utf16().collect();
        file.length = ((file.path_utf16.len() + 1) * 2 + 4) as u16;
        file.length
    };
    identity.file_path_list_length = match &identity.nodes[0] {
        CanonicalDevicePathNode::HardDrive(hd) => hd.length + file_length + 4,
        _ => unreachable!(),
    };
    ArchProvisionState::Ready(OwnedArchEntry {
        boot_id: BootId(0x1234),
        identity,
        identity_version: 1,
        uki_path: "EFI/BootHop/arch.efi".into(),
        build: BuildMetadata {
            kernel: "linux-zen".into(),
            kernel_release: "6.12.1-zen1-1-zen".into(),
            initramfs_sha256: [0x11; 32],
        },
        publish: Some(PublishMetadata {
            sha256: [0x22; 32],
            size: 42,
        }),
    })
}

#[derive(Clone)]
pub struct Node {
    pub meta: Metadata,
    pub bytes: Vec<u8>,
}
#[derive(Default)]
pub struct State {
    pub nodes: BTreeMap<String, Rc<RefCell<Node>>>,
    pub held: bool,
    pub fail: Option<(&'static str, i32)>,
    pub events: Vec<String>,
    pub next_inode: u64,
    pub write_limit: Option<usize>,
    pub read_limit: Option<usize>,
    pub fail_after: Option<(&'static str, usize, i32)>,
    pub replace_temp_on_write_failure: bool,
    pub open_handles: usize,
    pub collide_temp: bool,
    pub temp_metadata: Option<(u32, u32, u32, u64)>,
    pub grow_on_read: Option<Vec<u8>>,
    pub bytes_read: usize,
    pub rewrite_on_read: Option<(Vec<u8>, usize)>,
}
#[derive(Clone, Default)]
pub struct FakeFs(pub Rc<RefCell<State>>);
pub struct Handle {
    path: String,
    node: Rc<RefCell<Node>>,
    offset: usize,
    locked: bool,
    fs: FakeFs,
}
impl Drop for Handle {
    fn drop(&mut self) {
        let mut s = self.fs.0.borrow_mut();
        s.open_handles -= 1;
        if self.locked {
            s.held = false;
        }
    }
}
impl FakeFs {
    pub fn installed() -> Self {
        let fs = Self::default();
        for (name, mode) in [
            ("/", 0o40755),
            ("/var", 0o40755),
            ("/var/lib", 0o40755),
            ("/var/lib/boothop", 0o40700),
            ("/var/lib/boothop/operation.lock", 0o100600),
        ] {
            fs.insert(name, mode, vec![]);
        }
        fs
    }
    pub fn insert(&self, name: &str, mode: u32, bytes: Vec<u8>) {
        let mut s = self.0.borrow_mut();
        s.next_inode += 1;
        let inode = s.next_inode;
        s.nodes.insert(
            name.into(),
            Rc::new(RefCell::new(Node {
                meta: Metadata {
                    uid: 0,
                    gid: 0,
                    mode,
                    links: 1,
                    inode,
                    device: 1,
                    size: bytes.len() as u64,
                    mtime_seconds: 100,
                    mtime_nanoseconds: 10,
                    ctime_seconds: 200,
                    ctime_nanoseconds: 20,
                },
                bytes,
            })),
        );
    }
    pub fn set_record(&self, bytes: Vec<u8>) {
        self.set_named_record("targets.json", bytes);
    }
    pub fn record(&self) -> Option<Vec<u8>> {
        self.named_record("targets.json")
    }
    #[allow(dead_code)]
    pub fn set_journal(&self, bytes: Vec<u8>) {
        self.set_named_record("arch-provision.json", bytes);
    }
    #[allow(dead_code)]
    pub fn journal(&self) -> Option<Vec<u8>> {
        self.named_record("arch-provision.json")
    }
    fn set_named_record(&self, name: &str, bytes: Vec<u8>) {
        self.insert(&format!("/var/lib/boothop/{name}"), 0o100600, bytes);
    }
    fn named_record(&self, name: &str) -> Option<Vec<u8>> {
        self.0
            .borrow()
            .nodes
            .get(&format!("/var/lib/boothop/{name}"))
            .map(|n| n.borrow().bytes.clone())
    }
    pub fn held(&self) -> bool {
        self.0.borrow().held
    }
    fn stage(&self, name: &'static str) -> Result<(), i32> {
        let mut s = self.0.borrow_mut();
        s.events.push(name.into());
        if let Some((stage, after, code)) = s.fail_after
            && stage == name
            && s.events.iter().filter(|e| e.as_str() == name).count() > after
        {
            return Err(code);
        }
        if let Some((stage, code)) = s.fail
            && stage == name
        {
            return Err(code);
        }
        Ok(())
    }
}
impl Filesystem for FakeFs {
    type Handle = Handle;
    fn root(&self) -> Result<Handle, i32> {
        self.stage("root")?;
        self.0.borrow_mut().open_handles += 1;
        Ok(Handle {
            path: "/".into(),
            node: self.0.borrow().nodes["/"].clone(),
            offset: 0,
            locked: false,
            fs: self.clone(),
        })
    }
    fn open(&self, dir: &Handle, name: &str, kind: OpenKind) -> Result<Handle, i32> {
        self.stage(match kind {
            OpenKind::ExclusiveTemp => "create",
            _ if name == "targets.json" || name == "arch-provision.json" => "open_record",
            _ if name == "operation.lock" => "open_lock",
            _ => "open_dir",
        })?;
        let path = format!("{}/{}", dir.path.trim_end_matches('/'), name);
        if kind == OpenKind::ExclusiveTemp {
            if self.0.borrow().collide_temp {
                self.insert(&path, 0o100600, b"existing unrelated temp".to_vec());
            }
            if self.0.borrow().nodes.contains_key(&path) {
                return Err(17);
            }
            self.insert(&path, 0o100600, vec![]);
            if let Some((uid, gid, mode, links)) = self.0.borrow().temp_metadata {
                let s = self.0.borrow();
                let mut n = s.nodes[&path].borrow_mut();
                n.meta.uid = uid;
                n.meta.gid = gid;
                n.meta.mode = mode;
                n.meta.links = links;
            }
        }
        let node = self.0.borrow().nodes.get(&path).cloned().ok_or(2)?;
        if node.borrow().meta.mode & 0o170000 == 0o120000 {
            return Err(40);
        }
        self.0.borrow_mut().open_handles += 1;
        Ok(Handle {
            path,
            node,
            offset: 0,
            locked: false,
            fs: self.clone(),
        })
    }
    fn metadata(&self, file: &Handle) -> Result<Metadata, i32> {
        self.stage("metadata")?;
        if file.path.ends_with(".tmp") {
            self.stage("temp_metadata")?;
        }
        Ok(file.node.borrow().meta)
    }
    fn lock(&self, file: &mut Handle) -> Result<(), i32> {
        self.stage("lock")?;
        if self.held() {
            return Err(11);
        }
        self.0.borrow_mut().held = true;
        file.locked = true;
        Ok(())
    }
    fn read(&self, file: &mut Handle, bytes: &mut [u8]) -> Result<usize, i32> {
        self.stage("read")?;
        let mut n = file.node.borrow_mut();
        let count = bytes
            .len()
            .min(n.bytes.len() - file.offset)
            .min(self.0.borrow().read_limit.unwrap_or(bytes.len()));
        bytes[..count].copy_from_slice(&n.bytes[file.offset..file.offset + count]);
        file.offset += count;
        let mut s = self.0.borrow_mut();
        s.bytes_read += count;
        if let Some(extra) = s.grow_on_read.take() {
            n.bytes.extend(extra);
            n.meta.size = n.bytes.len() as u64;
        }
        if let Some((replacement, stamp)) = s.rewrite_on_read.take() {
            assert_eq!(replacement.len(), n.bytes.len());
            assert_eq!(&replacement[..file.offset], &n.bytes[..file.offset]);
            n.bytes = replacement;
            match stamp {
                0 => n.meta.mtime_seconds += 1,
                1 => n.meta.mtime_nanoseconds += 1,
                2 => n.meta.ctime_seconds += 1,
                3 => n.meta.ctime_nanoseconds += 1,
                _ => panic!("unknown synthetic change stamp"),
            }
        }
        Ok(count)
    }
    fn write(&self, file: &mut Handle, bytes: &[u8]) -> Result<usize, i32> {
        if let Err(code) = self.stage("write") {
            if self.0.borrow().replace_temp_on_write_failure {
                self.insert(&file.path, 0o100600, b"external replacement".to_vec());
            }
            return Err(code);
        }
        let count = self
            .0
            .borrow()
            .write_limit
            .unwrap_or(bytes.len())
            .min(bytes.len());
        let mut n = file.node.borrow_mut();
        n.bytes.extend_from_slice(&bytes[..count]);
        n.meta.size = n.bytes.len() as u64;
        Ok(count)
    }
    fn sync(&self, file: &Handle) -> Result<(), i32> {
        self.stage(if file.node.borrow().meta.mode & 0o170000 == 0o040000 {
            "dir_fsync"
        } else {
            "temp_fsync"
        })
    }
    fn rename(&self, dir: &Handle, from: &str, to: &str) -> Result<(), i32> {
        self.stage("rename")?;
        let mut s = self.0.borrow_mut();
        let node = s.nodes.remove(&format!("{}/{from}", dir.path)).ok_or(2)?;
        let journal_bytes = (to == "arch-provision.json").then(|| node.borrow().bytes.clone());
        s.nodes.insert(format!("{}/{to}", dir.path), node);
        if let Some(bytes) = journal_bytes
            && let Ok(state) = boothop_core::decode_arch_provision_state(Some(&bytes))
        {
            s.events.push(journal_event(&state).to_owned());
        }
        Ok(())
    }
    fn unlink(&self, dir: &Handle, name: &str) -> Result<(), i32> {
        self.stage("unlink")?;
        self.0
            .borrow_mut()
            .nodes
            .remove(&format!("{}/{name}", dir.path));
        Ok(())
    }
}

fn journal_event(state: &ArchProvisionState) -> &'static str {
    use boothop_core::{ProvisioningStep as P, UninstallingStep as U};
    match state {
        ArchProvisionState::Unprovisioned => "journal:unprovisioned",
        ArchProvisionState::Ready(_) => "journal:ready",
        ArchProvisionState::Uninstalled(_) => "journal:uninstalled",
        ArchProvisionState::Provisioning(record) => match record.step {
            P::UkiPublicationPending => "journal:provisioning:uki_publication_pending",
            P::UkiPublicationAttempted => "journal:provisioning:uki_publication_attempted",
            P::UkiPublished => "journal:provisioning:uki_published",
            P::BootEntryCreateAttempted => "journal:provisioning:boot_entry_create_attempted",
            P::BootEntryCreated => "journal:provisioning:boot_entry_created",
            P::BootEntryReadBackVerified => "journal:provisioning:boot_entry_read_back_verified",
            P::BootOrderAppendAttempted => "journal:provisioning:boot_order_append_attempted",
            P::BootOrderAppendWriteCompleted => {
                "journal:provisioning:boot_order_append_write_completed"
            }
            P::BootOrderAppended => "journal:provisioning:boot_order_appended",
            P::BootOrderReadBackVerified => "journal:provisioning:boot_order_read_back_verified",
        },
        ArchProvisionState::Uninstalling(record) => match record.step {
            U::Started => "journal:uninstalling:started",
            U::BootOrderRemovalAttempted => "journal:uninstalling:boot_order_removal_attempted",
            U::BootOrderRemoved => "journal:uninstalling:boot_order_removed",
            U::BootOrderRemovalReadBackVerified => {
                "journal:uninstalling:boot_order_removal_read_back_verified"
            }
            U::BootEntryRemovalAttempted => "journal:uninstalling:boot_entry_removal_attempted",
            U::BootEntryDeleteCompleted => "journal:uninstalling:boot_entry_delete_completed",
            U::BootEntryRemoved => "journal:uninstalling:boot_entry_removed",
            U::BootEntryRemovalReadBackVerified => {
                "journal:uninstalling:boot_entry_removal_read_back_verified"
            }
            U::UkiRemovalAttempted => "journal:uninstalling:uki_removal_attempted",
            U::UkiDeleteCompleted => "journal:uninstalling:uki_delete_completed",
            U::UkiRemoved => "journal:uninstalling:uki_removed",
        },
    }
}
