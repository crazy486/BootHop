use boothop_core::{BootId, Os, TargetRecord, canonicalize, parse_load_option};
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
                },
                bytes,
            })),
        );
    }
    pub fn set_record(&self, bytes: Vec<u8>) {
        self.insert("/var/lib/boothop/targets.json", 0o100600, bytes);
    }
    pub fn record(&self) -> Option<Vec<u8>> {
        self.0
            .borrow()
            .nodes
            .get("/var/lib/boothop/targets.json")
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
            _ if name == "targets.json" => "open_record",
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
        s.nodes.insert(format!("{}/{to}", dir.path), node);
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
