#![cfg(target_os = "linux")]
use boothop_core::{BootId, Error, Platform, RecordState, TargetRecord};
use boothop_platform::{
    ProtectedStore,
    linux::{
        LinuxCalls, LinuxPlatform,
        firmware::{Metadata, OpenKind},
        reboot::{Probe, Reply},
    },
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

const GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
fn name(stem: &str) -> String {
    format!("{stem}-{GUID}")
}
fn is_boot_next_read_open(event: &str) -> bool {
    event == format!("open:{}:ReadVariable", name("BootNext"))
}
fn is_boot_option_read_open(event: &str) -> bool {
    event == format!("open:{}:ReadVariable", name("Boot0007"))
}
#[derive(Default)]
struct Store;
impl ProtectedStore for Store {
    fn load(&mut self) -> Result<RecordState, Error> {
        Ok(RecordState::Missing)
    }
    fn save(&mut self, _: &TargetRecord) -> Result<(), Error> {
        Ok(())
    }
}
#[derive(Clone)]
struct FakeLinuxCalls(Rc<RefCell<State>>);
struct State {
    files: BTreeMap<String, Vec<u8>>,
    events: Vec<String>,
    fail: Option<(&'static str, i32)>,
    metadata: Option<Metadata>,
    changed: bool,
    reads: usize,
    chunk: usize,
    write_result: Result<usize, i32>,
    writes: Vec<(usize, Vec<u8>)>,
    probe: Result<Probe, Error>,
    reply: Reply,
    flags: Vec<u64>,
    live_handles: usize,
    file_meta: Option<Metadata>,
    changed_names: bool,
    replace_on_reopen: bool,
    next_opens: usize,
    create_race: bool,
    readback: Option<Vec<u8>>,
}
struct Handle {
    name: String,
    offset: usize,
    inode: u64,
    state: Rc<RefCell<State>>,
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.state.borrow_mut().live_handles -= 1;
    }
}
impl FakeLinuxCalls {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(State {
            files: BTreeMap::new(),
            events: vec![],
            fail: None,
            metadata: None,
            changed: false,
            reads: 0,
            chunk: usize::MAX,
            write_result: Ok(6),
            writes: vec![],
            probe: Ok(probe()),
            reply: Reply::Success,
            flags: vec![],
            live_handles: 0,
            file_meta: None,
            changed_names: false,
            replace_on_reopen: false,
            next_opens: 0,
            create_race: false,
            readback: None,
        })))
    }
    fn set(&self, stem: &str, bytes: &[u8]) {
        self.0.borrow_mut().files.insert(name(stem), bytes.to_vec());
    }
}
impl LinuxCalls for FakeLinuxCalls {
    type Handle = Handle;
    fn root(&mut self) -> Result<Handle, i32> {
        let mut s = self.0.borrow_mut();
        s.events.push("root".into());
        s.live_handles += 1;
        Ok(Handle {
            name: "/".into(),
            offset: 0,
            inode: 1,
            state: self.0.clone(),
        })
    }
    fn open(&mut self, _: &Handle, leaf: &str, kind: OpenKind) -> Result<Handle, i32> {
        let mut s = self.0.borrow_mut();
        s.events.push(format!("open:{leaf}:{kind:?}"));
        if let Some((op, code)) = s.fail
            && (op == "open" || op == leaf)
        {
            return Err(code);
        }
        if kind == OpenKind::CreateNext {
            if s.create_race {
                s.files.insert(leaf.into(), vec![7, 0, 0, 0, 9, 0]);
            }
            if s.files.contains_key(leaf) {
                return Err(17);
            }
            s.files.insert(leaf.into(), Vec::new());
        }
        if kind == OpenKind::ReadVariable
            && leaf == name("BootNext")
            && !s.writes.is_empty()
            && let Some(bytes) = s.readback.clone()
        {
            s.files.insert(leaf.into(), bytes);
        }
        if kind != OpenKind::Directory && !s.files.contains_key(leaf) {
            return Err(2);
        }
        if leaf == name("BootNext") {
            s.next_opens += 1;
        }
        let inode = if s.replace_on_reopen && s.next_opens > 1 {
            2
        } else {
            1
        };
        s.live_handles += 1;
        Ok(Handle {
            name: leaf.into(),
            offset: 0,
            inode,
            state: self.0.clone(),
        })
    }
    fn metadata(&mut self, fd: &Handle) -> Result<Metadata, i32> {
        let s = self.0.borrow();
        if let Some(("metadata", code)) = s.fail {
            return Err(code);
        }
        if let Some(meta) = s.metadata {
            return Ok(meta);
        }
        let bytes = s.files.get(&fd.name);
        if bytes.is_some()
            && let Some(meta) = s.file_meta
        {
            return Ok(meta);
        }
        Ok(Metadata {
            mode: if bytes.is_some() { 0o100644 } else { 0o040755 },
            filesystem: 0xde5e81e4,
            readonly: false,
            size: bytes.map_or(0, |b| b.len() as u64),
            device: 1,
            inode: fd.inode,
            mtime: (0, 0),
            ctime: (
                0,
                i64::from(
                    (s.changed && s.reads > 0)
                        || (bytes.is_none()
                            && s.changed_names
                            && s.events.iter().any(|e| e == "names")),
                ),
            ),
        })
    }
    fn names(&mut self, _: &Handle) -> Result<Vec<Vec<u8>>, Error> {
        let mut s = self.0.borrow_mut();
        s.events.push("names".into());
        if let Some(("names", code)) = s.fail {
            return Err(io("read", code));
        }
        Ok(s.files.keys().map(|k| k.as_bytes().to_vec()).collect())
    }
    fn read(&mut self, fd: &mut Handle, buffer: &mut [u8]) -> Result<usize, i32> {
        let mut s = self.0.borrow_mut();
        s.reads += 1;
        if let Some(("read", code)) = s.fail {
            return Err(code);
        }
        let bytes = s.files.get(&fd.name).ok_or(2)?;
        let count = buffer.len().min(s.chunk).min(bytes.len() - fd.offset);
        buffer[..count].copy_from_slice(&bytes[fd.offset..fd.offset + count]);
        fd.offset += count;
        Ok(count)
    }
    fn write(&mut self, fd: &mut Handle, bytes: &[u8]) -> Result<usize, i32> {
        let mut s = self.0.borrow_mut();
        s.events.push("write".into());
        s.writes.push((fd.offset, bytes.to_vec()));
        let count = s.write_result.unwrap_or(1).min(bytes.len());
        s.files
            .get_mut(&fd.name)
            .unwrap()
            .extend_from_slice(&bytes[..count]);
        fd.offset += count;
        s.write_result
    }
    fn probe(&mut self) -> Result<Probe, Error> {
        let mut s = self.0.borrow_mut();
        s.events.push("probe".into());
        s.probe.clone()
    }
    fn reboot_with_flags(&mut self, flags: u64) -> Reply {
        let mut s = self.0.borrow_mut();
        s.events.push("reboot".into());
        s.flags.push(flags);
        s.reply
    }
}

fn probe() -> Probe {
    Probe { systemd_version: "255.17-1".into(), polkit_version: "124".into(), effective_uid: 0, introspection: "<node><interface name='org.freedesktop.login1.Manager'><method name='RebootWithFlags'><arg name='flags' type='t' direction='in'/></method></interface></node>".into() }
}

// Catches checking compatibility only after firmware flow, and accepting unsupported signatures.
#[test]
fn environment_checks_versions_exact_method_and_permission_before_firmware() {
    for version in ["255", "257 (257.4)", "261"] {
        let calls = inventory_calls();
        calls.0.borrow_mut().probe.as_mut().unwrap().systemd_version = version.into();
        let report = boothop_core::execute(
            boothop_core::Request::Inspect,
            boothop_core::Os::Linux,
            &mut LinuxPlatform::new(&mut Store, calls.clone()),
        )
        .unwrap();
        assert_eq!(report.candidates.len(), 1);
        let events = &calls.0.borrow().events;
        assert!(
            events.iter().position(|e| e == "probe").unwrap()
                < events.iter().position(|e| e.contains("BootOrder")).unwrap()
        );
        assert!(!events.iter().any(|e| e == "reboot" || e == "write"));
    }
    let mut bad = vec![];
    for version in ["254", "", "unavailable", "99999999999999999999999"] {
        let mut p = probe();
        p.systemd_version = version.into();
        bad.push(p);
    }
    let mut p = probe();
    p.polkit_version = "123".into();
    bad.push(p);
    let mut p = probe();
    p.effective_uid = 1000;
    bad.push(p);
    for xml in [
        "",
        "<node/>",
        "<node><interface name='other'><method name='RebootWithFlags'><arg type='t'/></method></interface></node>",
        "<node><interface name='org.freedesktop.login1.Manager'><method name='RebootWithFlags'><arg type='u'/></method></interface></node>",
        "<node><interface name='org.freedesktop.login1.Manager'><method name='RebootWithFlags'><arg type='t'/><arg type='b'/></method></interface></node>",
        "<node><interface name='org.freedesktop.login1.Manager'><method name='RebootWithFlags'><arg type='t' direction='out'/></method></interface></node>",
        "<node><!-- RebootWithFlags(t) --></node>",
    ] {
        let mut p = probe();
        p.introspection = xml.into();
        bad.push(p);
    }
    for p in bad {
        let calls = inventory_calls();
        calls.0.borrow_mut().probe = Ok(p);
        assert!(
            boothop_core::execute(
                boothop_core::Request::Inspect,
                boothop_core::Os::Linux,
                &mut LinuxPlatform::new(&mut Store, calls.clone())
            )
            .is_err()
        );
        assert!(
            !calls
                .0
                .borrow()
                .events
                .iter()
                .any(|e| e.contains("Boot") || e == "write" || e == "reboot")
        );
    }
    let calls = inventory_calls();
    calls.0.borrow_mut().probe = Err(io("reboot", 2));
    assert_eq!(
        LinuxPlatform::new(&mut Store, calls.clone()).check_environment(),
        Err(io("reboot", 2))
    );
}

// D-Bus standard introspection carries an external DOCTYPE without fetching that DTD.
#[test]
fn standard_dbus_introspection_doctype_is_supported() {
    let calls = inventory_calls();
    let mut p = probe();
    p.introspection = format!(
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">{}",
        p.introspection
    );
    calls.0.borrow_mut().probe = Ok(p);
    assert_eq!(
        LinuxPlatform::new(&mut Store, calls.clone()).check_environment(),
        Ok(())
    );
}

#[test]
fn introspection_node_budget_is_bounded_below_byte_limit() {
    let calls = inventory_calls();
    let mut p = probe();
    p.introspection =
        p.introspection
            .replacen("<node>", &format!("<node>{}", "<node/>".repeat(65536)), 1);
    calls.0.borrow_mut().probe = Ok(p);
    assert_eq!(
        LinuxPlatform::new(&mut Store, calls.clone()).check_environment(),
        Err(Error::ResourceLimit)
    );
}

// Catches fallback, root bypass flags, or treating signals/disconnects as accepted replies.
#[test]
fn fixed_reboot_flags_and_reply_evidence_matrix() {
    use boothop_core::RebootOutcome::*;
    for (scenario, reply, expected) in [
        ("success", Reply::Success, Accepted),
        ("root block inhibitor", Reply::ExplicitDenial, Rejected),
        ("root block-weak inhibitor", Reply::ExplicitDenial, Rejected),
        ("multiple sessions denied", Reply::ExplicitDenial, Rejected),
        ("delay ends and reply succeeds", Reply::Success, Accepted),
        (
            "delay exceeds RPC deadline",
            Reply::TimedOutAfterSend,
            Unknown,
        ),
        (
            "PrepareForShutdown without reply",
            Reply::DisconnectedAfterSend,
            Unknown,
        ),
        ("postsend disconnect", Reply::DisconnectedAfterSend, Unknown),
        ("not sent", Reply::NotSent, Rejected),
    ] {
        let calls = FakeLinuxCalls::new();
        calls.0.borrow_mut().reply = reply;
        let mut store = Store;
        let mut p = LinuxPlatform::new(&mut store, calls.clone());
        p.check_environment().unwrap();
        assert_eq!(p.reboot(), expected, "{scenario}");
        assert_eq!(calls.0.borrow().flags, [1], "{scenario}");
    }
}

// Catches writes to other variables, repeated/partial writes, or an inherited offset.
#[test]
fn boot_next_single_exclusive_six_byte_write_at_zero() {
    let calls = FakeLinuxCalls::new();
    let mut store = Store;
    let mut platform = LinuxPlatform::new(&mut store, calls.clone());
    assert_eq!(platform.write_next(BootId(0x1234)), Ok(()));
    assert_eq!(calls.0.borrow().writes, [(0, vec![7, 0, 0, 0, 0x34, 0x12])]);
    assert_eq!(
        calls.0.borrow().files[&name("BootNext")],
        [7, 0, 0, 0, 0x34, 0x12]
    );
    assert!(
        calls
            .0
            .borrow()
            .events
            .contains(&format!("open:{}:CreateNext", name("BootNext")))
    );
    assert_eq!(platform.write_next(BootId(8)), Err(io("open", 17)));
    assert_eq!(calls.0.borrow().writes.len(), 1);
    assert_eq!(
        calls.0.borrow().files[&name("BootNext")],
        [7, 0, 0, 0, 0x34, 0x12]
    );
}

// Catches replay or cleanup after EINTR/short/error despite possible firmware changes.
#[test]
fn short_or_failed_write_never_replayed_or_cleaned() {
    for result in [
        Ok(0),
        Ok(1),
        Ok(5),
        Ok(7),
        Err(4),
        Err(1),
        Err(13),
        Err(30),
        Err(28),
        Err(122),
        Err(12),
        Err(5),
        Err(19),
        Err(22),
        Err(2),
        Err(40),
        Err(20),
        Err(21),
        Err(110),
    ] {
        let calls = FakeLinuxCalls::new();
        calls.0.borrow_mut().write_result = result;
        assert_eq!(
            LinuxPlatform::new(&mut Store, calls.clone()).write_next(BootId(3)),
            Err(io("write", result.err().unwrap_or(5)))
        );
        assert_eq!(calls.0.borrow().writes, [(0, vec![7, 0, 0, 0, 3, 0])]);
        assert!(calls.0.borrow().files.contains_key(&name("BootNext")));
        assert_eq!(calls.0.borrow().files.len(), 1);
    }
}

fn read_next(calls: &FakeLinuxCalls) -> Result<Option<BootId>, Error> {
    LinuxPlatform::new(&mut Store, calls.clone()).read_next()
}
fn io(op: &str, code: i32) -> Error {
    Error::PlatformIo {
        operation: op.into(),
        raw_code: code,
    }
}

// Catches accepting truncated, padded, or incorrectly attributed control values.
#[test]
fn boot_next_exact_six_bytes_and_attributes_seven() {
    for bytes in [
        vec![],
        vec![7, 0, 0],
        vec![7, 0, 0, 0],
        vec![7, 0, 0, 0, 1],
        vec![7, 0, 0, 0, 1, 0, 0],
        vec![7, 0, 0, 0, 1, 0, 0, 0],
        vec![6, 0, 0, 0, 1, 0],
    ] {
        let calls = FakeLinuxCalls::new();
        calls.set("BootNext", &bytes);
        assert_eq!(
            read_next(&calls),
            Err(Error::UnsupportedFormat),
            "{bytes:?}"
        );
    }
}

// Catches treating parent absence and permission/IO failures as absent BootNext.
#[test]
fn enoent_is_contextual_and_errno_preserved() {
    let calls = FakeLinuxCalls::new();
    assert_eq!(read_next(&calls), Ok(None));
    for op in ["open", "metadata", "read"] {
        for code in [2, 13, 1, 30, 40, 20, 21, 5, 19, 22, 28, 122, 12, 4, 110] {
            let calls = FakeLinuxCalls::new();
            calls.set("BootNext", &[7, 0, 0, 0, 1, 0]);
            calls.0.borrow_mut().fail = Some((op, code));
            assert_eq!(read_next(&calls), Err(io(op, code)), "{op} {code}");
            assert!(calls.0.borrow().reads <= 1, "unbounded retry");
        }
    }
}

// Catches ignoring descriptor filesystem, mode, mount state or observed changes.
#[test]
fn wrong_filesystem_type_readonly_and_changed_read_are_rejected() {
    for (mode, filesystem, readonly, expected) in [
        (0o040755, 1, false, io("metadata", 19)),
        (0o120777, 0xde5e81e4, false, io("metadata", 1)),
        (0o100644, 0xde5e81e4, false, io("metadata", 1)),
        (0o040755, 0xde5e81e4, true, io("metadata", 30)),
    ] {
        let calls = FakeLinuxCalls::new();
        calls.set("BootNext", &[7, 0, 0, 0, 1, 0]);
        calls.0.borrow_mut().metadata = Some(Metadata {
            mode,
            filesystem,
            readonly,
            size: 6,
            device: 1,
            inode: 1,
            mtime: (0, 0),
            ctime: (0, 0),
        });
        assert_eq!(read_next(&calls), Err(expected));
        assert_eq!(calls.0.borrow().reads, 0);
    }
    let calls = FakeLinuxCalls::new();
    calls.set("BootNext", &[7, 0, 0, 0, 1, 0]);
    calls.0.borrow_mut().changed = true;
    assert_eq!(read_next(&calls), Err(io("read", 5)));
}

// Catches decoding a single short read instead of assembling and checking EOF.
#[test]
fn bounded_short_reads_produce_complete_value() {
    let calls = FakeLinuxCalls::new();
    calls.set("BootNext", &[7, 0, 0, 0, 0x34, 0x12]);
    calls.0.borrow_mut().chunk = 1;
    assert_eq!(read_next(&calls), Ok(Some(BootId(0x1234))));
    assert_eq!(calls.0.borrow().reads, 7);
}

// Catches prefix bytes passed to the u16 decoder or the wrong variable name.
#[test]
fn efivar_prefix_and_payload_separate() {
    let calls = FakeLinuxCalls::new();
    calls.set("BootNext", &[7, 0, 0, 0, 3, 0]);
    let mut store = Store;
    let mut platform = LinuxPlatform::new(&mut store, calls.clone());
    assert_eq!(platform.read_next(), Ok(Some(BootId(3))));
    assert!(
        calls
            .0
            .borrow()
            .events
            .contains(&format!("open:{}:ReadVariable", name("BootNext")))
    );
}
fn option_bytes() -> Vec<u8> {
    let hex = include_str!("../../../fixtures/uefi/synthetic/task1-shape.hex").trim();
    let mut bytes = vec![7, 0, 0, 0];
    bytes.extend(
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()),
    );
    bytes
}
fn inventory_calls() -> FakeLinuxCalls {
    let calls = FakeLinuxCalls::new();
    calls.set("BootOrder", &[7, 0, 0, 0, 7, 0]);
    calls.set("BootCurrent", &[6, 0, 0, 0, 7, 0]);
    calls.set("Boot0007", &option_bytes());
    calls
}
fn options(calls: &FakeLinuxCalls) -> Result<boothop_core::OptionInventory, Error> {
    LinuxPlatform::new(&mut Store, calls.clone()).read_options()
}

#[test]
fn ready_inspect_does_not_open_boot_next_during_option_enumeration() {
    let calls = inventory_calls();
    let report = boothop_core::execute(
        boothop_core::Request::Inspect,
        boothop_core::Os::Linux,
        &mut LinuxPlatform::new(&mut ready_store(), calls.clone()),
    )
    .unwrap();
    assert_eq!(
        report.record,
        boothop_core::RecordDiagnostic::Ready {
            boot_id: BootId(7),
            os: boothop_core::Os::Windows,
        }
    );
    assert!(
        !calls
            .0
            .borrow()
            .events
            .iter()
            .any(|event| is_boot_next_read_open(event))
    );
}

#[test]
fn missing_record_inspect_does_not_open_boot_next_during_option_enumeration() {
    let calls = inventory_calls();
    let report = boothop_core::execute(
        boothop_core::Request::Inspect,
        boothop_core::Os::Linux,
        &mut LinuxPlatform::new(&mut Store, calls.clone()),
    )
    .unwrap();
    assert_eq!(report.record, boothop_core::RecordDiagnostic::Missing);
    assert!(
        !calls
            .0
            .borrow()
            .events
            .iter()
            .any(|event| is_boot_next_read_open(event))
    );
}

#[test]
fn malformed_boot_next_does_not_affect_inspect_inventory() {
    let calls = inventory_calls();
    calls.set("BootNext", &[7, 0, 0, 0, 7, 0, 0]);
    let report = boothop_core::execute(
        boothop_core::Request::Inspect,
        boothop_core::Os::Linux,
        &mut LinuxPlatform::new(&mut Store, calls.clone()),
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].boot_id, BootId(7));
    assert!(
        !calls
            .0
            .borrow()
            .events
            .iter()
            .any(|event| is_boot_next_read_open(event))
    );
}

// Catches reference-only discovery, lowercase/malformed names, and prefix leakage to parser.
#[test]
fn strict_global_enumeration_includes_orphans() {
    let calls = inventory_calls();
    calls.set("Boot00AF", &option_bytes());
    for leaf in [
        name("Boot00af"),
        name("Boot00070"),
        name("boot0008"),
        "Boot0008-00000000-0000-0000-0000-000000000000".into(),
        name("Boot000g"),
    ] {
        calls.0.borrow_mut().files.insert(leaf, vec![0]);
    }
    let result = options(&calls).unwrap();
    assert_eq!(
        result.entries.iter().map(|e| e.0).collect::<Vec<_>>(),
        [BootId(7), BootId(175)]
    );
    assert_eq!(
        result.entries[0].1,
        boothop_core::parse_load_option(&option_bytes()[4..]).unwrap()
    );
    assert!(result.diagnostics.is_empty());
    assert!(
        !calls
            .0
            .borrow()
            .events
            .iter()
            .any(|e| e.contains("Boot00af") || e.contains("Boot00070"))
    );
}

// Catches loss or repeated emission of duplicate diagnostics, and auto-selecting empty order.
#[test]
fn duplicate_order_dedupes_with_diagnostic_and_empty_order_is_valid() {
    let calls = inventory_calls();
    calls.set("BootOrder", &[7, 0, 0, 0, 7, 0, 7, 0, 7, 0]);
    let result = options(&calls).unwrap();
    assert_eq!(result.entries.len(), 1);
    assert_eq!(
        result.diagnostics,
        [boothop_core::EnumerationDiagnostic::DuplicateBootOrder(
            BootId(7)
        )]
    );
    calls.set("BootOrder", &[7, 0, 0, 0]);
    let report = boothop_core::execute(
        boothop_core::Request::Inspect,
        boothop_core::Os::Linux,
        &mut LinuxPlatform::new(&mut Store, calls.clone()),
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.record, boothop_core::RecordDiagnostic::Missing);
    assert!(report.stages.is_empty());
}

// Catches malformed control variables being silently ignored during discovery.
#[test]
fn all_control_variables_and_option_attributes_are_validated() {
    for (stem, values) in [
        (
            "BootOrder",
            vec![vec![], vec![7, 0, 0, 0, 7], vec![6, 0, 0, 0, 7, 0]],
        ),
        (
            "BootCurrent",
            vec![
                vec![7, 0, 0, 0, 7, 0],
                vec![6, 0, 0, 0],
                vec![6, 0, 0, 0, 7, 0, 0, 0],
            ],
        ),
    ] {
        for bytes in values {
            let calls = inventory_calls();
            calls.set(stem, &bytes);
            assert_eq!(
                options(&calls),
                Err(Error::UnsupportedFormat),
                "{stem} {bytes:?}"
            );
        }
    }
    let calls = inventory_calls();
    let mut bytes = option_bytes();
    bytes[0] = 6;
    calls.set("Boot0007", &bytes);
    assert_eq!(options(&calls), Err(Error::UnsupportedFormat));
}

// Catches partial inventories after disappearance and unresolved control references.
#[test]
fn missing_control_references_and_disappearing_entries_fail_whole_inventory() {
    for stem in ["BootOrder", "BootCurrent"] {
        let calls = inventory_calls();
        calls.0.borrow_mut().files.remove(&name(stem));
        assert_eq!(options(&calls), Err(io("open", 2)));
    }
    let calls = inventory_calls();
    calls.set("BootOrder", &[7, 0, 0, 0, 8, 0]);
    assert_eq!(options(&calls), Err(Error::TargetMissing));
    let calls = inventory_calls();
    calls.0.borrow_mut().fail = Some(("Boot0007-8be4df61-93ca-11d2-aa0d-00e098032b8c", 2));
    assert_eq!(options(&calls), Err(io("open", 2)));
}

// Catches counting payload only, or returning a truncated partial list at the aggregate cap.
#[test]
fn enumeration_raw_aggregate_limit_no_partial_success() {
    let calls = inventory_calls();
    let mut bytes = option_bytes();
    bytes.resize(1_048_564, 0);
    calls.set("Boot0007", &bytes);
    assert_eq!(options(&calls).unwrap().entries.len(), 1); // 6 + 6 + 1,048,564 = 1 MiB.
    bytes.push(0);
    calls.set("Boot0007", &bytes);
    assert_eq!(options(&calls), Err(Error::ResourceLimit));
    bytes.resize(1_048_581, 0);
    calls.set("Boot0007", &bytes);
    assert_eq!(options(&calls), Err(Error::ResourceLimit));
}
// Catches retaining a valid but stale descriptor after a leaf replacement or directory change.
#[test]
fn replaced_leaf_and_changed_enumeration_fail_without_leaking_handles() {
    let calls = FakeLinuxCalls::new();
    calls.set("BootNext", &[7, 0, 0, 0, 7, 0]);
    calls.0.borrow_mut().replace_on_reopen = true;
    assert_eq!(read_next(&calls), Err(io("read", 5)));
    assert_eq!(calls.0.borrow().live_handles, 0);
    let calls = inventory_calls();
    calls.0.borrow_mut().changed_names = true;
    assert_eq!(options(&calls), Err(io("read", 5)));
    assert_eq!(calls.0.borrow().live_handles, 0);
}

#[test]
fn file_descriptor_metadata_and_enumeration_errors_remain_failures() {
    for (mode, filesystem, readonly, size, expected) in [
        (0o120777, 0xde5e81e4, false, 6, io("metadata", 1)),
        (0o040755, 0xde5e81e4, false, 6, io("metadata", 1)),
        (0o010600, 0xde5e81e4, false, 6, io("metadata", 1)),
        (0o100644, 1, false, 6, io("metadata", 19)),
        (0o100644, 0xde5e81e4, true, 6, io("metadata", 30)),
        (0o100644, 0xde5e81e4, false, 5, io("read", 5)),
        (0o100644, 0xde5e81e4, false, 1_048_581, Error::ResourceLimit),
    ] {
        let calls = FakeLinuxCalls::new();
        calls.set("BootNext", &[7, 0, 0, 0, 7, 0]);
        calls.0.borrow_mut().file_meta = Some(Metadata {
            mode,
            filesystem,
            readonly,
            size,
            device: 1,
            inode: 1,
            mtime: (0, 0),
            ctime: (0, 0),
        });
        assert_eq!(read_next(&calls), Err(expected));
        assert_eq!(calls.0.borrow().live_handles, 0);
    }
    for code in [2, 13, 1, 30, 40, 20, 21, 5, 19, 22, 28, 122, 12, 4, 110] {
        let calls = inventory_calls();
        calls.0.borrow_mut().fail = Some(("names", code));
        assert_eq!(options(&calls), Err(io("read", code)));
        assert_eq!(calls.0.borrow().live_handles, 0);
    }
}
struct ReadyStore(TargetRecord);
impl ProtectedStore for ReadyStore {
    fn load(&mut self) -> Result<RecordState, Error> {
        Ok(RecordState::Ready(self.0.clone()))
    }
    fn save(&mut self, target: &TargetRecord) -> Result<(), Error> {
        self.0 = target.clone();
        Ok(())
    }
}
fn ready_store() -> ReadyStore {
    ReadyStore(TargetRecord {
        os: boothop_core::Os::Windows,
        boot_id: BootId(7),
        identity: boothop_core::canonicalize(
            &boothop_core::parse_load_option(&option_bytes()[4..]).unwrap(),
        )
        .unwrap(),
    })
}
struct ConfigureStore {
    saves: Rc<RefCell<usize>>,
}
impl ProtectedStore for ConfigureStore {
    fn load(&mut self) -> Result<RecordState, Error> {
        Ok(RecordState::Missing)
    }
    fn save(&mut self, _: &TargetRecord) -> Result<(), Error> {
        *self.saves.borrow_mut() += 1;
        Ok(())
    }
}

#[test]
fn configure_ignores_malformed_or_inaccessible_boot_next_and_only_saves_record() {
    for inaccessible in [false, true] {
        let calls = inventory_calls();
        if inaccessible {
            calls.0.borrow_mut().fail = Some(("BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c", 13));
        } else {
            calls.set("BootNext", &[7, 0, 0, 0, 7, 0, 0]);
        }
        let saves = Rc::new(RefCell::new(0));
        let mut store = ConfigureStore {
            saves: saves.clone(),
        };
        let report = boothop_core::execute(
            boothop_core::Request::Configure {
                boot_id: BootId(7),
                os: boothop_core::Os::Windows,
            },
            boothop_core::Os::Linux,
            &mut LinuxPlatform::new(&mut store, calls.clone()),
        )
        .unwrap();
        assert_eq!(*saves.borrow(), 1);
        assert_eq!(report.stages, [boothop_core::Stage::TargetValidated]);
        let events = calls.0.borrow().events.clone();
        assert!(!events.iter().any(|event| is_boot_next_read_open(event)));
        assert!(calls.0.borrow().writes.is_empty());
        assert!(calls.0.borrow().flags.is_empty());
    }
}

fn switch(calls: &FakeLinuxCalls) -> Result<boothop_core::Report, Error> {
    boothop_core::execute(
        boothop_core::Request::Switch {
            os: boothop_core::Os::Windows,
        },
        boothop_core::Os::Linux,
        &mut LinuxPlatform::new(&mut ready_store(), calls.clone()),
    )
}

// End-to-end evidence: firmware mutations and reboot stages must agree with stored bytes.
#[test]
fn switch_write_readback_and_reboot_evidence_matrix() {
    use boothop_core::Stage::*;
    for (reply, expected) in [
        (
            Reply::Success,
            vec![TargetValidated, BootNextVerified, RebootAccepted],
        ),
        (
            Reply::DisconnectedAfterSend,
            vec![
                TargetValidated,
                BootNextVerified,
                RebootUnknown,
                ResidualPossible,
            ],
        ),
        (
            Reply::TimedOutAfterSend,
            vec![
                TargetValidated,
                BootNextVerified,
                RebootUnknown,
                ResidualPossible,
            ],
        ),
    ] {
        let calls = inventory_calls();
        calls.0.borrow_mut().reply = reply;
        let report = switch(&calls).unwrap();
        assert_eq!(report.stages, expected);
        assert_eq!(
            calls.0.borrow().files[&name("BootNext")],
            [7, 0, 0, 0, 7, 0]
        );
        assert_eq!(calls.0.borrow().writes, [(0, vec![7, 0, 0, 0, 7, 0])]);
        assert_eq!(calls.0.borrow().flags, [1]);
        let s = calls.0.borrow();
        let write = s.events.iter().position(|e| e == "write").unwrap();
        let reboot = s.events.iter().position(|e| e == "reboot").unwrap();
        assert!(
            s.events[write + 1..reboot]
                .iter()
                .any(|e| e == &format!("open:{}:ReadVariable", name("BootNext")))
        );
        assert_eq!(s.live_handles, 0);
    }
    let calls = inventory_calls();
    calls.set("BootNext", &[7, 0, 0, 0, 7, 0]);
    assert!(switch(&calls).is_ok());
    assert!(calls.0.borrow().writes.is_empty());
    assert_eq!(calls.0.borrow().flags, [1]);
    let calls = inventory_calls();
    calls.0.borrow_mut().reply = Reply::ExplicitDenial;
    let error = switch(&calls).unwrap_err();
    assert!(error.residual_possible());
    let Error::FlowFailure {
        cause,
        stages,
        residual_assessment,
        ..
    } = error
    else {
        panic!("flow failure")
    };
    assert_eq!(*cause, Error::RebootRejected);
    assert_eq!(
        stages,
        [
            TargetValidated,
            BootNextVerified,
            RebootRejected,
            ResidualPossible
        ]
    );
    assert_eq!(
        residual_assessment,
        boothop_core::ResidualAssessment::Observed(Some(BootId(7)))
    );
    assert_eq!(
        calls.0.borrow().files[&name("BootNext")],
        [7, 0, 0, 0, 7, 0]
    );
    assert_eq!(calls.0.borrow().writes.len(), 1);
}

#[test]
fn switch_write_failures_race_conflict_and_readback_never_reboot() {
    for result in [Ok(0), Ok(1), Ok(5), Err(4), Err(28), Err(5)] {
        let calls = inventory_calls();
        calls.0.borrow_mut().write_result = result;
        let error = switch(&calls).unwrap_err();
        assert!(error.residual_possible());
        let Error::FlowFailure { cause, stages, .. } = error else {
            panic!("flow failure")
        };
        assert_eq!(*cause, io("write", result.err().unwrap_or(5)));
        assert_eq!(
            stages,
            [
                boothop_core::Stage::TargetValidated,
                boothop_core::Stage::ResidualPossible
            ]
        );
        assert_eq!(calls.0.borrow().writes.len(), 1);
        assert!(calls.0.borrow().flags.is_empty());
        assert!(calls.0.borrow().files.contains_key(&name("BootNext")));
        assert_eq!(calls.0.borrow().live_handles, 0);
    }
    let calls = inventory_calls();
    calls.0.borrow_mut().create_race = true;
    let error = switch(&calls).unwrap_err();
    assert!(error.residual_possible());
    let Error::FlowFailure { cause, .. } = error else {
        panic!("flow failure")
    };
    assert_eq!(*cause, io("open", 17));
    assert_eq!(
        calls.0.borrow().files[&name("BootNext")],
        [7, 0, 0, 0, 9, 0]
    );
    assert!(calls.0.borrow().writes.is_empty());
    assert!(calls.0.borrow().flags.is_empty());
    let calls = inventory_calls();
    calls.set("Boot0008", &option_bytes());
    calls.set("BootNext", &[7, 0, 0, 0, 8, 0]);
    let Error::FlowFailure { cause, .. } = switch(&calls).unwrap_err() else {
        panic!("flow failure")
    };
    assert_eq!(*cause, Error::BootNextConflict);
    assert!(calls.0.borrow().writes.is_empty());
    assert!(calls.0.borrow().flags.is_empty());
    let calls = inventory_calls();
    calls.0.borrow_mut().readback = Some(vec![7, 0, 0, 0, 8, 0]);
    let Error::FlowFailure { cause, .. } = switch(&calls).unwrap_err() else {
        panic!("flow failure")
    };
    assert_eq!(*cause, Error::ReadbackFailed);
    assert_eq!(calls.0.borrow().writes.len(), 1);
    assert!(calls.0.borrow().flags.is_empty());
}

#[test]
fn switch_explicitly_reads_boot_next_and_fails_closed_on_malformed_or_inaccessible_value() {
    let calls = inventory_calls();
    calls.set("BootNext", &[7, 0, 0, 0, 7, 0, 0]);
    let Error::FlowFailure { cause, stages, .. } = switch(&calls).unwrap_err() else {
        panic!("flow failure")
    };
    assert_eq!(*cause, Error::UnsupportedFormat);
    assert_eq!(stages, [boothop_core::Stage::TargetValidated]);
    let events = calls.0.borrow().events.clone();
    let names = events.iter().position(|event| event == "names").unwrap();
    let option = events
        .iter()
        .rposition(|event| is_boot_option_read_open(event))
        .unwrap();
    let next = events
        .iter()
        .position(|event| is_boot_next_read_open(event))
        .unwrap();
    // Core target validation is pure and emits no adapter event; the final
    // Boot0007 reopen is the strongest observable inventory-complete marker.
    assert!(names < option && option < next);
    assert!(calls.0.borrow().writes.is_empty());
    assert!(calls.0.borrow().flags.is_empty());

    let calls = inventory_calls();
    calls.0.borrow_mut().fail = Some(("BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c", 13));
    let Error::FlowFailure { cause, stages, .. } = switch(&calls).unwrap_err() else {
        panic!("flow failure")
    };
    assert_eq!(*cause, io("open", 13));
    assert_eq!(stages, [boothop_core::Stage::TargetValidated]);
    let events = calls.0.borrow().events.clone();
    let names = events.iter().position(|event| event == "names").unwrap();
    let option = events
        .iter()
        .rposition(|event| is_boot_option_read_open(event))
        .unwrap();
    let next = events
        .iter()
        .position(|event| is_boot_next_read_open(event))
        .unwrap();
    assert!(names < option && option < next);
    assert!(calls.0.borrow().writes.is_empty());
    assert!(calls.0.borrow().flags.is_empty());
}

#[test]
fn bootorder_cannot_exceed_u16_domain_budget() {
    let calls = inventory_calls();
    let mut order = vec![7, 0, 0, 0];
    for _ in 0..65537 {
        order.extend_from_slice(&[7, 0]);
    }
    calls.set("BootOrder", &order);
    assert_eq!(options(&calls), Err(Error::ResourceLimit));
}
