use boothop_core::{
    BootId, Error, Os, RecordState, Request, TargetRecord, arch_uki_load_option, canonicalize,
    execute, serialize_load_option,
};
use boothop_platform::{
    ProtectedStore,
    windows::{
        CallError, FirmwareType, ReadOutcome, RebootCalls, RebootReply, VariableName, WindowsCalls,
        WindowsPlatform,
        uki::{EfiVolume, FileReadError, GptPartition, ReadOnlyEfiVolumes, VolumeEnumerationError},
    },
};
use std::{cell::Cell, rc::Rc};

struct Store(RecordState);

impl ProtectedStore for Store {
    fn load(&mut self) -> Result<RecordState, Error> {
        Ok(self.0.clone())
    }

    fn save(&mut self, target: &TargetRecord) -> Result<(), Error> {
        self.0 = RecordState::Ready(target.clone());
        Ok(())
    }
}

struct Calls {
    boot_option: Vec<u8>,
    boot_next_reads: Rc<Cell<usize>>,
    boot_next_writes: Rc<Cell<usize>>,
}

impl WindowsCalls for Calls {
    fn firmware_type(&mut self) -> Result<FirmwareType, CallError> {
        Ok(FirmwareType::Uefi)
    }

    fn read_variable(&mut self, variable: VariableName, _: usize) -> ReadOutcome {
        match variable {
            VariableName::BootOrder => ReadOutcome::success(7, vec![7, 0]),
            VariableName::BootCurrent => ReadOutcome::success(6, vec![7, 0]),
            VariableName::Boot(boot_id) => {
                assert_eq!(boot_id, BootId(7));
                ReadOutcome::success(7, self.boot_option.clone())
            }
            VariableName::BootNext => {
                self.boot_next_reads.set(self.boot_next_reads.get() + 1);
                ReadOutcome::success(7, BootId(7).0.to_le_bytes().to_vec())
            }
        }
    }

    fn write_boot_next(&mut self, _: [u8; 2]) -> Result<(), CallError> {
        self.boot_next_writes.set(self.boot_next_writes.get() + 1);
        Ok(())
    }
}

struct Volumes {
    file: Result<Vec<u8>, FileReadError>,
    matching_volume: bool,
    file_reads: Rc<Cell<usize>>,
}

impl ReadOnlyEfiVolumes for Volumes {
    fn existing_efi_volumes(&self) -> Result<Vec<EfiVolume>, VolumeEnumerationError> {
        Ok(if self.matching_volume {
            vec![EfiVolume {
                id: 9,
                partition: partition(),
            }]
        } else {
            Vec::new()
        })
    }

    fn read_file(&self, volume_id: u64, path_utf16: &[u16]) -> Result<Vec<u8>, FileReadError> {
        assert_eq!(volume_id, 9);
        assert_eq!(
            path_utf16,
            r"\EFI\BootHop\arch.efi".encode_utf16().collect::<Vec<_>>()
        );
        self.file_reads.set(self.file_reads.get() + 1);
        self.file.clone()
    }
}

struct Reboot(Rc<Cell<usize>>);

impl RebootCalls for Reboot {
    fn request_reboot(&mut self) -> RebootReply {
        self.0.set(self.0.get() + 1);
        RebootReply::Accepted
    }
}

fn partition() -> GptPartition {
    GptPartition {
        number: 3,
        starting_lba: 2048,
        size_lba: 500_000,
        partition_guid_uefi_bytes: [0x11; 16],
    }
}

fn valid_uki() -> Vec<u8> {
    let names = [b".linux".as_slice(), b".osrel", b".cmdline", b".initrd"];
    let pe_offset = 0x80;
    let optional_size = 0xf0;
    let table = pe_offset + 4 + 20 + optional_size;
    let raw_start = table + names.len() * 40;
    let mut image = vec![0_u8; raw_start + names.len()];
    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    image[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    image[pe_offset + 4..pe_offset + 6].copy_from_slice(&0x8664_u16.to_le_bytes());
    image[pe_offset + 6..pe_offset + 8].copy_from_slice(&(names.len() as u16).to_le_bytes());
    image[pe_offset + 20..pe_offset + 22].copy_from_slice(&(optional_size as u16).to_le_bytes());
    image[pe_offset + 24..pe_offset + 26].copy_from_slice(&0x20b_u16.to_le_bytes());
    for (index, name) in names.iter().enumerate() {
        let header = table + index * 40;
        image[header..header + name.len()].copy_from_slice(name);
        image[header + 16..header + 20].copy_from_slice(&1_u32.to_le_bytes());
        image[header + 20..header + 24]
            .copy_from_slice(&((raw_start + index) as u32).to_le_bytes());
        image[raw_start + index] = 0x41 + index as u8;
    }
    image
}

struct SwitchFixture {
    store: Store,
    calls: Calls,
    reboot: Reboot,
    volumes: Volumes,
    next_reads: Rc<Cell<usize>>,
    next_writes: Rc<Cell<usize>>,
    file_reads: Rc<Cell<usize>>,
    reboots: Rc<Cell<usize>>,
}

fn setup(file: Result<Vec<u8>, FileReadError>, matching_volume: bool) -> SwitchFixture {
    let partition = partition();
    let option = arch_uki_load_option(
        partition.number,
        partition.starting_lba,
        partition.size_lba,
        partition.partition_guid_uefi_bytes,
    )
    .unwrap();
    let boot_option = serialize_load_option(&option).unwrap();
    let identity = canonicalize(&option).unwrap();
    let target = TargetRecord {
        os: Os::Linux,
        boot_id: BootId(7),
        identity,
    };
    let boot_next_reads = Rc::new(Cell::new(0));
    let boot_next_writes = Rc::new(Cell::new(0));
    let file_reads = Rc::new(Cell::new(0));
    let reboots = Rc::new(Cell::new(0));
    SwitchFixture {
        store: Store(RecordState::Ready(target)),
        calls: Calls {
            boot_option,
            boot_next_reads: boot_next_reads.clone(),
            boot_next_writes: boot_next_writes.clone(),
        },
        reboot: Reboot(reboots.clone()),
        volumes: Volumes {
            file,
            matching_volume,
            file_reads: file_reads.clone(),
        },
        next_reads: boot_next_reads,
        next_writes: boot_next_writes,
        file_reads,
        reboots,
    }
}

#[test]
fn fixed_uki_missing_or_unmatched_volume_stops_before_bootnext_and_reboot() {
    for (file, matching_volume) in [
        (Err(FileReadError::Missing), true),
        (Ok(valid_uki()), false),
    ] {
        let fixture = setup(file, matching_volume);
        let mut store = fixture.store;
        let mut platform = WindowsPlatform::new(&mut store, fixture.calls, fixture.reboot)
            .with_read_only_efi_volumes(fixture.volumes);
        let result = execute(
            Request::Switch { os: Os::Linux },
            Os::Windows,
            &mut platform,
        );
        assert_eq!(result, Err(Error::TargetMissing));
        drop(platform);
        assert_eq!(fixture.next_reads.get(), 0);
        assert_eq!(fixture.next_writes.get(), 0);
        assert_eq!(fixture.file_reads.get(), usize::from(matching_volume));
        assert_eq!(fixture.reboots.get(), 0);
    }
}

#[test]
fn default_volume_provider_fails_closed_before_bootnext_and_reboot() {
    let fixture = setup(Ok(valid_uki()), true);
    let mut store = fixture.store;
    let mut platform = WindowsPlatform::new(&mut store, fixture.calls, fixture.reboot);
    let result = execute(
        Request::Switch { os: Os::Linux },
        Os::Windows,
        &mut platform,
    );

    assert_eq!(result, Err(Error::UnsupportedFormat));
    drop(platform);
    assert_eq!(fixture.next_reads.get(), 0);
    assert_eq!(fixture.next_writes.get(), 0);
    assert_eq!(fixture.file_reads.get(), 0);
    assert_eq!(fixture.reboots.get(), 0);
}

#[test]
fn matching_fixed_uki_preflight_allows_existing_switch_flow() {
    let fixture = setup(Ok(valid_uki()), true);
    let mut store = fixture.store;
    let mut platform = WindowsPlatform::new(&mut store, fixture.calls, fixture.reboot)
        .with_read_only_efi_volumes(fixture.volumes);
    let report = execute(
        Request::Switch { os: Os::Linux },
        Os::Windows,
        &mut platform,
    )
    .unwrap();
    assert!(
        report
            .stages
            .contains(&boothop_core::Stage::BootNextVerified)
    );
    drop(platform);
    assert_eq!(fixture.file_reads.get(), 1);
    assert_eq!(fixture.next_reads.get(), 2);
    assert_eq!(fixture.next_writes.get(), 0);
    assert_eq!(fixture.reboots.get(), 1);
}
