use boothop_core::{
    BootId, Error, LoadOption, Os, Platform, RebootOutcome, RecordState, TargetRecord,
    canonicalize, decode_record, parse_load_option,
};

pub fn option() -> LoadOption {
    let hex = include_str!("../../../../fixtures/uefi/synthetic/task1-shape.hex").trim();
    let bytes: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    parse_load_option(&bytes).unwrap()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    ReadRecord,
    CheckEnvironment,
    SaveRecord,
    ReadOptions,
    ReadNext,
    WriteNext(BootId),
    Reboot,
}

impl Event {
    pub fn is_mutation(&self) -> bool {
        matches!(self, Self::SaveRecord | Self::WriteNext(_) | Self::Reboot)
    }
}

pub struct FakePlatform {
    pub record: Result<RecordState, Error>,
    pub options: Vec<(BootId, LoadOption)>,
    pub next: Option<BootId>,
    pub reboot_outcome: RebootOutcome,
    pub events: Vec<Event>,
    // Zero-based call index, including the environment check.
    pub failure: Option<(usize, Error)>,
    pub next_reads: std::collections::VecDeque<Result<Option<BootId>, Error>>,
    pub write_error_mutates: bool,
}

impl FakePlatform {
    pub fn missing() -> Self {
        Self {
            record: Ok(RecordState::Missing),
            options: vec![(BootId(7), option())],
            next: None,
            reboot_outcome: RebootOutcome::Accepted,
            events: Vec::new(),
            failure: None,
            next_reads: Default::default(),
            write_error_mutates: false,
        }
    }

    pub fn ready() -> Self {
        let mut p = Self::missing();
        p.record = Ok(RecordState::Ready(TargetRecord {
            os: Os::Windows,
            boot_id: BootId(7),
            identity: canonicalize(&p.options[0].1).unwrap(),
        }));
        p
    }

    pub fn unsupported_version(version: u64) -> Self {
        let mut p = Self::missing();
        p.record =
            decode_record(format!("{{\"version\":{version}}}").as_bytes()).map(RecordState::Ready);
        p
    }

    fn call(&mut self, event: Event) -> Result<(), Error> {
        let index = self.events.len();
        self.events.push(event);
        if let Some((at, error)) = &self.failure
            && index == *at
        {
            return Err(error.clone());
        }
        Ok(())
    }
}

impl Platform for FakePlatform {
    fn load_record(&mut self) -> Result<RecordState, Error> {
        self.call(Event::ReadRecord)?;
        self.record.clone()
    }
    fn check_environment(&mut self) -> Result<(), Error> {
        self.call(Event::CheckEnvironment)
    }
    fn save_record(&mut self, target: &TargetRecord) -> Result<(), Error> {
        self.call(Event::SaveRecord)?;
        self.record = Ok(RecordState::Ready(target.clone()));
        Ok(())
    }
    fn read_options(&mut self) -> Result<Vec<(BootId, LoadOption)>, Error> {
        self.call(Event::ReadOptions)?;
        Ok(self.options.clone())
    }
    fn read_next(&mut self) -> Result<Option<BootId>, Error> {
        self.call(Event::ReadNext)?;
        self.next_reads.pop_front().unwrap_or(Ok(self.next))
    }
    fn write_next(&mut self, target: BootId) -> Result<(), Error> {
        let result = self.call(Event::WriteNext(target));
        if result.is_ok() || self.write_error_mutates {
            self.next = Some(target);
        }
        result
    }
    fn reboot(&mut self) -> RebootOutcome {
        self.call(Event::Reboot)
            .expect("reboot uses its explicit outcome channel");
        self.reboot_outcome
    }
}
