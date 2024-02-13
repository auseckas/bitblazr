use crate::events::BpfShieldEvents;
use crate::probes::Probe;
use aya::{include_bytes_aligned, Bpf, BpfLoader, Btf};
use aya_log::BpfLogger;
use std::fs;
use std::path::Path;
use std::vec::Vec;

pub struct EbpfLoader {
    events: BpfShieldEvents,
}

impl EbpfLoader {
    pub fn new(events: BpfShieldEvents) -> EbpfLoader {
        EbpfLoader { events }
    }

    pub fn attach(&self, bpf: &mut Bpf, probes: Vec<Box<dyn Probe>>) -> Result<(), anyhow::Error> {
        for probe in probes {
            probe.init(bpf, self.events.snd.clone())?;
        }
        BpfLogger::init(bpf)?;
        Ok(())
    }
}
