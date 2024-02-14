use crate::events::BSProcessTracker;
use crate::probes::Probe;
use aya::{include_bytes_aligned, Bpf, BpfLoader, Btf};
use aya_log::BpfLogger;
use std::fs;
use std::path::Path;
use std::vec::Vec;

pub struct EbpfLoader {
    tracker: BSProcessTracker,
}

impl EbpfLoader {
    pub fn new(tracker: BSProcessTracker) -> EbpfLoader {
        EbpfLoader { tracker }
    }

    pub fn attach(&self, bpf: &mut Bpf, probes: Vec<Box<dyn Probe>>) -> Result<(), anyhow::Error> {
        for probe in probes {
            probe.init(bpf, self.tracker.snd.clone())?;
        }
        BpfLogger::init(bpf)?;
        Ok(())
    }
}
