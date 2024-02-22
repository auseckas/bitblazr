use crate::probes::Probe;
use crate::tracker::BSProcessTracker;
use aya::Bpf;
use aya_log::BpfLogger;
use bpfshield_common::rules::{BSRuleClass, BShieldRule};
use std::collections::HashMap;
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
