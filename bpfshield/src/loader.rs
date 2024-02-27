use crate::probes::Probe;
use crate::tracker::BSProcessTracker;
use crate::ContextTracker;
use aya::Bpf;
use aya_log::BpfLogger;
use std::sync::Arc;
use std::vec::Vec;

pub struct EbpfLoader {
    tracker: BSProcessTracker,
}

impl EbpfLoader {
    pub fn new(tracker: BSProcessTracker) -> EbpfLoader {
        EbpfLoader { tracker }
    }

    pub fn attach(
        &self,
        bpf: &mut Bpf,
        ctx_tracker: Arc<ContextTracker>,
        probes: Vec<Box<dyn Probe>>,
    ) -> Result<(), anyhow::Error> {
        for probe in probes {
            probe.init(bpf, self.tracker.snd.clone(), ctx_tracker.clone())?;
        }
        BpfLogger::init(bpf)?;
        Ok(())
    }
}
