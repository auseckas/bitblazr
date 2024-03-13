use crate::probes::Probe;
use crate::tracker::BSProcessTracker;
use crate::ContextTracker;
use aya::Bpf;
#[allow(unused_imports)]
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

        // For eBPF module logging, unless you are debugging modules don't enable this - eats a ton of CPU
        // BpfLogger::init(bpf)?;

        Ok(())
    }
}
