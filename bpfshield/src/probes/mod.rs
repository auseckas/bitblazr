pub mod btftracepoints;
pub mod lsm;
pub mod tracepoints;

use crate::ContextTracker;
use aya::Bpf;
use bpfshield_common::models::BShieldEvent;
use crossbeam_channel::Sender;
use std::sync::Arc;

pub(crate) trait Probe {
    fn init(
        &self,
        bpf: &mut Bpf,
        snd: Sender<BShieldEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error>;
}

#[derive(Debug)]
pub(crate) struct PsLabels {
    pub ppid: u32,
    pub pid: u32,
    pub labels: [i64; 5],
}
