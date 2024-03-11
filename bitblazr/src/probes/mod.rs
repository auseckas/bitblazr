pub mod btftracepoints;
pub mod kprobes;
pub mod lsm;
pub mod tracepoints;

use crate::ContextTracker;
use aya::Bpf;
use bitblazr_common::models::BlazrEvent;
use crossbeam_channel::Sender;
use std::sync::Arc;

pub(crate) trait Probe {
    fn init(
        &self,
        bpf: &mut Bpf,
        snd: Sender<BlazrEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error>;
}

#[derive(Debug)]
pub(crate) struct PsLabels {
    pub ppid: u32,
    pub pid: u32,
    pub labels: [i64; 5],
}
