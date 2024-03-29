pub mod btftracepoints;
pub mod lsm;
pub mod tracepoints;

use crate::ContextTracker;
use aya::Bpf;
use bitblazr_common::models::BlazrEvent;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

pub(crate) trait Probe {
    fn init(
        &self,
        bpf: &mut Bpf,
        snd: Sender<BlazrEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error>;
}

#[derive(Debug)]
pub struct PsLabels {
    pub ppid: u32,
    pub pid: u32,
    pub labels: [i64; 5],
}
