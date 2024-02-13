pub mod btftracepoints;
pub mod lsm;
pub mod tracepoints;

use crate::events::EbpfEvent;
use aya::Bpf;
use crossbeam_channel::Sender;

pub(crate) trait Probe {
    fn init(&self, bpf: &mut Bpf, snd: Sender<EbpfEvent>) -> Result<(), anyhow::Error>;
}
