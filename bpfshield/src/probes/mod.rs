pub mod btftracepoints;
pub mod lsm;
pub mod tracepoints;

use aya::Bpf;
use bpfshield_common::models::BShieldEvent;
use crossbeam_channel::Sender;

pub(crate) trait Probe {
    fn init(&self, bpf: &mut Bpf, snd: Sender<BShieldEvent>) -> Result<(), anyhow::Error>;
}
