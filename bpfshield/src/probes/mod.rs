pub mod btftracepoints;
pub mod tracepoints;
use aya::Bpf;

pub fn load_probes(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    tracepoints::Tracepoints::init(bpf)?;
    btftracepoints::BtfTracepoints::init(bpf)?;
    Ok(())
}
