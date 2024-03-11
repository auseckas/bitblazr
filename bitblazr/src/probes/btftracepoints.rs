use super::Probe;
use crate::ContextTracker;
use aya::programs::BtfTracePoint;
use aya::{Bpf, Btf};
use bitblazr_common::models::BlazrEvent;
use std::result::Result;
use std::sync::Arc;

pub struct BtfTracepoints {}

impl BtfTracepoints {
    pub fn new() -> BtfTracepoints {
        BtfTracepoints {}
    }

    fn load_program(&self, bpf: &mut Bpf, btf: &Btf, btf_tp: &str) -> Result<(), anyhow::Error> {
        let program: &mut BtfTracePoint = bpf.program_mut(btf_tp).unwrap().try_into()?;
        program.load(btf_tp, &btf)?;
        program.attach()?;
        Ok(())
    }
}

impl Probe for BtfTracepoints {
    fn init(
        &self,
        bpf: &mut Bpf,
        _snd: crossbeam_channel::Sender<BlazrEvent>,
        _ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        let btf = Btf::from_sys_fs()?;

        self.load_program(bpf, &btf, "sched_process_exec")?;
        self.load_program(bpf, &btf, "sched_process_exit")?;
        self.load_program(bpf, &btf, "sys_enter")?;

        Ok(())
    }
}
