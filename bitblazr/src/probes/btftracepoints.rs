use super::Probe;
use crate::ContextTracker;
use aya::maps::perf::PerfBufferError;
use aya::maps::AsyncPerfEventArray;
use aya::programs::BtfTracePoint;
use aya::util::online_cpus;
use aya::{Bpf, Btf};
use bitblazr_common::models::BlazrEvent;
use bytes::BytesMut;
use std::result::Result;
use std::sync::Arc;
use tracing::warn;

pub struct BtfTracepoints {}

impl BtfTracepoints {
    pub fn new() -> BtfTracepoints {
        BtfTracepoints {}
    }

    #[allow(unreachable_code)]
    fn run(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BlazrEvent>,
    ) -> Result<(), anyhow::Error> {
        let mut tp_array: AsyncPerfEventArray<_> =
            bpf.take_map("BTP_BUFFER").unwrap().try_into()?;

        for cpu_id in online_cpus()? {
            let mut tp_buf = tp_array.open(cpu_id, Some(128))?;
            let thread_snd = snd.clone();

            tokio::spawn(async move {
                let mut buffer =
                    vec![BytesMut::with_capacity(core::mem::size_of::<BlazrEvent>()); 100];

                loop {
                    // wait for events
                    let events = tp_buf.read_events(&mut buffer).await?;

                    for i in 0..events.read {
                        let buf = &mut buffer[i];
                        let be: &BlazrEvent = unsafe { &*(buf.as_ptr() as *const BlazrEvent) };

                        if let Err(e) = thread_snd.send(be.clone()) {
                            warn!("Could not send Tracepoints event. Err: {}", e);
                        }
                    }
                }
                Ok::<_, PerfBufferError>(())
            });
        }
        Ok(())
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
        snd: crossbeam_channel::Sender<BlazrEvent>,
        _ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        self.run(bpf, snd)?;
        let btf = Btf::from_sys_fs()?;

        self.load_program(bpf, &btf, "sched_process_exec")?;
        self.load_program(bpf, &btf, "sched_process_exit")?;
        self.load_program(bpf, &btf, "sys_enter")?;

        Ok(())
    }
}
