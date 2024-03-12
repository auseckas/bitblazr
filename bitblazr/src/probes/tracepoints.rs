use super::Probe;
use crate::ContextTracker;
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bitblazr_common::models::{BlazrArch, BlazrEvent};
use bitblazr_common::rules::BlazrRuleVar;
use bitblazr_common::utils::str_from_buf_nul;
use bytes::BytesMut;
use std::result::Result;
use std::sync::Arc;
use tracing::{error, warn};

pub struct Tracepoints {}

impl Tracepoints {
    pub fn new() -> Tracepoints {
        Tracepoints {}
    }

    #[allow(unreachable_code)]
    fn run(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BlazrEvent>,
    ) -> Result<(), anyhow::Error> {
        let mut tp_array: AsyncPerfEventArray<_> = bpf.take_map("TP_BUFFER").unwrap().try_into()?;

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
}

impl Probe for Tracepoints {
    fn init(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BlazrEvent>,
        _cxt_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        self.run(bpf, snd)?;

        let program: &mut TracePoint = bpf.program_mut("tracepoints").unwrap().try_into()?;
        program.load()?;
        program.attach("raw_syscalls", "sys_enter")?;

        Ok(())
    }
}
