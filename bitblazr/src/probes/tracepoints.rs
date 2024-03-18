use super::Probe;
use crate::ContextTracker;
use crate::PsLabels;
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bitblazr_common::models::BlazrEvent;
use bytes::BytesMut;
use std::result::Result;
use std::sync::Arc;
use tracing::warn;

pub struct Tracepoints {
    labels_snd: crossbeam_channel::Sender<PsLabels>,
}

impl Tracepoints {
    pub fn new(labels_snd: crossbeam_channel::Sender<PsLabels>) -> Tracepoints {
        Tracepoints { labels_snd }
    }

    #[allow(unreachable_code)]
    fn run(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BlazrEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        let mut tp_array: AsyncPerfEventArray<_> = bpf.take_map("TP_BUFFER").unwrap().try_into()?;

        for cpu_id in online_cpus()? {
            let mut tp_buf = tp_array.open(cpu_id, Some(256))?;
            let thread_snd = snd.clone();
            let th_ctx_tracker = ctx_tracker.clone();
            let th_labels_snd = self.labels_snd.clone();

            tokio::spawn(async move {
                let mut buffer =
                    vec![BytesMut::with_capacity(core::mem::size_of::<BlazrEvent>()); 100];

                loop {
                    // wait for events
                    let events = tp_buf.read_events(&mut buffer).await?;

                    if events.lost > 0 {
                        warn!(target: "error", "Events lost in TP_BUFFER: {}", events.lost);
                    }

                    for i in 0..events.read {
                        let buf = &mut buffer[i];
                        let be: &mut BlazrEvent =
                            unsafe { &mut *(buf.as_ptr() as *mut BlazrEvent) };

                        th_ctx_tracker.process_event(be, th_labels_snd.clone());

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
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        self.run(bpf, snd, ctx_tracker.clone())?;

        let program: &mut TracePoint = bpf.program_mut("tracepoints").unwrap().try_into()?;
        program.load()?;
        program.attach("raw_syscalls", "sys_enter")?;

        Ok(())
    }
}
