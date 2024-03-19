use super::Probe;
use crate::config::ShieldConfig;
use crate::ContextTracker;
use crate::PsLabels;
use aya::maps::perf::PerfBufferError;
use aya::maps::AsyncPerfEventArray;
use aya::programs::BtfTracePoint;
use aya::util::online_cpus;
use aya::{Bpf, Btf};
use bitblazr_common::models::BlazrEvent;
use bytes::BytesMut;
use std::result::Result;
use std::sync::Arc;
use tokio::time::{sleep_until, Duration, Instant};
use tracing::warn;

pub(crate) struct BtfTracepoints {
    labels_snd: crossbeam_channel::Sender<PsLabels>,
    max_events: Arc<u32>,
    backoff: Arc<u32>,
}

impl BtfTracepoints {
    pub fn new(
        config: &ShieldConfig,
        labels_snd: crossbeam_channel::Sender<PsLabels>,
    ) -> BtfTracepoints {
        let max_events = Arc::new(config.limits.max_events);
        let backoff = Arc::new(config.limits.backoff);
        BtfTracepoints {
            labels_snd,
            max_events,
            backoff,
        }
    }

    #[allow(unreachable_code)]
    fn run(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BlazrEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        let mut tp_array: AsyncPerfEventArray<_> =
            bpf.take_map("BTP_BUFFER").unwrap().try_into()?;

        for cpu_id in online_cpus()? {
            let mut tp_buf = tp_array.open(cpu_id, Some(256))?;
            let thread_snd = snd.clone();
            let th_ctx_tracker = ctx_tracker.clone();

            let th_labels_snd = self.labels_snd.clone();
            let th_max_events = self.max_events.clone();
            let th_backoff = self.backoff.clone();

            tokio::spawn(async move {
                let mut buffer =
                    vec![BytesMut::with_capacity(core::mem::size_of::<BlazrEvent>()); 100];

                let mut event_tracker_timer = Instant::now();
                let mut event_tracker = 0;

                loop {
                    // wait for events
                    let events = tp_buf.read_events(&mut buffer).await?;
                    if events.lost > 0 {
                        warn!(target: "error", "Events lost in BTP_BUFFER: {}", events.lost);
                    }

                    for i in 0..events.read {
                        let buf = &mut buffer[i];
                        let be: &mut BlazrEvent =
                            unsafe { &mut *(buf.as_ptr() as *mut BlazrEvent) };

                        event_tracker += 1;
                        let elapsed = event_tracker_timer.elapsed().as_secs();
                        if elapsed >= 5 && *th_max_events > 0 {
                            let events = event_tracker / elapsed;
                            if events >= *th_max_events as u64 {
                                warn!(target: "error", "Max event limit reached on CPU: {}. Backing off for {} seconds.", cpu_id, th_backoff);

                                sleep_until(
                                    Instant::now() + Duration::from_secs(*th_backoff as u64),
                                )
                                .await;
                                let es = tp_buf.read_events(&mut buffer).await?;
                                warn!(target: "error", "Backoff time completed on CPU: {}. Events lost in BTP_BUFFER: {}", cpu_id, es.lost);
                                event_tracker = 0;
                                event_tracker_timer = Instant::now();
                            }
                        }

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
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        self.run(bpf, snd, ctx_tracker)?;
        let btf = Btf::from_sys_fs()?;

        self.load_program(bpf, &btf, "sched_process_exec")?;
        self.load_program(bpf, &btf, "sched_process_exit")?;
        self.load_program(bpf, &btf, "sys_enter")?;

        Ok(())
    }
}
