use super::Probe;
use crate::config::ShieldConfig;
use crate::ContextTracker;
use crate::PsLabels;
use aya::maps::lpm_trie::Key;
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::maps::{Array, LpmTrie, MapData};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bitblazr_common::models::BlazrEvent;
use bitblazr_common::rules::PrefixKey;
use bytes::BytesMut;
use std::result::Result;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep_until, Duration, Instant};
use tracing::warn;

pub(crate) struct Tracepoints {
    labels_snd: Sender<PsLabels>,
    max_events: Arc<u32>,
    backoff: Arc<u32>,
    open_prefixes: Vec<String>,
}

impl Tracepoints {
    pub fn new(config: &ShieldConfig, labels_snd: Sender<PsLabels>) -> Tracepoints {
        let max_events = Arc::new(config.limits.max_events);
        let backoff = Arc::new(config.limits.backoff);
        let open_prefixes = config.tracing.open_prefixes.clone();
        Tracepoints {
            labels_snd,
            max_events,
            backoff,
            open_prefixes,
        }
    }

    #[allow(unreachable_code)]
    fn run(
        &self,
        bpf: &mut Bpf,
        snd: Sender<BlazrEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        let mut open_prefixes: LpmTrie<&mut MapData, PrefixKey, u32> =
            LpmTrie::try_from(bpf.map_mut("TP_OPEN_PREFIX").unwrap()).unwrap();

        let mut prefixes = Vec::new();

        for (i, p) in self.open_prefixes.iter().enumerate() {
            if i == 100 {
                warn!(
                    "Open syscall prefixes are limited to 100. Entries after 100 will be ignored."
                );
                break;
            }
            let mut key = PrefixKey { buf: [0; 27] };
            let mut len = p.len();
            let pb = p.as_bytes();
            if len > 25 {
                warn!("Open prefix '{}' longer than 25 characters. Truncating", p);
                len = 25;
            }
            key.buf[..len].copy_from_slice(&pb[..len]);
            prefixes.push(len as u32);
            open_prefixes.insert(&Key::new(len as u32 * 8, key), 1, 0)?;
        }

        let mut open_prefixes_len: Array<&mut MapData, u32> =
            Array::try_from(bpf.map_mut("TP_OPEN_PREFIX_LEN").unwrap()).unwrap();

        for (i, len) in prefixes.into_iter().enumerate() {
            open_prefixes_len.set(i as u32, len, 0)?;
        }

        let mut tp_array: AsyncPerfEventArray<_> = bpf.take_map("TP_BUFFER").unwrap().try_into()?;

        for cpu_id in online_cpus()? {
            let mut tp_buf = tp_array.open(cpu_id, Some(512))?;
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
                        warn!(target: "error", "Events lost in TP_BUFFER: {}", events.lost);
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
                                warn!(target: "error", "Backoff time completed on CPU: {}. Events lost in TP_BUFFER: {}", cpu_id, es.lost);
                                event_tracker = 0;
                                event_tracker_timer = Instant::now();
                            }
                        }

                        th_ctx_tracker.process_event(be, th_labels_snd.clone());

                        if let Err(e) = thread_snd.send(be.clone()).await {
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
        snd: Sender<BlazrEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        self.run(bpf, snd, ctx_tracker.clone())?;

        let program: &mut TracePoint = bpf.program_mut("tracepoints").unwrap().try_into()?;
        program.load()?;
        program.attach("raw_syscalls", "sys_enter")?;

        Ok(())
    }
}
